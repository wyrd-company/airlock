//! Deterministic file alignment in a local working tree.
//!
//! This module is intentionally ignorant of git operations and GitHub write
//! APIs. It consumes an observation, authors only the deterministic lane, and
//! reports every path-level outcome so the caller can decide commit
//! granularity.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::findings::{Finding, Report, Status};
use crate::remediation::Lane;
use crate::worktree::{self, WorkingTreeFacts};
use crate::{Error, Result};

/// Paths whose working-tree contents never authorize an audit decision.
///
/// Keep this explicit beside the writer: [`WorkingTreeFacts::head_file`] is
/// the authority boundary and no author may cross it.
const AUTHORIZATION_BEARING_PATHS: &[&str] = &[".github/airlock.yml"];

const APACHE_2_LICENSE: &str = include_str!("../../../LICENSE");
const EDITORCONFIG: &str = "\
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
indent_style = space
indent_size = 2
trim_trailing_whitespace = true

[*.md]
trim_trailing_whitespace = false
";
const GITATTRIBUTES: &str = "* text=auto\n";
const CI_WORKFLOW: &str = "\
name: CI

on:
  pull_request:

permissions: {}

concurrency:
  group: ci-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  check:
    permissions:
      contents: read
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: arduino/setup-task@b3d5f287d2603d9c66a05c0f45d245e6d5b9d5dc # v2
      - run: task check
";
const AUDIT_WORKFLOW: &str = "\
name: Airlock audit

on:
  schedule:
    - cron: '17 7 * * 1'
  workflow_dispatch:

permissions: {}

jobs:
  audit:
    permissions:
      contents: read
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: wyrd-company/airlock@bfe5533ec4b60059c457bb91a5b424926c33fe23 # 0.0.0
        env:
          AIRLOCK_TOKEN: ${{ secrets.AIRLOCK_TOKEN }}
";
const TITLE_WORKFLOW: &str = "\
name: Pull request title

on:
  pull_request:
    types: [opened, edited, synchronize, reopened]

permissions: {}

jobs:
  title:
    permissions: {}
    runs-on: ubuntu-24.04
    steps:
      - uses: amannn/action-semantic-pull-request@e9a082f0e5ee444fe0a88945d2423a50c6d7a4c3 # v5
        env:
          GITHUB_TOKEN: ${{ github.token }}
";
const RENOVATE: &str = "{\n  \"extends\": [\"github>wyrd-company/.github\"]\n}\n";
const LEFTHOOK: &str = "\
pre-commit:
  commands:
    format:
      run: task format
    lint:
      run: task lint
commit-msg:
  commands:
    conventional:
      run: scripts/check-commit-subject.sh {1}
pre-push:
  commands:
    lint:
      run: task lint
";
const CHANGELOG: &str =
    "# Changelog\n\nAll notable changes to this release unit are documented here.\n";

/// One path-level result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathOperation {
    pub path: String,
    pub operation: String,
    pub rule: String,
    pub remediation_code: String,
    pub outcome: String,
    pub reason: Option<String>,
}

/// A judgment-lane finding handed to an agent using the embedded skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentDelegation {
    pub rule: String,
    pub remediation_code: String,
    pub change: String,
    pub source: Option<String>,
    pub evidence_code: Option<String>,
    pub evidence_path: Option<String>,
    pub skill_command: String,
}

/// The complete result of one authoring pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorReport {
    pub working_tree: String,
    pub dirty_before: Option<bool>,
    pub dirty_after: Option<bool>,
    pub operations: Vec<PathOperation>,
    pub judgment_findings: Vec<AgentDelegation>,
}

impl AuthorReport {
    #[must_use]
    pub fn wrote_anything(&self) -> bool {
        self.operations.iter().any(|item| item.outcome == "written")
    }
}

#[derive(Debug, Clone)]
struct PlannedOperation {
    path: String,
    kind: OperationKind,
    rule: String,
    code: String,
}

#[derive(Debug, Clone)]
enum OperationKind {
    Write(Vec<u8>),
    Symlink(String),
    Remove,
    Skip(String),
}

/// Author deterministic failing findings into `root`.
///
/// The initial and final facts both come from [`worktree::read_facts`].
/// Dirty trees are accepted, but a path that differs from HEAD is skipped.
///
/// # Errors
///
/// Returns the same refusal as [`worktree::read_facts`], or an error carrying
/// the completed path report when a filesystem operation fails.
pub fn author(root: &Path, report: &Report) -> Result<AuthorReport> {
    let before = worktree::read_facts(root)?;
    let mut output = AuthorReport {
        working_tree: before.root.display().to_string(),
        dirty_before: before.dirty,
        dirty_after: before.dirty,
        operations: Vec::new(),
        judgment_findings: judgment_findings(report),
    };

    let planned = plan_operations(&before, report, &mut output);
    for (index, operation) in planned.iter().enumerate() {
        if let OperationKind::Skip(reason) = &operation.kind {
            output.operations.push(skipped(operation, reason));
            continue;
        }
        if AUTHORIZATION_BEARING_PATHS.contains(&operation.path.as_str()) {
            output.operations.push(skipped(
                operation,
                "authorization-bearing paths are never written",
            ));
            continue;
        }
        if !safe_repository_path(&operation.path) {
            output.operations.push(skipped(
                operation,
                "path is not a safe repository-relative path",
            ));
            continue;
        }
        // Re-read immediately before touching each path. The report selected
        // the remediation, but it does not grant authority over a path that
        // changed after that observation.
        let current = worktree::read_facts(root)?;
        if current.path_modified_from_head(&operation.path) {
            output.operations.push(skipped(
                operation,
                "path is locally modified relative to HEAD",
            ));
            continue;
        }
        if let Err(error) = apply(&before.root, operation) {
            output.operations.push(PathOperation {
                path: operation.path.clone(),
                operation: operation.kind.name().to_owned(),
                rule: operation.rule.clone(),
                remediation_code: operation.code.clone(),
                outcome: "not_written".to_owned(),
                reason: Some(error.to_string()),
            });
            let after = worktree::read_facts(root)?;
            output.dirty_after = after.dirty;
            for remaining in planned.iter().skip(index + 1) {
                output.operations.push(PathOperation {
                    path: remaining.path.clone(),
                    operation: remaining.kind.name().to_owned(),
                    rule: remaining.rule.clone(),
                    remediation_code: remaining.code.clone(),
                    outcome: "not_written".to_owned(),
                    reason: Some("not attempted after an earlier path failure".to_owned()),
                });
            }
            return Err(Error::Alignment {
                message: format!("alignment stopped after a path operation failed: {error}"),
                report: serde_json::to_string(&output)
                    .unwrap_or_else(|_| "{\"report\":\"unavailable\"}".to_owned()),
            });
        }
        output.operations.push(PathOperation {
            path: operation.path.clone(),
            operation: operation.kind.name().to_owned(),
            rule: operation.rule.clone(),
            remediation_code: operation.code.clone(),
            outcome: "written".to_owned(),
            reason: None,
        });
    }
    output.dirty_after = worktree::read_facts(root)?.dirty;
    Ok(output)
}

fn safe_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !Path::new(path).is_absolute()
        && Path::new(path).components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn judgment_findings(report: &Report) -> Vec<AgentDelegation> {
    report
        .findings
        .iter()
        .filter(|finding| {
            finding.status == Status::Fail
                && finding.remediation_class.lane.as_deref() == Some(Lane::JudgmentFile.code())
        })
        .filter_map(|finding| {
            Some(AgentDelegation {
                rule: finding.rule.clone(),
                remediation_code: finding.remediation_class.code.clone()?,
                change: finding.remediation_class.change.clone()?,
                source: finding.source.clone(),
                evidence_code: finding.evidence.as_ref().map(|value| value.code.clone()),
                evidence_path: finding
                    .evidence
                    .as_ref()
                    .and_then(|value| value.path.clone()),
                skill_command: "airlock skill repository-standards".to_owned(),
            })
        })
        .collect()
}

fn plan_operations(
    facts: &WorkingTreeFacts,
    report: &Report,
    output: &mut AuthorReport,
) -> Vec<PlannedOperation> {
    let mut operations = Vec::new();
    let mut claimed = BTreeSet::new();
    for finding in report.findings.iter().filter(|finding| {
        finding.status == Status::Fail
            && finding.remediation_class.lane.as_deref() == Some(Lane::DeterministicFile.code())
            && finding.source.as_deref() == Some("working-tree")
    }) {
        let Some(code) = finding.remediation_class.code.as_deref() else {
            continue;
        };
        for operation in author_for(code, finding, facts) {
            if claimed.insert(operation.path.clone()) {
                operations.push(operation);
            } else {
                output.operations.push(PathOperation {
                    path: operation.path,
                    operation: operation.kind.name().to_owned(),
                    rule: finding.rule.clone(),
                    remediation_code: code.to_owned(),
                    outcome: "skipped".to_owned(),
                    reason: Some(
                        "another remediation in this run already owns the path".to_owned(),
                    ),
                });
            }
        }
    }
    operations
}

fn author_for(code: &str, finding: &Finding, facts: &WorkingTreeFacts) -> Vec<PlannedOperation> {
    let operation = |path: &str, kind| PlannedOperation {
        path: path.to_owned(),
        kind,
        rule: finding.rule.clone(),
        code: code.to_owned(),
    };
    match code {
        "add-license-file" => vec![operation(
            "LICENSE",
            OperationKind::Write(APACHE_2_LICENSE.into()),
        )],
        "add-gitattributes" => vec![operation(
            ".gitattributes",
            OperationKind::Write(
                append_line_if_present(&facts.root, ".gitattributes", GITATTRIBUTES).into_bytes(),
            ),
        )],
        "add-editorconfig" => vec![operation(
            ".editorconfig",
            OperationKind::Write(EDITORCONFIG.into()),
        )],
        "add-ci-workflow" => vec![operation(
            ".github/workflows/ci.yml",
            OperationKind::Write(CI_WORKFLOW.into()),
        )],
        "add-renovate-config" => vec![operation(
            ".github/renovate.json",
            OperationKind::Write(renovate_contents(finding, facts).into_bytes()),
        )],
        "add-audit-workflow" => vec![operation(
            ".github/workflows/audit.yml",
            OperationKind::Write(AUDIT_WORKFLOW.into()),
        )],
        "add-lefthook-config" => vec![operation(
            ".config/lefthook.yml",
            OperationKind::Write(LEFTHOOK.into()),
        )],
        "add-claude-symlink" => vec![operation(
            "CLAUDE.md",
            OperationKind::Symlink("AGENTS.md".to_owned()),
        )],
        "remove-agent-harness-config" => forbidden_paths(facts)
            .into_iter()
            .map(|path| operation(&path, OperationKind::Remove))
            .collect(),
        "remove-codeowners" => ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
            .into_iter()
            .filter(|path| facts.tree.entries.iter().any(|entry| entry.path == *path))
            .map(|path| operation(path, OperationKind::Remove))
            .collect(),
        "add-title-check" => vec![operation(
            ".github/workflows/pr-title.yml",
            OperationKind::Write(TITLE_WORKFLOW.into()),
        )],
        "add-unit-changelogs" => release_unit_paths(&facts.root)
            .into_iter()
            .map(|path| operation(&path, OperationKind::Write(CHANGELOG.into())))
            .collect(),
        "remove-root-changelog" => {
            vec![operation("CHANGELOG.md", OperationKind::Remove)]
        }
        "declare-package-license" => package_license_operations(finding, facts),
        "remove-org-name-topics"
        | "declare-merge-settings"
        | "remove-visibility-field"
        | "remove-custom-property-values" => {
            yaml_transform_operation(".github/repo-settings.yml", finding, facts, code)
        }
        "set-include-dirs" | "align-include-namespaces" => {
            yaml_transform_operation("taskfile.yml", finding, facts, code)
        }
        "pin-actions-to-shas" => pin_action_operations(finding, facts),
        "add-pull-request-trigger"
        | "empty-workflow-permissions"
        | "add-ci-concurrency-group"
        | "supply-airlock-token"
        | "add-tag-trigger"
        | "add-push-trigger"
        | "set-cd-concurrency" => workflow_transform_operations(finding, facts, code),
        "configure-pre-commit-hook" | "configure-commit-msg-hook" | "configure-pre-push-hook" => {
            vec![operation(
                ".config/lefthook.yml",
                OperationKind::Write(LEFTHOOK.into()),
            )]
        }
        _ if implemented_codes().contains(code) => {
            panic!("deterministic remediation `{code}` has no author dispatch")
        }
        _ => Vec::new(),
    }
}

fn append_line_if_present(root: &Path, path: &str, line: &str) -> String {
    match fs::read_to_string(root.join(path)) {
        Ok(mut text) => {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(line);
            text
        }
        Err(_) => line.to_owned(),
    }
}

fn renovate_contents(finding: &Finding, facts: &WorkingTreeFacts) -> String {
    let expected = finding
        .remediation
        .as_ref()
        .and_then(|remediation| remediation.detail.split('`').nth(1))
        .unwrap_or("github>wyrd-company/.github");
    let path = facts.root.join(".github/renovate.json");
    let mut value = fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    value["extends"] = serde_json::json!([expected]);
    serde_json::to_string_pretty(&value)
        .map(|value| format!("{value}\n"))
        .unwrap_or_else(|_| RENOVATE.to_owned())
}

fn yaml_transform_operation(
    path: &str,
    finding: &Finding,
    facts: &WorkingTreeFacts,
    code: &str,
) -> Vec<PlannedOperation> {
    let Some(text) = fs::read_to_string(facts.root.join(path)).ok() else {
        return Vec::new();
    };
    let mut value: serde_norway::Value =
        serde_norway::from_str(&text).unwrap_or(serde_norway::Value::Mapping(Default::default()));
    let mapping = value
        .as_mapping_mut()
        .expect("the replacement value above is a mapping");
    let key = serde_norway::Value::String;
    match code {
        "remove-visibility-field" => {
            mapping.remove(key("visibility".to_owned()));
        }
        "remove-custom-property-values" => {
            mapping.remove(key("custom-properties".to_owned()));
            mapping.remove(key("custom_properties".to_owned()));
        }
        "declare-merge-settings" => {
            let mut merge = serde_norway::Mapping::new();
            merge.insert(key("squash".to_owned()), true.into());
            merge.insert(key("rebase".to_owned()), true.into());
            merge.insert(key("merge_commit".to_owned()), false.into());
            merge.insert(key("delete_branch_on_merge".to_owned()), true.into());
            mapping.insert(key("merge".to_owned()), serde_norway::Value::Mapping(merge));
        }
        "remove-org-name-topics" => {
            if let Some(topics) = mapping
                .get_mut(key("topics".to_owned()))
                .and_then(serde_norway::Value::as_sequence_mut)
            {
                topics.retain(|topic| {
                    topic.as_str().is_none_or(|topic| {
                        !matches!(topic, "wyrd-company" | "boblangley" | "mmenm" | "flapstack")
                    })
                });
            }
        }
        "set-include-dirs" | "align-include-namespaces" => {
            // These transformations are structural and depend only on the
            // declared include path. Preserve the document when there are no
            // includes rather than inventing repository-specific tasks.
            align_taskfile_includes(mapping, code, &facts.root);
        }
        _ => {}
    }
    let Ok(contents) = serde_norway::to_string(&value) else {
        return Vec::new();
    };
    vec![PlannedOperation {
        path: path.to_owned(),
        kind: OperationKind::Write(contents.into_bytes()),
        rule: finding.rule.clone(),
        code: code.to_owned(),
    }]
}

fn align_taskfile_includes(mapping: &mut serde_norway::Mapping, code: &str, root: &Path) {
    let key = serde_norway::Value::String;
    let Some(includes) = mapping
        .get_mut(key("includes".to_owned()))
        .and_then(serde_norway::Value::as_mapping_mut)
    else {
        return;
    };
    let entries: Vec<_> = includes.clone().into_iter().collect();
    for (name, mut include) in entries {
        let Some(path) = include
            .as_mapping()
            .and_then(|map| map.get(key("taskfile".to_owned())))
            .and_then(serde_norway::Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        if code == "set-include-dirs" {
            if let Some(include) = include.as_mapping_mut() {
                let directory = Path::new(&path)
                    .parent()
                    .unwrap_or(Path::new("."))
                    .to_string_lossy()
                    .to_string();
                include.insert(key("dir".to_owned()), directory.into());
                includes.insert(name, serde_norway::Value::Mapping(include.clone()));
            }
        } else if code == "align-include-namespaces" {
            let directory = Path::new(&path)
                .parent()
                .unwrap_or(Path::new("."))
                .to_string_lossy()
                .to_string();
            if let Some(unit) = release_unit_ids(root).get(&directory) {
                includes.remove(&name);
                includes.insert(unit.clone().into(), include);
            }
        }
    }
}

fn release_unit_ids(root: &Path) -> BTreeMap<String, String> {
    let Some(text) = fs::read_to_string(root.join(".intentional/config.yml")).ok() else {
        return BTreeMap::new();
    };
    let Some(units) = serde_norway::from_str::<serde_norway::Value>(&text)
        .ok()
        .and_then(|value| value.get("release-units").cloned())
        .and_then(|value| value.as_mapping().cloned())
    else {
        return BTreeMap::new();
    };
    units
        .into_iter()
        .filter_map(|(id, unit)| {
            Some((
                unit.get("path")?.as_str()?.trim_end_matches('/').to_owned(),
                id.as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn workflow_transform_operations(
    finding: &Finding,
    facts: &WorkingTreeFacts,
    code: &str,
) -> Vec<PlannedOperation> {
    facts
        .tree
        .entries
        .iter()
        .filter(|entry| {
            entry.path.starts_with(".github/workflows/")
                && (entry.path.ends_with(".yml") || entry.path.ends_with(".yaml"))
        })
        .filter_map(|entry| {
            let text = fs::read_to_string(facts.root.join(&entry.path)).ok()?;
            let transformed = transform_workflow(&text, code)?;
            Some(PlannedOperation {
                path: entry.path.clone(),
                kind: OperationKind::Write(transformed.into_bytes()),
                rule: finding.rule.clone(),
                code: code.to_owned(),
            })
        })
        .collect()
}

fn pin_action_operations(finding: &Finding, facts: &WorkingTreeFacts) -> Vec<PlannedOperation> {
    facts
        .tree
        .entries
        .iter()
        .filter(|entry| {
            entry.path.starts_with(".github/workflows/")
                && (entry.path.ends_with(".yml") || entry.path.ends_with(".yaml"))
        })
        .filter_map(|entry| {
            let text = fs::read_to_string(facts.root.join(&entry.path)).ok()?;
            match pin_actions(&text) {
                Ok(Some(contents)) => Some(PlannedOperation {
                    path: entry.path.clone(),
                    kind: OperationKind::Write(contents.into_bytes()),
                    rule: finding.rule.clone(),
                    code: "pin-actions-to-shas".to_owned(),
                }),
                Ok(None) => None,
                Err(reason) => Some(PlannedOperation {
                    path: entry.path.clone(),
                    kind: OperationKind::Skip(reason),
                    rule: finding.rule.clone(),
                    code: "pin-actions-to-shas".to_owned(),
                }),
            }
        })
        .collect()
}

fn pin_actions(text: &str) -> std::result::Result<Option<String>, String> {
    const PINS: &[(&str, &str, &str)] = &[
        (
            "actions/checkout",
            "11bd71901bbe5b1630ceea73d27597364c9af683",
            "v4",
        ),
        (
            "actions/upload-artifact",
            "ea165f8d65b6e75b540449e92b4886f43607fa02",
            "v4",
        ),
        (
            "arduino/setup-task",
            "b3d5f287d2603d9c66a05c0f45d245e6d5b9d5dc",
            "v2",
        ),
        (
            "amannn/action-semantic-pull-request",
            "e9a082f0e5ee444fe0a88945d2423a50c6d7a4c3",
            "v5",
        ),
        (
            "dtolnay/rust-toolchain",
            "e97e2d8cc328f1b50210efc529dca0028893a2d9",
            "v1",
        ),
        (
            "Swatinem/rust-cache",
            "e18b497796c12c097a38f9edb9d0641fb99eee32",
            "v2",
        ),
    ];
    let mut changed = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(value) = trimmed.strip_prefix("- uses:").map(str::trim) else {
            lines.push(line.to_owned());
            continue;
        };
        let value = value.split('#').next().unwrap_or(value).trim();
        let Some((action, reference)) = value.rsplit_once('@') else {
            return Err(format!("`{value}` has no action reference to pin"));
        };
        if action.starts_with("./") || action.starts_with("docker://") {
            lines.push(line.to_owned());
            continue;
        }
        if reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            lines.push(line.to_owned());
            continue;
        }
        let Some((_, sha, version)) = PINS.iter().find(|(known, _, _)| *known == action) else {
            return Err(format!(
                "`{action}` has no compiled-in reviewed pin; the path was left untouched"
            ));
        };
        let indentation = &line[..line.len() - trimmed.len()];
        lines.push(format!("{indentation}- uses: {action}@{sha} # {version}"));
        changed = true;
    }
    Ok(changed.then(|| format!("{}\n", lines.join("\n"))))
}

fn transform_workflow(text: &str, code: &str) -> Option<String> {
    let mut value: serde_norway::Value = serde_norway::from_str(text).ok()?;
    let root = value.as_mapping_mut()?;
    let key = serde_norway::Value::String;
    match code {
        "add-pull-request-trigger" => {
            let on = root
                .entry(key("on".to_owned()))
                .or_insert_with(|| serde_norway::Value::Mapping(Default::default()));
            on.as_mapping_mut()?
                .insert(key("pull_request".to_owned()), serde_norway::Value::Null);
        }
        "empty-workflow-permissions" => {
            root.insert(
                key("permissions".to_owned()),
                serde_norway::Value::Mapping(Default::default()),
            );
        }
        "add-ci-concurrency-group" => {
            root.insert(
                key("concurrency".to_owned()),
                serde_norway::from_str(
                    "group: ci-${{ github.event.pull_request.number || github.ref }}\ncancel-in-progress: true\n",
                )
                .ok()?,
            );
        }
        "supply-airlock-token" => {
            let jobs = root.get_mut(key("jobs".to_owned()))?.as_mapping_mut()?;
            for job in jobs
                .values_mut()
                .filter_map(serde_norway::Value::as_mapping_mut)
            {
                let Some(steps) = job
                    .get_mut(key("steps".to_owned()))
                    .and_then(serde_norway::Value::as_sequence_mut)
                else {
                    continue;
                };
                for step in steps
                    .iter_mut()
                    .filter_map(serde_norway::Value::as_mapping_mut)
                {
                    let is_airlock = step
                        .get(key("uses".to_owned()))
                        .and_then(serde_norway::Value::as_str)
                        .is_some_and(|uses| uses.contains("/airlock"));
                    if is_airlock {
                        let env = step
                            .entry(key("env".to_owned()))
                            .or_insert_with(|| serde_norway::Value::Mapping(Default::default()));
                        env.as_mapping_mut()?.insert(
                            key("AIRLOCK_TOKEN".to_owned()),
                            "${{ secrets.AIRLOCK_TOKEN }}".into(),
                        );
                    }
                }
            }
        }
        "add-tag-trigger" => add_push_trigger(root, "tags", "*"),
        "add-push-trigger" => add_push_trigger(root, "branches", "main"),
        "set-cd-concurrency" => {
            root.insert(
                key("concurrency".to_owned()),
                serde_norway::from_str("group: cd-${{ github.ref }}\ncancel-in-progress: false\n")
                    .ok()?,
            );
        }
        _ => return None,
    }
    serde_norway::to_string(&value).ok()
}

fn add_push_trigger(root: &mut serde_norway::Mapping, selector: &str, value: &str) {
    let key = serde_norway::Value::String;
    let on = root
        .entry(key("on".to_owned()))
        .or_insert_with(|| serde_norway::Value::Mapping(Default::default()));
    let Some(on) = on.as_mapping_mut() else {
        return;
    };
    let push = on
        .entry(key("push".to_owned()))
        .or_insert_with(|| serde_norway::Value::Mapping(Default::default()));
    let Some(push) = push.as_mapping_mut() else {
        return;
    };
    push.insert(
        key(selector.to_owned()),
        serde_norway::Value::Sequence(vec![value.into()]),
    );
}

fn package_license_operations(
    finding: &Finding,
    facts: &WorkingTreeFacts,
) -> Vec<PlannedOperation> {
    let license_path = facts.root.join("LICENSE");
    let license = if license_path.exists() {
        repository_license(&facts.root)
    } else {
        Some("Apache-2.0".to_owned())
    };
    let Some(license) = license else {
        return ["Cargo.toml", "package.json", "pubspec.yaml"]
            .into_iter()
            .filter(|path| facts.root.join(path).exists())
            .map(|path| PlannedOperation {
                path: path.to_owned(),
                kind: OperationKind::Skip(
                    "the committed LICENSE could not be identified; package metadata was left untouched"
                        .to_owned(),
                ),
                rule: finding.rule.clone(),
                code: "declare-package-license".to_owned(),
            })
            .collect();
    };
    ["Cargo.toml", "package.json", "pubspec.yaml"]
        .into_iter()
        .filter_map(|path| {
            let text = fs::read_to_string(facts.root.join(path)).ok()?;
            let transformed = match path {
                "Cargo.toml" => {
                    let mut value: toml::Value = toml::from_str(&text).ok()?;
                    let package = if value.get("package").is_some() {
                        value
                            .get_mut("package")
                            .and_then(toml::Value::as_table_mut)?
                    } else {
                        value
                            .get_mut("workspace")
                            .and_then(toml::Value::as_table_mut)
                            .and_then(|workspace| workspace.get_mut("package"))
                            .and_then(toml::Value::as_table_mut)?
                    };
                    package.insert("license".to_owned(), license.clone().into());
                    toml::to_string_pretty(&value).ok()?
                }
                "package.json" => {
                    let mut value: serde_json::Value = serde_json::from_str(&text).ok()?;
                    value["license"] = license.clone().into();
                    format!("{}\n", serde_json::to_string_pretty(&value).ok()?)
                }
                "pubspec.yaml" => {
                    let mut value: serde_norway::Value = serde_norway::from_str(&text).ok()?;
                    value
                        .as_mapping_mut()?
                        .insert("license".into(), license.clone().into());
                    serde_norway::to_string(&value).ok()?
                }
                _ => return None,
            };
            Some(PlannedOperation {
                path: path.to_owned(),
                kind: OperationKind::Write(transformed.into_bytes()),
                rule: finding.rule.clone(),
                code: "declare-package-license".to_owned(),
            })
        })
        .collect()
}

fn repository_license(root: &Path) -> Option<String> {
    let text = fs::read_to_string(root.join("LICENSE")).ok()?;
    if text.contains("Apache License") {
        Some("Apache-2.0".to_owned())
    } else if text.contains("CC0 1.0 Universal") || text.contains("Creative Commons Zero") {
        Some("CC0-1.0".to_owned())
    } else if text.contains("Permission is hereby granted, free of charge") {
        Some("MIT".to_owned())
    } else {
        None
    }
}

fn forbidden_paths(facts: &WorkingTreeFacts) -> Vec<String> {
    const PREFIXES: &[&str] = &[
        ".claude",
        ".cursor",
        ".windsurf",
        ".codex",
        ".aider.conf.yml",
        ".github/copilot-instructions.md",
    ];
    facts
        .tree
        .entries
        .iter()
        .filter(|entry| {
            PREFIXES.iter().any(|prefix| {
                entry.path == *prefix || entry.path.starts_with(&format!("{prefix}/"))
            })
        })
        .map(|entry| entry.path.clone())
        .collect()
}

fn release_unit_paths(root: &Path) -> Vec<String> {
    let Some(text) = fs::read_to_string(root.join(".intentional/config.yml")).ok() else {
        return Vec::new();
    };
    let Some(units) = serde_norway::from_str::<serde_norway::Value>(&text)
        .ok()
        .and_then(|value| value.get("release-units").cloned())
        .and_then(|value| value.as_mapping().cloned())
    else {
        return Vec::new();
    };
    units
        .values()
        .filter_map(|unit| unit.get("path").and_then(serde_norway::Value::as_str))
        .map(|path| {
            if path == "." {
                "CHANGELOG.md".to_owned()
            } else {
                format!("{}/CHANGELOG.md", path.trim_end_matches('/'))
            }
        })
        .collect()
}

fn skipped(operation: &PlannedOperation, reason: &str) -> PathOperation {
    PathOperation {
        path: operation.path.clone(),
        operation: operation.kind.name().to_owned(),
        rule: operation.rule.clone(),
        remediation_code: operation.code.clone(),
        outcome: "skipped".to_owned(),
        reason: Some(reason.to_owned()),
    }
}

fn apply(root: &Path, operation: &PlannedOperation) -> std::io::Result<()> {
    let target = root.join(&operation.path);
    match &operation.kind {
        OperationKind::Write(contents) => atomic_write(&target, contents),
        OperationKind::Symlink(destination) => atomic_symlink(&target, destination),
        OperationKind::Remove => atomic_remove(&target),
        OperationKind::Skip(_) => Ok(()),
    }
}

fn staging_path(target: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("path");
    target.with_file_name(format!(".{name}.airlock-{}-{nonce}", std::process::id()))
}

fn atomic_write(target: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = staging_path(target);
    fs::write(&staging, contents)?;
    fs::rename(staging, target)
}

#[cfg(unix)]
fn atomic_symlink(target: &Path, destination: &str) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = staging_path(target);
    symlink(destination, &staging)?;
    fs::rename(staging, target)
}

#[cfg(not(unix))]
fn atomic_symlink(_target: &Path, _destination: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink alignment is unsupported on this platform",
    ))
}

fn atomic_remove(target: &Path) -> std::io::Result<()> {
    if fs::symlink_metadata(target).is_err() {
        return Ok(());
    }
    let staging = staging_path(target);
    fs::rename(target, &staging)?;
    if fs::symlink_metadata(&staging)?.file_type().is_dir() {
        fs::remove_dir_all(staging)
    } else {
        fs::remove_file(staging)
    }
}

impl OperationKind {
    const fn name(&self) -> &'static str {
        match self {
            Self::Write(_) => "write",
            Self::Symlink(_) => "symlink",
            Self::Remove => "remove",
            Self::Skip(_) => "write",
        }
    }
}

/// Every deterministic remediation code has an author dispatch entry.
#[must_use]
pub fn implemented_codes() -> BTreeSet<&'static str> {
    [
        "remove-org-name-topics",
        "declare-merge-settings",
        "remove-visibility-field",
        "add-license-file",
        "declare-package-license",
        "add-gitattributes",
        "add-editorconfig",
        "add-ci-workflow",
        "add-renovate-config",
        "add-audit-workflow",
        "add-lefthook-config",
        "add-claude-symlink",
        "remove-agent-harness-config",
        "remove-codeowners",
        "set-include-dirs",
        "align-include-namespaces",
        "add-pull-request-trigger",
        "empty-workflow-permissions",
        "pin-actions-to-shas",
        "add-ci-concurrency-group",
        "add-title-check",
        "supply-airlock-token",
        "add-tag-trigger",
        "add-push-trigger",
        "set-cd-concurrency",
        "configure-pre-commit-hook",
        "configure-commit-msg-hook",
        "configure-pre-push-hook",
        "add-unit-changelogs",
        "remove-root-changelog",
        "remove-custom-property-values",
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::findings::{
        AirlockIdentity, AuditedRepository, Gate, ObservationRecord, PolicyIdentity,
        RemediationClass,
    };
    use crate::remediation;

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn repository() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        git(directory.path(), &["init", "-q", "-b", "main"]);
        fs::write(directory.path().join("seed"), "seed\n").unwrap();
        git(directory.path(), &["add", "seed"]);
        git(directory.path(), &["commit", "-q", "-m", "fixture"]);
        directory
    }

    fn report(rule: &str) -> Report {
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "example/project".to_owned(),
                id: None,
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            ObservationRecord {
                file_source: "working-tree".to_owned(),
                platform_source: None,
                working_tree: None,
            },
            PolicyIdentity {
                name: "test".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                sources: Vec::new(),
                bundle_digest: format!("sha256:{}", "b".repeat(64)),
                gate: Gate::Blocking,
            },
            Vec::new(),
            Vec::new(),
            vec![Finding {
                rule: rule.to_owned(),
                statement: "fixture".to_owned(),
                severity: "required".to_owned(),
                status: Status::Fail,
                evidence: None,
                remediation: None,
                remediation_class: RemediationClass::for_rule(rule),
                suppression: None,
                source: Some("working-tree".to_owned()),
                error: None,
            }],
        )
    }

    #[test]
    fn every_deterministic_lane_entry_has_an_author() {
        let declared: BTreeSet<_> = remediation::CLASSIFICATIONS
            .iter()
            .filter_map(remediation::Classification::remediation)
            .filter(|definition| definition.lane == Lane::DeterministicFile)
            .map(|definition| definition.code)
            .collect();
        assert_eq!(implemented_codes(), declared);
    }

    #[test]
    fn authorization_bearing_paths_are_not_author_targets() {
        for definition in remediation::CLASSIFICATIONS
            .iter()
            .filter_map(remediation::Classification::remediation)
        {
            let finding = report(definition.rule);
            let directory = repository();
            let facts = worktree::read_facts(directory.path()).unwrap();
            assert!(author_for(definition.code, &finding.findings[0], &facts)
                .iter()
                .all(|operation| !AUTHORIZATION_BEARING_PATHS.contains(&operation.path.as_str())));
        }
    }

    #[test]
    fn writes_a_missing_file_then_treats_the_uncommitted_result_as_locally_owned() {
        let directory = repository();
        let first = author(directory.path(), &report("REPO-FILE-05")).unwrap();
        assert_eq!(first.operations[0].outcome, "written");
        assert_eq!(
            fs::read_to_string(directory.path().join(".editorconfig")).unwrap(),
            EDITORCONFIG
        );
        assert_eq!(first.dirty_before, Some(false));
        assert_eq!(first.dirty_after, Some(true));

        let second = author(directory.path(), &report("REPO-FILE-05")).unwrap();
        assert_eq!(second.operations[0].outcome, "skipped");
        assert!(second.operations[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("locally modified"));
    }

    #[test]
    fn skips_a_dirty_target_without_refusing_the_dirty_tree() {
        let directory = repository();
        fs::write(directory.path().join(".gitattributes"), "*.png binary\n").unwrap();
        git(directory.path(), &["add", ".gitattributes"]);
        git(directory.path(), &["commit", "-q", "-m", "attributes"]);
        fs::write(directory.path().join(".gitattributes"), "*.png -text\n").unwrap();

        let result = author(directory.path(), &report("REPO-FILE-04")).unwrap();
        assert_eq!(result.dirty_before, Some(true));
        assert_eq!(result.operations[0].outcome, "skipped");
        assert_eq!(
            fs::read_to_string(directory.path().join(".gitattributes")).unwrap(),
            "*.png -text\n"
        );
    }

    #[test]
    fn a_path_failure_reports_what_was_not_written() {
        let directory = repository();
        fs::create_dir(directory.path().join(".editorconfig")).unwrap();
        let error = author(directory.path(), &report("REPO-FILE-05")).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("\"outcome\":\"not_written\""));
        assert!(text.contains("\"path\":\".editorconfig\""));
    }

    #[test]
    fn action_pinning_is_reviewed_and_unknown_actions_are_left_untouched() {
        let known = "steps:\n  - uses: actions/checkout@v4\n";
        let pinned = pin_actions(known).unwrap().unwrap();
        assert!(pinned.contains("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4"));

        let unknown = pin_actions("steps:\n  - uses: example/action@v1\n").unwrap_err();
        assert!(unknown.contains("no compiled-in reviewed pin"));
    }

    #[test]
    fn author_paths_cannot_escape_the_repository() {
        assert!(safe_repository_path(".github/workflows/ci.yml"));
        assert!(!safe_repository_path("../outside"));
        assert!(!safe_repository_path("/outside"));
    }
}
