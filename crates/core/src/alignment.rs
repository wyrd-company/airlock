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

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, Report, Status};
use crate::remediation::Lane;
use crate::worktree::{self, WorkingTreeFacts, AUTHORIZATION_BEARING_PATHS};
use crate::{Error, Result};

/// One deterministic file suitable for the branch-creating commit of an empty
/// repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldFile {
    pub path: String,
    pub contents: Vec<u8>,
}

/// Resolve the fixed-content deterministic files required by a policy's
/// unconditional capability profile.
///
/// Repository-specific and destructive transformations are deliberately not
/// expressible here. They remain ordinary audit gaps after the first commit.
#[must_use]
pub fn scaffold_files(policy: &crate::policy::ResolvedPolicy) -> Vec<ScaffoldFile> {
    let mut files = BTreeMap::new();
    for rule in policy
        .rules
        .iter()
        .filter(|rule| rule.condition == crate::policy::Condition::Always)
    {
        let Some(definition) = crate::remediation::classify(rule.def.id)
            .and_then(crate::remediation::Classification::remediation)
            .filter(|definition| definition.lane == Lane::DeterministicFile)
        else {
            continue;
        };
        match deterministic_author(definition.code, rule.param_str("renovate-preset"), None)
            .unwrap_or_else(|| {
                panic!(
                    "deterministic remediation `{}` has no scaffold author dispatch",
                    definition.code
                )
            }) {
            DeterministicAuthor::File(path, contents) => {
                files.entry(path).or_insert(contents);
            }
            DeterministicAuthor::OrdinaryLane => {}
        }
    }
    files
        .into_iter()
        .map(|(path, contents)| ScaffoldFile { path, contents })
        .collect()
}

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

[*.{go,mod}]
indent_style = tab

[*.rs]
indent_size = 4

[*.py]
indent_size = 4

[Makefile]
indent_style = tab
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
      # Replace this placeholder with the full SHA of a released Airlock version.
      - uses: wyrd-company/airlock@0123456789abcdef0123456789abcdef01234567 # 0.0.1
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PathOperation {
    pub path: String,
    pub operation: String,
    pub rule: String,
    pub remediation_code: String,
    pub outcome: String,
    pub reason: Option<String>,
}

/// A judgment-lane finding handed to an agent using the embedded skill.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Debug, Clone)]
enum AuthorResult {
    Authored {
        first: PlannedOperation,
        additional: Vec<PlannedOperation>,
    },
    Skipped(PlannedOperation),
}

impl AuthorResult {
    fn from_operations(
        operations: Vec<PlannedOperation>,
        fallback: PlannedOperation,
        reason: impl Into<String>,
    ) -> Self {
        let mut operations = operations.into_iter();
        let Some(first) = operations.next() else {
            return Self::Skipped(PlannedOperation {
                kind: OperationKind::Skip(reason.into()),
                ..fallback
            });
        };
        Self::Authored {
            first,
            additional: operations.collect(),
        }
    }

    fn into_operations(self) -> Vec<PlannedOperation> {
        match self {
            Self::Authored {
                first,
                mut additional,
            } => {
                additional.insert(0, first);
                additional
            }
            Self::Skipped(operation) => vec![operation],
        }
    }
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
        for operation in author_for(code, finding, facts).into_operations() {
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
                        "another remediation in this run already owns the path; commit the \
                         reported write, then re-run alignment to apply this remediation"
                            .to_owned(),
                    ),
                });
            }
        }
    }
    operations
}

fn author_for(code: &str, finding: &Finding, facts: &WorkingTreeFacts) -> AuthorResult {
    let operation = |path: &str, kind| PlannedOperation {
        path: path.to_owned(),
        kind,
        rule: finding.rule.clone(),
        code: code.to_owned(),
    };
    let fallback_path = finding
        .evidence
        .as_ref()
        .and_then(|evidence| evidence.path.as_deref())
        .unwrap_or("(no path identified)");
    let fallback = || operation(fallback_path, OperationKind::Skip(String::new()));
    let operations = match code {
        code @ ("add-license-file"
        | "add-gitattributes"
        | "add-editorconfig"
        | "add-ci-workflow"
        | "add-renovate-config"
        | "add-audit-workflow"
        | "add-lefthook-config"
        | "add-title-check") => deterministic_author(
            code,
            finding
                .remediation
                .as_ref()
                .and_then(|remediation| remediation.detail.split('`').nth(1))
                .or((code == "add-renovate-config").then_some("github>wyrd-company/.github")),
            Some(&facts.root),
        )
        .and_then(|author| match author {
            DeterministicAuthor::File(path, contents) => {
                Some(operation(&path, OperationKind::Write(contents)))
            }
            DeterministicAuthor::OrdinaryLane => None,
        })
        .into_iter()
        .collect(),
        "add-claude-symlink" => {
            if facts.root.join("AGENTS.md").is_file() {
                vec![operation(
                    "CLAUDE.md",
                    OperationKind::Symlink("AGENTS.md".to_owned()),
                )]
            } else {
                vec![operation(
                    "CLAUDE.md",
                    OperationKind::Skip(
                        "AGENTS.md is absent; refusing to create a dangling CLAUDE.md symlink"
                            .to_owned(),
                    ),
                )]
            }
        }
        "remove-agent-harness-config" => forbidden_paths(facts)
            .into_iter()
            .map(|path| operation(&path, OperationKind::Remove))
            .collect(),
        "remove-codeowners" => ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
            .into_iter()
            .filter(|path| facts.tree.entries.iter().any(|entry| entry.path == *path))
            .map(|path| operation(path, OperationKind::Remove))
            .collect(),
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
    };
    AuthorResult::from_operations(
        operations,
        fallback(),
        format!("remediation `{code}` could not identify a safe authored operation"),
    )
}

enum DeterministicAuthor {
    File(String, Vec<u8>),
    OrdinaryLane,
}

fn deterministic_author(
    code: &str,
    renovate_preset: Option<&str>,
    root: Option<&Path>,
) -> Option<DeterministicAuthor> {
    let fixed = |path: &str, contents: &str| {
        Some(DeterministicAuthor::File(
            path.to_owned(),
            contents.as_bytes().to_vec(),
        ))
    };
    match code {
        "add-license-file" => fixed("LICENSE", APACHE_2_LICENSE),
        "add-gitattributes" => Some(DeterministicAuthor::File(
            ".gitattributes".to_owned(),
            append_line_if_present(root, ".gitattributes", GITATTRIBUTES).into_bytes(),
        )),
        "add-editorconfig" => fixed(".editorconfig", EDITORCONFIG),
        "add-ci-workflow" => fixed(".github/workflows/ci.yml", CI_WORKFLOW),
        "add-renovate-config" => Some(renovate_preset.map_or(
            DeterministicAuthor::OrdinaryLane,
            |preset| {
                DeterministicAuthor::File(
                    ".github/renovate.json".to_owned(),
                    renovate_contents(root, preset).into_bytes(),
                )
            },
        )),
        "add-audit-workflow" => fixed(".github/workflows/audit.yml", AUDIT_WORKFLOW),
        "add-lefthook-config" => fixed(".config/lefthook.yml", LEFTHOOK),
        "add-title-check" => fixed(".github/workflows/pr-title.yml", TITLE_WORKFLOW),
        "remove-org-name-topics"
        | "declare-merge-settings"
        | "remove-visibility-field"
        | "declare-package-license"
        | "add-claude-symlink"
        | "remove-agent-harness-config"
        | "remove-codeowners"
        | "set-include-dirs"
        | "align-include-namespaces"
        | "add-pull-request-trigger"
        | "empty-workflow-permissions"
        | "pin-actions-to-shas"
        | "add-ci-concurrency-group"
        | "supply-airlock-token"
        | "add-tag-trigger"
        | "add-push-trigger"
        | "set-cd-concurrency"
        | "configure-pre-commit-hook"
        | "configure-commit-msg-hook"
        | "configure-pre-push-hook"
        | "add-unit-changelogs"
        | "remove-root-changelog"
        | "remove-custom-property-values" => Some(DeterministicAuthor::OrdinaryLane),
        _ => None,
    }
}

fn append_line_if_present(root: Option<&Path>, path: &str, line: &str) -> String {
    match root.and_then(|root| fs::read_to_string(root.join(path)).ok()) {
        Some(mut text) => {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(line);
            text
        }
        None => line.to_owned(),
    }
}

fn renovate_contents(root: Option<&Path>, expected: &str) -> String {
    let mut value = root
        .and_then(|root| fs::read_to_string(root.join(".github/renovate.json")).ok())
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
    let Ok(mut value) = serde_norway::from_str::<serde_norway::Value>(&text) else {
        return vec![PlannedOperation {
            path: path.to_owned(),
            kind: OperationKind::Skip("the YAML document could not be parsed".to_owned()),
            rule: finding.rule.clone(),
            code: code.to_owned(),
        }];
    };
    let Some(mapping) = value.as_mapping_mut() else {
        return vec![PlannedOperation {
            path: path.to_owned(),
            kind: OperationKind::Skip("the YAML document root is not a mapping".to_owned()),
            rule: finding.rule.clone(),
            code: code.to_owned(),
        }];
    };
    let key = serde_norway::Value::String;
    let changed_keys: &[&str] = match code {
        "remove-visibility-field" => {
            mapping.remove(key("visibility".to_owned()));
            &["visibility"]
        }
        "remove-custom-property-values" => {
            mapping.remove(key("custom-properties".to_owned()));
            mapping.remove(key("custom_properties".to_owned()));
            &["custom-properties", "custom_properties"]
        }
        "declare-merge-settings" => {
            let mut merge = serde_norway::Mapping::new();
            merge.insert(key("squash".to_owned()), true.into());
            merge.insert(key("rebase".to_owned()), true.into());
            merge.insert(key("merge_commit".to_owned()), false.into());
            merge.insert(key("delete_branch_on_merge".to_owned()), true.into());
            mapping.insert(key("merge".to_owned()), serde_norway::Value::Mapping(merge));
            &["merge"]
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
            &["topics"]
        }
        "set-include-dirs" | "align-include-namespaces" => {
            // These transformations are structural and depend only on the
            // declared include path. Preserve the document when there are no
            // includes rather than inventing repository-specific tasks.
            align_taskfile_includes(mapping, code, &facts.root);
            &["includes"]
        }
        _ => &[],
    };
    let contents = patch_top_level_keys(&text, &value, changed_keys);
    vec![PlannedOperation {
        path: path.to_owned(),
        kind: OperationKind::Write(contents.into_bytes()),
        rule: finding.rule.clone(),
        code: code.to_owned(),
    }]
}

fn patch_top_level_keys(text: &str, value: &serde_norway::Value, keys: &[&str]) -> String {
    let Some(mapping) = value.as_mapping() else {
        return text.to_owned();
    };
    let mut result = text.to_owned();
    for key in keys {
        let replacement = mapping
            .get(serde_norway::Value::String((*key).to_owned()))
            .and_then(|entry| {
                let mut single = serde_norway::Mapping::new();
                single.insert(
                    serde_norway::Value::String((*key).to_owned()),
                    entry.clone(),
                );
                serde_norway::to_string(&serde_norway::Value::Mapping(single)).ok()
            });
        result = replace_top_level_block(&result, key, replacement.as_deref());
    }
    result
}

fn replace_top_level_block(text: &str, key: &str, replacement: Option<&str>) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let marker = format!("{key}:");
    let start = lines.iter().position(|line| {
        let bare = line.trim_end_matches(['\r', '\n']);
        !bare.starts_with(char::is_whitespace)
            && bare.strip_prefix(&marker).is_some_and(|tail| {
                tail.is_empty() || tail.starts_with(' ') || tail.starts_with('\t')
            })
    });
    let end = start.map(|start| {
        lines
            .iter()
            .enumerate()
            .skip(start + 1)
            .find(|(_, line)| {
                let bare = line.trim_end_matches(['\r', '\n']);
                !bare.is_empty() && !bare.starts_with(char::is_whitespace)
            })
            .map_or(lines.len(), |(index, _)| index)
    });
    let insertion = replacement.unwrap_or("");
    match (start, end) {
        (Some(start), Some(end)) => {
            let mut output = lines[..start].concat();
            output.push_str(insertion);
            output.push_str(&lines[end..].concat());
            output
        }
        (None, _) if replacement.is_some() => {
            let mut output = text.to_owned();
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(insertion);
            output
        }
        _ => text.to_owned(),
    }
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
        let uses = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"));
        let Some(value) = uses.map(str::trim) else {
            lines.push(line.to_owned());
            continue;
        };
        let value = value.split('#').next().unwrap_or(value).trim();
        if value.starts_with("./") || value.starts_with("docker://") {
            lines.push(line.to_owned());
            continue;
        }
        let Some((action, reference)) = value.rsplit_once('@') else {
            return Err(format!("`{value}` has no action reference to pin"));
        };
        if reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            lines.push(line.to_owned());
            continue;
        }
        let Some((_, sha, version)) = PINS.iter().find(|(known, _, _)| *known == action) else {
            return Err(format!(
                "`{action}` has no compiled-in reviewed pin; the path was left untouched"
            ));
        };
        let value_offset = line.find(value).unwrap_or(line.len());
        lines.push(format!(
            "{}{action}@{sha} # {version}",
            &line[..value_offset]
        ));
        changed = true;
    }
    Ok(changed.then(|| format!("{}\n", lines.join("\n"))))
}

fn transform_workflow(text: &str, code: &str) -> Option<String> {
    if code == "supply-airlock-token" {
        return supply_airlock_token(text);
    }
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
    let changed = match code {
        "add-pull-request-trigger" | "add-tag-trigger" | "add-push-trigger" => &["on"][..],
        "empty-workflow-permissions" => &["permissions"][..],
        "add-ci-concurrency-group" | "set-cd-concurrency" => &["concurrency"][..],
        _ => return None,
    };
    Some(patch_top_level_keys(text, &value, changed))
}

fn supply_airlock_token(text: &str) -> Option<String> {
    if text.contains("AIRLOCK_TOKEN:") {
        return Some(text.to_owned());
    }
    let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
    let uses_index = lines.iter().position(|line| {
        line.trim_start()
            .trim_start_matches("- ")
            .strip_prefix("uses:")
            .is_some_and(|uses| uses.contains("/airlock"))
    })?;
    let indentation = lines[uses_index].len() - lines[uses_index].trim_start().len();
    let step_end = lines
        .iter()
        .enumerate()
        .skip(uses_index + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            indent <= indentation && trimmed.starts_with("- ")
        })
        .map_or(lines.len(), |(index, _)| index);
    let env_index = lines
        .iter()
        .enumerate()
        .take(step_end)
        .skip(uses_index + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            indent == indentation + 2 && trimmed.starts_with("env:")
        })
        .map(|(index, _)| index);
    let insertion = if let Some(env_index) = env_index {
        (
            env_index + 1,
            format!(
                "{}AIRLOCK_TOKEN: ${{{{ secrets.AIRLOCK_TOKEN }}}}",
                " ".repeat(indentation + 4)
            ),
        )
    } else {
        (
            uses_index + 1,
            format!(
                "{}env:\n{}AIRLOCK_TOKEN: ${{{{ secrets.AIRLOCK_TOKEN }}}}",
                " ".repeat(indentation + 2),
                " ".repeat(indentation + 4)
            ),
        )
    };
    lines.insert(insertion.0, insertion.1);
    Some(format!("{}\n", lines.join("\n")))
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
    if let Err(error) = fs::rename(&staging, target) {
        let _ = fs::remove_file(staging);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_symlink(target: &Path, destination: &str) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = staging_path(target);
    symlink(destination, &staging)?;
    if let Err(error) = fs::rename(&staging, target) {
        let _ = fs::remove_file(staging);
        return Err(error);
    }
    Ok(())
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

    #[test]
    fn scaffold_files_include_only_fixed_deterministic_unconditional_rules() {
        let rule = |id, condition| crate::policy::RuleInstance {
            def: crate::registry::find(id).expect("registered rule"),
            severity: crate::registry::Severity::Required,
            params: BTreeMap::new(),
            provenance: "capability:fixture".to_owned(),
            condition,
        };
        let policy = crate::policy::ResolvedPolicy {
            name: "fixture".to_owned(),
            source: "fixture".to_owned(),
            commit: None,
            bundle_digest: "digest".to_owned(),
            sources: Vec::new(),
            gate: Gate::Blocking,
            rules: vec![
                rule("REPO-LIC-01", crate::policy::Condition::Always),
                rule(
                    "REPO-FILE-05",
                    crate::policy::Condition::CustomProperty {
                        name: "publishes".to_owned(),
                        value: "true".to_owned(),
                    },
                ),
            ],
            suppressions: Default::default(),
            reference_data: Default::default(),
            capabilities: Vec::new(),
        };
        let files = scaffold_files(&policy);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "LICENSE");
        assert_eq!(files[0].contents, APACHE_2_LICENSE.as_bytes());
    }

    #[test]
    fn scaffolded_bytes_are_the_bytes_the_deterministic_author_would_write() {
        let preset = "github>wyrd-company/.github";
        let policy = crate::policy::ResolvedPolicy {
            name: "fixture".to_owned(),
            source: "fixture".to_owned(),
            commit: None,
            bundle_digest: "digest".to_owned(),
            sources: Vec::new(),
            gate: Gate::Blocking,
            rules: vec![crate::policy::RuleInstance {
                def: crate::registry::find("REPO-FILE-08").expect("registered rule"),
                severity: crate::registry::Severity::Required,
                params: BTreeMap::from([("renovate-preset".to_owned(), serde_json::json!(preset))]),
                provenance: "fixture".to_owned(),
                condition: crate::policy::Condition::Always,
            }],
            suppressions: Default::default(),
            reference_data: Default::default(),
            capabilities: Vec::new(),
        };
        let scaffolded = scaffold_files(&policy);
        let directory = repository();
        let facts = worktree::read_facts(directory.path()).unwrap();
        let authored = report("REPO-FILE-08");
        let operations =
            author_for("add-renovate-config", &authored.findings[0], &facts).into_operations();
        let OperationKind::Write(expected) = &operations[0].kind else {
            panic!("renovate author did not produce a write")
        };

        assert_eq!(scaffolded[0].path, operations[0].path);
        assert_eq!(&scaffolded[0].contents, expected);
    }

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
    fn every_deterministic_author_declares_its_scaffold_disposition() {
        for code in implemented_codes() {
            assert!(
                deterministic_author(code, Some("generic-preset"), None).is_some(),
                "{code} has no scaffold disposition"
            );
        }
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
                .into_operations()
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

        let named = "steps:\n  - name: Checkout\n    uses: actions/checkout@v4\n";
        let pinned = pin_actions(named).unwrap().unwrap();
        assert!(pinned
            .contains("    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4"));

        assert_eq!(
            pin_actions("steps:\n  - uses: ./.github/actions/build\n").unwrap(),
            None
        );
        assert_eq!(
            pin_actions("steps:\n  - uses: docker://example.invalid/tool\n").unwrap(),
            None
        );

        let unknown = pin_actions("steps:\n  - uses: example/action@v1\n").unwrap_err();
        assert!(unknown.contains("no compiled-in reviewed pin"));
    }

    #[test]
    fn non_mapping_yaml_and_empty_authors_are_reported_as_skipped() {
        let directory = repository();
        fs::create_dir_all(directory.path().join(".github")).unwrap();
        fs::write(
            directory.path().join(".github/repo-settings.yml"),
            "# comments only\n",
        )
        .unwrap();
        git(directory.path(), &["add", ".github/repo-settings.yml"]);
        git(directory.path(), &["commit", "-q", "-m", "settings"]);

        let result = author(directory.path(), &report("REPO-META-11")).unwrap();
        assert_eq!(result.operations[0].outcome, "skipped");
        assert!(result.operations[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("root is not a mapping"));

        let result = author(directory.path(), &report("REPO-REL-02")).unwrap();
        assert_eq!(result.operations[0].outcome, "skipped");
        assert!(result.operations[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("could not identify"));
    }

    #[test]
    fn yaml_edits_preserve_unaffected_comments_and_action_pin_comments() {
        let workflow = "\
# workflow comment
name: CI
jobs:
  check:
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
";
        let transformed = transform_workflow(workflow, "empty-workflow-permissions").unwrap();
        assert!(transformed.contains("# workflow comment"));
        assert!(transformed.contains("# v4"));
        assert!(transformed.contains("permissions: {}"));
    }

    #[test]
    fn audit_workflow_uses_an_explicit_unreleased_placeholder() {
        assert!(AUDIT_WORKFLOW
            .contains("wyrd-company/airlock@0123456789abcdef0123456789abcdef01234567 # 0.0.1"));
        assert!(AUDIT_WORKFLOW.contains("Replace this placeholder"));
        assert!(!AUDIT_WORKFLOW.contains("bfe5533"));
    }

    #[test]
    fn claude_symlink_is_skipped_until_agents_exists() {
        let directory = repository();
        let result = author(directory.path(), &report("REPO-FILE-12")).unwrap();
        assert_eq!(result.operations[0].outcome, "skipped");
        assert!(result.operations[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("dangling"));
        assert!(!directory.path().join("CLAUDE.md").exists());
    }

    #[test]
    fn author_paths_cannot_escape_the_repository() {
        assert!(safe_repository_path(".github/workflows/ci.yml"));
        assert!(!safe_repository_path("../outside"));
        assert!(!safe_repository_path("/outside"));
    }
}
