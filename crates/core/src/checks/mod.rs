//! The checks.
//!
//! A check turns one rule instance and one repository snapshot into one
//! verdict. Checks never fetch: everything they read was gathered into the
//! snapshot at a single resolved commit, so a verdict describes a repository
//! state that existed.
//!
//! The rule that governs every check: never report `pass` for an assertion the
//! check did not fully evaluate. A bounded scan that ran out of budget is
//! inconclusive. A rule whose remaining clause is a judgment call is manual.
//! Absence of evidence is never evidence of conformance.

mod automation;
mod classification;
mod files;
mod git;
mod identity;
mod licensing;
mod release;

use crate::findings::{Evidence, FindingError, Remediation, Status};
use crate::github::{ApiError, BranchRule, CommitSummary, Ruleset, TagRef, MESSAGE_HINTS_VERSION};
use crate::limits::Limits;
use crate::policy::{Condition, ResolvedPolicy, RuleInstance};
use crate::registry::Evaluation;
use crate::snapshot::{FileState, RepoSnapshot};
use crate::yaml::{self, Yaml};

/// What one check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The status.
    pub status: Status,
    /// What was observed.
    pub evidence: Option<Evidence>,
    /// What to do about it.
    pub remediation: Option<Remediation>,
    /// What stopped the evaluation.
    pub error: Option<FindingError>,
}

impl Verdict {
    /// The assertion holds.
    #[must_use]
    pub fn pass(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            evidence: Some(Evidence::new(code, detail)),
            remediation: None,
            error: None,
        }
    }

    /// The assertion holds, and the evidence is about one path.
    #[must_use]
    pub fn pass_at(code: &str, path: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            evidence: Some(Evidence::at(code, path, detail)),
            remediation: None,
            error: None,
        }
    }

    /// The assertion does not hold.
    #[must_use]
    pub fn fail(code: &str, detail: impl Into<String>, remediation: Remediation) -> Self {
        Self {
            status: Status::Fail,
            evidence: Some(Evidence::new(code, detail)),
            remediation: Some(remediation),
            error: None,
        }
    }

    /// The assertion does not hold, and the evidence is about one path.
    #[must_use]
    pub fn fail_at(
        code: &str,
        path: &str,
        detail: impl Into<String>,
        remediation: Remediation,
    ) -> Self {
        Self {
            status: Status::Fail,
            evidence: Some(Evidence::at(code, path, detail)),
            remediation: Some(remediation),
            error: None,
        }
    }

    /// What airlock could decide holds; the rest is a judgment call.
    #[must_use]
    pub fn manual(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Manual,
            evidence: Some(Evidence::new(code, detail)),
            remediation: None,
            error: None,
        }
    }

    /// The assertion could not be decided within a budget.
    #[must_use]
    pub fn inconclusive(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Inconclusive,
            evidence: Some(Evidence::new(code, detail)),
            remediation: None,
            error: None,
        }
    }

    /// An API failure prevented the evaluation.
    #[must_use]
    pub fn from_api_error(error: &ApiError) -> Self {
        let remediation = match error.cause {
            crate::github::ErrorCause::Permission => Some(Remediation::new(
                "grant_permission",
                match &error.accepted_permissions {
                    Some(permissions) => format!(
                        "The credential lacks the permission {permissions} that {} requires.",
                        error.endpoint
                    ),
                    None => format!("The credential cannot read {}.", error.endpoint),
                },
            )),
            crate::github::ErrorCause::PlanLimitation => Some(Remediation::new(
                "plan_gate",
                format!(
                    "{} is gated by the account's GitHub plan, so airlock cannot read it.",
                    error.endpoint
                ),
            )),
            _ => None,
        };
        Self {
            status: Status::Error,
            evidence: None,
            remediation,
            error: Some(FindingError {
                cause: error.cause.code().to_owned(),
                endpoint: error.endpoint.clone(),
                status: error.status,
                message: error.message.clone(),
                documentation_url: error.documentation_url.clone(),
                accepted_permissions: error.accepted_permissions.clone(),
                request_id: error.request_id.clone(),
                message_hints_version: MESSAGE_HINTS_VERSION,
            }),
        }
    }
}

/// A workflow file, kept as both text and document.
///
/// The text matters: action pinning is partly a comment convention, and
/// comments do not survive parsing.
#[derive(Debug, Clone)]
pub struct Workflow {
    /// Path within the repository.
    pub path: String,
    /// File name.
    pub name: String,
    /// Raw text.
    pub text: String,
    /// The parsed document, when it parsed.
    pub document: Option<Yaml>,
    /// Why it did not parse, when it did not.
    pub parse_error: Option<String>,
}

impl Workflow {
    /// The workflow's triggers, whatever shape `on:` took.
    #[must_use]
    pub fn triggers(&self) -> Vec<String> {
        let Some(document) = &self.document else {
            return Vec::new();
        };
        match document.get("on") {
            Some(Yaml::String(name)) => vec![name.clone()],
            Some(Yaml::Seq(names)) => names
                .iter()
                .filter_map(|name| name.as_str().map(ToOwned::to_owned))
                .collect(),
            Some(Yaml::Map(entries)) => entries.iter().map(|(name, _)| name.clone()).collect(),
            _ => Vec::new(),
        }
    }

    /// The configuration under one trigger, when `on:` is a mapping.
    #[must_use]
    pub fn trigger(&self, name: &str) -> Option<&Yaml> {
        self.document.as_ref()?.get("on")?.get(name)
    }

    /// Whether the workflow declares a trigger.
    #[must_use]
    pub fn has_trigger(&self, name: &str) -> bool {
        self.triggers().iter().any(|trigger| trigger == name)
    }

    /// The jobs, in declaration order.
    #[must_use]
    pub fn jobs(&self) -> Vec<(&str, &Yaml)> {
        self.document
            .as_ref()
            .and_then(|document| document.get("jobs"))
            .and_then(Yaml::as_map)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(name, job)| (name.as_str(), job))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the workflow pushes to `branch`.
    #[must_use]
    pub fn pushes_to(&self, branch: &str) -> bool {
        let Some(push) = self.trigger("push") else {
            return false;
        };
        match push.get("branches").and_then(Yaml::as_seq) {
            Some(branches) => branches
                .iter()
                .any(|name| name.as_str() == Some(branch) || name.as_str() == Some("**")),
            // `on: push:` with no branch filter covers every branch.
            None => push.get("tags").is_none(),
        }
    }
}

/// Everything one audit run gathered, ready for the checks to read.
pub struct AuditContext<'a> {
    /// The repository at the audited commit.
    pub snapshot: &'a RepoSnapshot,
    /// The policy the audit runs under.
    pub policy: &'a ResolvedPolicy,
    /// The budgets in force.
    pub limits: Limits,
    /// Every workflow under `.github/workflows/`.
    pub workflows: Vec<Workflow>,
    /// Whether the workflow listing was cut short by a budget.
    pub workflows_truncated: bool,
    /// The repository's tags.
    pub tags: Result<Vec<TagRef>, ApiError>,
    /// Default-branch history, and whether the walk stopped at the budget.
    pub history: Result<(Vec<CommitSummary>, bool), ApiError>,
    /// Rulesets covering the repository, including inherited ones.
    pub rulesets: Result<Vec<Ruleset>, ApiError>,
    /// The effective rules on the default branch.
    pub branch_rules: Result<Vec<BranchRule>, ApiError>,
}

/// What airlock knows about a YAML file it wanted to read.
pub enum ParsedFile<'a> {
    /// Nothing is at that path.
    Missing,
    /// The file was read and parsed.
    Parsed(Yaml),
    /// The file could not be read or parsed, with the evidence saying why.
    Undecided(Box<Verdict>),
    /// The path holds something that is not a file.
    NotAFile(&'a FileState),
}

impl AuditContext<'_> {
    /// The audited repository, as `owner/name`.
    #[must_use]
    pub fn full_name(&self) -> &str {
        &self.snapshot.repository.full_name
    }

    /// The text of a file at the audited commit.
    #[must_use]
    pub fn text(&self, path: &str) -> Option<&str> {
        self.snapshot.file(path).text()
    }

    /// Whether a file is present and readable at the audited commit.
    #[must_use]
    pub fn has_file(&self, path: &str) -> bool {
        self.snapshot.file(path).is_content()
    }

    /// Parse a YAML file from the snapshot.
    #[must_use]
    pub fn yaml(&self, path: &str) -> ParsedFile<'_> {
        let state = self.snapshot.file(path);
        match state {
            FileState::Missing => ParsedFile::Missing,
            FileState::Content { .. } => {
                let text = state.text().unwrap_or_default();
                match yaml::parse_mapping(text, self.limits.yaml) {
                    Ok(document) => ParsedFile::Parsed(document),
                    Err(error) => ParsedFile::Undecided(Box::new(Verdict::inconclusive(
                        "unparseable_yaml",
                        format!("{path} could not be parsed: {error}"),
                    ))),
                }
            }
            FileState::OverBudget { size, limit } => {
                ParsedFile::Undecided(Box::new(Verdict::inconclusive(
                    "file_over_budget",
                    format!(
                        "{path} is {size} bytes, over the {limit} byte limit, so it was not read"
                    ),
                )))
            }
            FileState::Unreadable(error) => {
                ParsedFile::Undecided(Box::new(Verdict::from_api_error(error)))
            }
            FileState::Symlink { .. } | FileState::NotAFile { .. } => ParsedFile::NotAFile(state),
        }
    }

    /// The workflow at `.github/workflows/{name}`.
    #[must_use]
    pub fn workflow(&self, name: &str) -> Option<&Workflow> {
        self.workflows.iter().find(|workflow| workflow.name == name)
    }

    /// Release unit paths declared by `.intentional/config.yml`, if it parses.
    #[must_use]
    pub fn release_units(&self) -> Option<Vec<(String, String)>> {
        let ParsedFile::Parsed(document) = self.yaml(".intentional/config.yml") else {
            return None;
        };
        let units = document.get("release-units")?.as_map()?;
        Some(
            units
                .iter()
                .map(|(id, unit)| {
                    let path = unit
                        .get("path")
                        .and_then(Yaml::as_str)
                        .unwrap_or(".")
                        .trim_end_matches('/')
                        .to_owned();
                    (id.clone(), path)
                })
                .collect(),
        )
    }
}

/// Evaluate one rule instance.
///
/// The dispatch order is deliberate: policy conditions and registry evaluation
/// modes are decided before any check runs, so a rule that cannot be evaluated
/// says so through the status taxonomy rather than through a check pretending
/// to have looked.
#[must_use]
pub fn evaluate(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    if !condition_holds(rule.condition, context) {
        return Verdict {
            status: Status::Skipped,
            evidence: Some(Evidence::new(
                "condition_not_met",
                format!(
                    "the capability that enables this rule applies only when `{}`",
                    rule.condition.code()
                ),
            )),
            remediation: None,
            error: None,
        };
    }

    match rule.def.evaluation {
        Evaluation::Manual => Verdict {
            status: Status::Manual,
            evidence: Some(Evidence::new(
                "judgment_rule",
                "this rule is a judgment call; airlock reports it for a human",
            )),
            remediation: None,
            error: None,
        },
        Evaluation::Unimplemented => Verdict {
            status: Status::Unimplemented,
            evidence: Some(Evidence::new(
                "not_implemented",
                "this rule is registered but airlock does not evaluate it yet",
            )),
            remediation: Some(Remediation::new(
                "disable_or_wait",
                "Remove the rule from the policy or wait for airlock to implement it. An \
                 enabled rule airlock cannot evaluate makes the audit incomplete rather than \
                 quietly narrower.",
            )),
            error: None,
        },
        Evaluation::Mechanical => run(rule, context),
    }
}

fn condition_holds(condition: Condition, context: &AuditContext) -> bool {
    match condition {
        Condition::Always => true,
        Condition::IntentionalConfigPresent => context.has_file(".intentional/config.yml"),
    }
}

fn run(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let id = rule.def.id;
    identity::run(id, rule, context)
        .or_else(|| licensing::run(id, rule, context))
        .or_else(|| files::run(id, rule, context))
        .or_else(|| git::run(id, rule, context))
        .or_else(|| automation::run(id, rule, context))
        .or_else(|| release::run(id, rule, context))
        .or_else(|| classification::run(id, rule, context))
        .unwrap_or_else(|| {
            // A rule registered mechanical with no implementation would be a
            // silent gap, so it reports as one rather than passing.
            Verdict {
                status: Status::Unimplemented,
                evidence: Some(Evidence::new(
                    "no_implementation_registered",
                    format!("{id} is registered mechanical but has no implementation"),
                )),
                remediation: None,
                error: None,
            }
        })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A presence check over one path.
pub(crate) fn presence(context: &AuditContext, path: &str, subject: &str) -> Verdict {
    match context.snapshot.file(path) {
        FileState::Content { .. } => {
            Verdict::pass_at("file_present", path, format!("{subject} is present"))
        }
        FileState::Missing => Verdict::fail_at(
            "file_missing",
            path,
            format!("{subject} is absent"),
            Remediation::new("add_file", format!("Add {path}.")),
        ),
        FileState::Symlink { target } => Verdict::fail_at(
            "file_is_a_symlink",
            path,
            format!("{path} is a symlink to `{target}` rather than a file"),
            Remediation::new("replace_symlink", format!("Make {path} a regular file.")),
        ),
        FileState::NotAFile { kind, mode } => Verdict::fail_at(
            "path_is_not_a_file",
            path,
            format!("{path} is a {kind:?} (mode {mode}) rather than a file"),
            Remediation::new("replace_entry", format!("Make {path} a regular file.")),
        ),
        FileState::OverBudget { size, limit } => Verdict::inconclusive(
            "file_over_budget",
            format!("{path} is {size} bytes, over the {limit} byte limit, so it was not read"),
        ),
        FileState::Unreadable(error) => Verdict::from_api_error(error),
    }
}

/// The declared repository settings file, or the verdict explaining why not.
pub(crate) fn repo_settings(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
    match context.yaml(".github/repo-settings.yml") {
        ParsedFile::Parsed(document) => Ok(document),
        ParsedFile::Undecided(verdict) => Err(verdict),
        ParsedFile::Missing => Err(Box::new(Verdict::fail_at(
            "file_missing",
            ".github/repo-settings.yml",
            "the declared settings file is absent, so nothing is declared",
            Remediation::new(
                "add_file",
                "Add .github/repo-settings.yml declaring the repository's metadata.",
            ),
        ))),
        ParsedFile::NotAFile(_) => Err(Box::new(Verdict::fail_at(
            "path_is_not_a_file",
            ".github/repo-settings.yml",
            "the declared settings path is not a regular file",
            Remediation::new(
                "replace_entry",
                "Make .github/repo-settings.yml a regular file.",
            ),
        ))),
    }
}

/// The declared topics, as strings.
pub(crate) fn declared_topics(settings: &Yaml) -> Option<Vec<String>> {
    Some(
        settings
            .get("topics")?
            .as_seq()?
            .iter()
            .filter_map(|topic| topic.as_str().map(ToOwned::to_owned))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Builders for check tests.

    use super::*;
    use crate::github::{EntryKind, Repository, Tree, TreeEntry};
    use crate::registry;
    use std::collections::BTreeMap;

    /// Build a snapshot from `(path, content)` pairs.
    pub fn snapshot(files: &[(&str, &str)]) -> RepoSnapshot {
        let mut entries = Vec::new();
        let mut states = BTreeMap::new();
        for (path, content) in files {
            entries.push(TreeEntry {
                path: (*path).to_owned(),
                kind: EntryKind::Blob,
                mode: "100644".to_owned(),
                sha: format!("{:x}", path.len()),
                size: Some(content.len() as u64),
            });
            states.insert(
                (*path).to_owned(),
                FileState::Content {
                    sha: format!("{:x}", path.len()),
                    bytes: content.as_bytes().to_vec(),
                },
            );
        }
        RepoSnapshot {
            repository: repository(),
            topics: Ok(Vec::new()),
            commit: "c".repeat(40),
            tree: Tree {
                entries,
                truncated: false,
            },
            files: states,
            bytes_read: 0,
            limits: Limits::default(),
        }
    }

    /// A plain conformant-looking repository record.
    pub fn repository() -> Repository {
        Repository {
            full_name: "owner/name".to_owned(),
            id: 1,
            owner: "owner".to_owned(),
            name: "name".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "public".to_owned(),
            description: Some("A thing.".to_owned()),
            license_spdx: Some("Apache-2.0".to_owned()),
            allow_merge_commit: false,
            allow_squash_merge: true,
            allow_rebase_merge: true,
            delete_branch_on_merge: true,
            has_wiki: false,
            has_projects: false,
            has_discussions: false,
            has_issues: true,
            observed_at: None,
        }
    }

    /// Parse the workflows out of a snapshot's files.
    pub fn workflows(snapshot: &RepoSnapshot) -> Vec<Workflow> {
        snapshot
            .files
            .iter()
            .filter(|(path, _)| path.starts_with(".github/workflows/"))
            .map(|(path, state)| {
                let text = state.text().unwrap_or_default().to_owned();
                let parsed = yaml::parse_mapping(&text, Limits::default().yaml);
                Workflow {
                    path: path.clone(),
                    name: path.rsplit('/').next().unwrap_or(path).to_owned(),
                    text,
                    document: parsed.as_ref().ok().cloned(),
                    parse_error: parsed.err().map(|error| error.to_string()),
                }
            })
            .collect()
    }

    /// A policy enabling every section, so any rule can be exercised.
    pub fn policy() -> ResolvedPolicy {
        ResolvedPolicy {
            name: "test".to_owned(),
            source: "./policy.yml".to_owned(),
            commit: None,
            bundle_digest: "sha256:0".to_owned(),
            sources: Vec::new(),
            gate: crate::findings::Gate::Blocking,
            rules: Vec::new(),
            suppressions: Default::default(),
            reference_data: BTreeMap::new(),
        }
    }

    /// A rule instance for `id` at its registered severity.
    pub fn rule(id: &str) -> RuleInstance {
        let def = registry::find(id).expect("the rule is registered");
        RuleInstance {
            def,
            severity: def.severity,
            params: BTreeMap::new(),
            provenance: "test".to_owned(),
            condition: Condition::Always,
        }
    }

    /// A rule instance with parameters.
    pub fn rule_with(id: &str, params: &[(&str, serde_json::Value)]) -> RuleInstance {
        let mut rule = rule(id);
        rule.params = params
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect();
        rule
    }

    /// Build a context over a snapshot and a policy.
    pub fn context<'a>(
        snapshot: &'a RepoSnapshot,
        policy: &'a ResolvedPolicy,
        workflows: Vec<Workflow>,
    ) -> AuditContext<'a> {
        AuditContext {
            snapshot,
            policy,
            limits: Limits::default(),
            workflows,
            workflows_truncated: false,
            tags: Ok(Vec::new()),
            history: Ok((Vec::new(), false)),
            rulesets: Ok(Vec::new()),
            branch_rules: Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn a_judgment_rule_reports_manual_without_running_anything() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-README-01"), &context);
        assert_eq!(verdict.status, Status::Manual);
    }

    #[test]
    fn an_unimplemented_rule_reports_unimplemented() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-DOCS-05"), &context);
        assert_eq!(verdict.status, Status::Unimplemented);
    }

    #[test]
    fn a_rule_whose_condition_is_unmet_is_skipped() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let mut instance = rule("REPO-REL-01");
        instance.condition = Condition::IntentionalConfigPresent;
        assert_eq!(evaluate(&instance, &context).status, Status::Skipped);
    }

    #[test]
    fn a_condition_that_holds_lets_the_check_run() {
        let snapshot = snapshot(&[(
            ".intentional/config.yml",
            "release-units:\n  main:\n    path: .\n",
        )]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let mut instance = rule("REPO-REL-01");
        instance.condition = Condition::IntentionalConfigPresent;
        assert_eq!(evaluate(&instance, &context).status, Status::Pass);
    }

    #[test]
    fn every_mechanical_rule_has_an_implementation() {
        // A mechanical rule with no arm in the dispatcher would silently
        // report unimplemented forever. Catch it here instead.
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        for def in crate::registry::CHECKS {
            if def.evaluation != Evaluation::Mechanical {
                continue;
            }
            let verdict = evaluate(&rule(def.id), &context);
            assert!(
                verdict
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.code != "no_implementation_registered")
                    .unwrap_or(true),
                "{} has no implementation",
                def.id
            );
        }
    }

    #[test]
    fn workflow_triggers_are_read_whatever_shape_on_takes() {
        let snapshot = snapshot(&[
            (".github/workflows/a.yml", "on: push\njobs: {}\n"),
            (
                ".github/workflows/b.yml",
                "on: [push, pull_request]\njobs: {}\n",
            ),
            (
                ".github/workflows/c.yml",
                "on:\n  pull_request:\n  push:\n    branches: [main]\njobs: {}\n",
            ),
        ]);
        let parsed = workflows(&snapshot);
        for workflow in &parsed {
            assert!(workflow.has_trigger("push"), "{}", workflow.name);
        }
        assert!(parsed
            .iter()
            .find(|workflow| workflow.name == "c.yml")
            .unwrap()
            .pushes_to("main"));
    }
}
