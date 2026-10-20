//! The checks.
//!
//! A check turns one rule instance and one repository snapshot into one
//! verdict. Checks never fetch: everything they read was gathered into the
//! snapshot at a single resolved commit, so a verdict describes a repository
//! state that existed.
//!
//! Only the compiled check decides Met or Gap. Exhausted read budgets are run
//! errors. A declared unbuilt boundary stays visible without claiming an
//! outcome. Absence of evidence never establishes Met.

macro_rules! try_verdict {
    ($expression:expr) => {
        match $expression {
            Ok(value) => value,
            Err(verdict) => return *verdict,
        }
    };
}

mod automation;
mod classification;
mod files;
mod git;
mod identity;
mod licensing;
mod readme;
mod release;
mod release_record;
mod template_identity;

use crate::findings::{Evidence, FindingError, Fix, Status};
use crate::github::{
    ApiError, BranchRule, CommitSummary, Paged, Repository, Ruleset, TagRef, MESSAGE_HINTS_VERSION,
};
use crate::limits::Limits;
use crate::policy::{EffectiveRule, ResolvedPolicy};
use crate::rules::{CredentialCapability, DisclosureGate, RuleDefinition};
use crate::snapshot::{FileState, RepoSnapshot};
use crate::yaml::{self, Yaml};
use crate::FixGroup;

pub(crate) struct MergeSetting {
    pub(crate) declared: &'static str,
    pub(crate) expected: bool,
}

impl MergeSetting {
    pub(crate) fn live(&self, repository: &Repository) -> Option<bool> {
        match self.declared {
            "squash" => repository.allow_squash_merge,
            "rebase" => repository.allow_rebase_merge,
            "merge_commit" => repository.allow_merge_commit,
            "delete_branch_on_merge" => repository.delete_branch_on_merge,
            _ => unreachable!("merge settings are declared in MERGE_SETTINGS"),
        }
    }
}

pub(crate) const MERGE_SETTINGS: &[MergeSetting] = &[
    MergeSetting {
        declared: "squash",
        expected: true,
    },
    MergeSetting {
        declared: "rebase",
        expected: true,
    },
    MergeSetting {
        declared: "merge_commit",
        expected: false,
    },
    MergeSetting {
        declared: "delete_branch_on_merge",
        expected: true,
    },
];

pub(crate) fn merge_setting(declared: &str) -> &'static MergeSetting {
    MERGE_SETTINGS
        .iter()
        .find(|setting| setting.declared == declared)
        .expect("named merge setting is declared")
}

/// What one check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The status.
    pub status: Option<Status>,
    /// What was observed.
    pub evidence: Option<Evidence>,
    /// What to do about it.
    pub fix: Option<Fix>,
    /// What stopped the evaluation.
    pub error: Option<FindingError>,
    pub routing: Option<crate::findings::Routing>,
}

impl Verdict {
    pub fn out_of_scope() -> Self {
        Self {
            status: None,
            evidence: Some(Evidence::new(
                "no_release_units_declared",
                "The repository declares no release units",
            )),
            fix: None,
            error: None,
            routing: Some(crate::findings::Routing {
                reason: "out-of-scope".to_owned(),
                settling_surface: "An audit of a repository with declared release units".to_owned(),
            }),
        }
    }

    pub fn needs_repository_owner() -> Self {
        Self {
            status: None,
            evidence: Some(Evidence::new(
                "repository_owner_unobserved",
                "The repository owner is needed to resolve the preset",
            )),
            fix: None,
            error: None,
            routing: Some(crate::findings::Routing {
                reason: "needs-repository-owner".to_owned(),
                settling_surface: "An audit with an observed GitHub repository owner".to_owned(),
            }),
        }
    }

    pub fn needs_github_api() -> Self {
        Self {
            status: None,
            evidence: None,
            fix: None,
            error: None,
            routing: Some(crate::findings::Routing {
                reason: "needs-github-api".to_owned(),
                settling_surface: "Credentialed API-tree audit or Action".to_owned(),
            }),
        }
    }

    /// The assertion holds.
    #[must_use]
    pub fn pass(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Some(Status::Met),
            evidence: Some(Evidence::new(code, detail)),
            fix: None,
            error: None,
            routing: None,
        }
    }

    /// The assertion holds, and the evidence is about one path.
    #[must_use]
    pub fn pass_at(code: &str, path: &str, detail: impl Into<String>) -> Self {
        Self {
            status: Some(Status::Met),
            evidence: Some(Evidence::at(code, path, detail)),
            fix: None,
            error: None,
            routing: None,
        }
    }

    /// The assertion does not hold.
    #[must_use]
    pub fn fail(code: &str, detail: impl Into<String>, fix: Fix) -> Self {
        Self {
            status: Some(Status::Gap),
            evidence: Some(Evidence::new(code, detail)),
            fix: Some(fix),
            error: None,
            routing: None,
        }
    }

    /// The assertion does not hold, and the evidence is about one path.
    #[must_use]
    pub fn fail_at(code: &str, path: &str, detail: impl Into<String>, fix: Fix) -> Self {
        Self {
            status: Some(Status::Gap),
            evidence: Some(Evidence::at(code, path, detail)),
            fix: Some(fix),
            error: None,
            routing: None,
        }
    }

    /// This repository reaches the check's declared unbuilt boundary.
    #[must_use]
    pub fn unbuilt(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: None,
            evidence: Some(Evidence::new(code, detail)),
            fix: None,
            error: None,
            routing: Some(crate::findings::Routing {
                reason: "unbuilt".to_owned(),
                settling_surface: "A release of Airlock with this compiled check implemented"
                    .to_owned(),
            }),
        }
    }

    /// The assertion could not be decided within a budget.
    #[must_use]
    pub fn run_error(code: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            status: None,
            evidence: Some(Evidence::new(code, &detail)),
            fix: None,
            error: Some(FindingError {
                cause: code.to_owned(),
                endpoint: "audit-input".to_owned(),
                status: None,
                message: Some(detail),
                documentation_url: None,
                accepted_permissions: None,
                request_id: None,
                message_hints_version: MESSAGE_HINTS_VERSION,
            }),
            routing: None,
        }
    }

    /// The gate the rule declares withheld the fact.
    ///
    /// A structurally undecided verdict cannot be written without a
    /// [`DisclosureGate`] in hand, so no check can privately decide that its
    /// missing input was permanently out of reach. Both the evidence code and
    /// the detail come from the declaration; nothing about which rules are
    /// gated, or why, lives here.
    #[must_use]
    pub fn withheld(gate: &DisclosureGate, subject: &str) -> Self {
        Self {
            status: None,
            routing: Some(crate::findings::Routing {
                reason: gate.evidence_code.to_owned(),
                settling_surface: gate.verified_by.code().to_owned(),
            }),
            evidence: Some(Evidence::new(
                gate.evidence_code,
                format!(
                    "{subject} was not disclosed to this credential: {}",
                    gate.rationale()
                ),
            )),
            fix: None,
            error: None,
        }
    }

    /// An API failure prevented the evaluation.
    #[must_use]
    pub fn from_api_error(error: &ApiError) -> Self {
        let fix = match error.cause {
            crate::github::ErrorCause::Permission => Some(Fix::new(
                FixGroup::GRANT_PERMISSION,
                match &error.accepted_permissions {
                    Some(permissions) => format!(
                        "The credential lacks the permission {permissions} that {} requires.",
                        error.endpoint
                    ),
                    None => format!("The credential cannot read {}.", error.endpoint),
                },
            )),
            crate::github::ErrorCause::PlanLimitation => Some(Fix::new(
                FixGroup::PLAN_GATE,
                format!(
                    "{} is gated by the account's GitHub plan, so airlock cannot read it.",
                    error.endpoint
                ),
            )),
            _ => None,
        };
        Self {
            status: None,
            evidence: None,
            fix,
            routing: None,
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
    ///
    /// Fallible because `on: [push, 3]` is a workflow airlock cannot read, and
    /// reporting one trigger fewer would let "no workflow uses
    /// `pull_request_target`" pass over a trigger list it never understood.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive verdict when the trigger block is not a shape
    /// airlock can read.
    pub fn triggers(&self) -> Result<Vec<String>, Box<Verdict>> {
        let Some(document) = &self.document else {
            return Ok(Vec::new());
        };
        match document.get("on") {
            Some(Yaml::String(name)) => Ok(vec![name.clone()]),
            Some(value @ Yaml::Seq(_)) => {
                yaml_string_seq(value, &format!("the `on:` list in {}", self.path))
            }
            Some(Yaml::Map(entries)) => Ok(entries.iter().map(|(name, _)| name.clone()).collect()),
            None => Ok(Vec::new()),
            Some(other) => Err(Box::new(Verdict::run_error(
                MALFORMED_DECLARATION,
                format!("`on:` in {} is a {}", self.path, other.kind()),
            ))),
        }
    }

    /// The configuration under one trigger, when `on:` is a mapping.
    #[must_use]
    pub fn trigger(&self, name: &str) -> Option<&Yaml> {
        self.document.as_ref()?.get("on")?.get(name)
    }

    /// Whether the workflow declares a trigger.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive verdict when the trigger block is unreadable.
    pub fn has_trigger(&self, name: &str) -> Result<bool, Box<Verdict>> {
        Ok(self.triggers()?.iter().any(|trigger| trigger == name))
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
    ///
    /// # Errors
    ///
    /// Returns an inconclusive verdict when the branch filter is unreadable.
    pub fn pushes_to(&self, branch: &str) -> Result<bool, Box<Verdict>> {
        let Some(push) = self.trigger("push") else {
            return Ok(false);
        };
        match yaml_strings(
            push,
            "branches",
            &format!("the push branches in {}", self.path),
        )? {
            Some(branches) => Ok(branches.iter().any(|name| name == branch || name == "**")),
            // `on: push:` with no branch filter covers every branch.
            None => Ok(push.get("tags").is_none()),
        }
    }
}

/// Everything one audit run gathered, ready for the checks to read.
#[derive(Clone)]
pub struct AuditContext<'a> {
    /// Observed from committed Git evidence; never from mutable local files.
    pub maturity: Result<crate::maturity::Observed, crate::maturity::ObservationError>,
    /// Captured template revisions and ancestry comparisons.
    pub template_revisions: Result<Vec<crate::template_identity::TemplateRevision>, ApiError>,
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
    /// The repository's tags, and whether the listing was complete.
    pub tags: Result<Paged<TagRef>, ApiError>,
    /// Captured release records and matching annotated tag objects.
    pub release_records: Result<crate::release_records::ReleaseInputs, ApiError>,
    /// Default-branch history, and whether the walk stopped at a budget.
    pub history: Result<Paged<CommitSummary>, ApiError>,
    /// Rulesets covering the repository, including inherited ones.
    pub rulesets: Result<Paged<Ruleset>, ApiError>,
    /// The effective rules on the default branch.
    pub branch_rules: Result<Paged<BranchRule>, ApiError>,
    /// What the credential this run presented was enumerated to be able to do.
    ///
    /// A check never sees the credential; it sees what the credential can do,
    /// which is all that decides whether a declared disclosure gate explains an
    /// absent field.
    pub credential: CredentialCapability,
}

/// What airlock knows about a YAML file it wanted to read.
pub enum ParsedFile<'a> {
    /// Nothing is at that path.
    Missing,
    /// The file was read and parsed.
    Parsed(Yaml),
    /// The file could not be read or parsed, with the evidence saying why.
    ReadError(Box<Verdict>),
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
        snapshot_yaml(self.snapshot, path, self.limits)
    }

    /// The workflow at `.github/workflows/{name}`.
    #[must_use]
    pub fn workflow(&self, name: &str) -> Option<&Workflow> {
        self.workflows.iter().find(|workflow| workflow.name == name)
    }

    /// Release unit paths, or the declared scope boundary when none are present.
    /// Malformed or unreadable declarations remain run errors.
    pub fn release_units(&self) -> Result<Vec<(String, String)>, Box<Verdict>> {
        release_units(self.snapshot)
    }
}

/// Shared release-unit scope for input gathering and evaluation.
pub(crate) fn release_units(
    snapshot: &RepoSnapshot,
) -> Result<Vec<(String, String)>, Box<Verdict>> {
    let document = match snapshot_yaml(snapshot, ".intentional/config.yml", snapshot.limits) {
        ParsedFile::Missing | ParsedFile::NotAFile(_) => {
            return Err(Box::new(Verdict::out_of_scope()))
        }
        ParsedFile::ReadError(error) => return Err(error),
        ParsedFile::Parsed(document) => document,
    };
    let Some(declared) = document.get("release-units") else {
        return Err(Box::new(Verdict::out_of_scope()));
    };
    let Some(units) = declared.as_map() else {
        return Err(Box::new(Verdict::run_error(
            MALFORMED_DECLARATION,
            "`release-units` must be a mapping",
        )));
    };
    if units.is_empty() {
        return Err(Box::new(Verdict::out_of_scope()));
    }
    Ok(units
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
        .collect())
}

fn snapshot_yaml<'a>(snapshot: &'a RepoSnapshot, path: &str, limits: Limits) -> ParsedFile<'a> {
    let state = snapshot.file(path);
    match state {
        FileState::Missing => ParsedFile::Missing,
        FileState::TreeTruncated => ParsedFile::ReadError(Box::new(Verdict::run_error(
            "tree_truncated",
            snapshot.truncation_detail(&format!("whether {path} exists")),
        ))),
        FileState::Content { .. } => {
            let text = state.text().unwrap_or_default();
            match yaml::parse_mapping(text, limits.yaml) {
                Ok(document) => ParsedFile::Parsed(document),
                Err(error) => ParsedFile::ReadError(Box::new(Verdict::run_error(
                    "unparseable_yaml",
                    format!("{path} could not be parsed: {error}"),
                ))),
            }
        }
        FileState::OverBudget { size, limit } => {
            ParsedFile::ReadError(Box::new(Verdict::run_error(
                "file_over_budget",
                format!("{path} is {size} bytes, over the {limit} byte limit, so it was not read"),
            )))
        }
        FileState::Unreadable(error) => {
            ParsedFile::ReadError(Box::new(Verdict::from_api_error(error)))
        }
        FileState::LocalUnreadable { detail } => ParsedFile::ReadError(Box::new(
            Verdict::run_error("local_path_unreadable", detail.clone()),
        )),
        FileState::Symlink { .. } | FileState::NotAFile { .. } => ParsedFile::NotAFile(state),
    }
}

/// Evaluate the compiled check. Every non-outcome requires a declared gate;
/// an undeclared boundary is a run error.
#[must_use]
pub fn evaluate(rule: &EffectiveRule, context: &AuditContext) -> Verdict {
    if let Err(verdict) = applicability(rule, context) {
        return *verdict;
    }
    let mut verdict = run(rule, context);
    if let Some(route) = &verdict.routing {
        let declared = match route.reason.as_str() {
            "unbuilt" => rule.def.unbuilt_reason().is_some(),
            "out-of-scope" => rule.def.needs_release_units(),
            "needs-repository-owner" => rule.def.needs_repository_owner(),
            reason => rule
                .def
                .disclosure_gate()
                .is_some_and(|gate| gate.evidence_code == reason),
        };
        if !declared {
            verdict = Verdict::run_error(
                "undeclared_gate",
                "The check reached a gate its compiled rule does not declare",
            );
        }
    }
    verdict
}

/// Whether the captured API source or credential leaves this rule routed.
/// File scope and maturity are settled separately before this gate.
pub(crate) fn api_gated(
    rule: &EffectiveRule,
    credential: CredentialCapability,
    api_observed: bool,
) -> bool {
    rule.def.needs_github_api()
        && (!api_observed
            || (rule.def.id == "REPO-TPL-01"
                && credential == CredentialCapability::Unauthenticated))
}

/// Shared scope boundary for evaluation and API routing. Classification/config
/// selection remains outside this function.
pub fn applicability(rule: &EffectiveRule, context: &AuditContext) -> Result<(), Box<Verdict>> {
    if let Ok(maturity) = &context.maturity {
        if !rule.def.lifecycle.governs(maturity.rung) {
            return Err(Box::new(Verdict {
                status: None,
                evidence: Some(Evidence::new(
                    "maturity_out_of_scope",
                    format!(
                        "Observed {}; this rule applies from {}",
                        maturity.rung.code(),
                        rule.def.lifecycle.code(),
                    ),
                )),
                fix: None,
                error: None,
                routing: Some(crate::findings::Routing {
                    reason: "out-of-scope".to_owned(),
                    settling_surface: format!(
                        "An audit at the {} rung or above",
                        rule.def.lifecycle.code()
                    ),
                }),
            }));
        }
    }
    // File-only rules can reach this boundary only in a comparison branch.
    if rule.def.needs_release_units() && rule.def.needs_github_api() {
        context.release_units()?;
    }
    if rule.def.lifecycle != crate::rules::Lifecycle::Seeded {
        context
            .maturity
            .as_ref()
            .map_err(|error| Box::new(error.verdict()))?;
    }
    Ok(())
}

fn run(rule: &EffectiveRule, context: &AuditContext) -> Verdict {
    let id = rule.def.id;
    (id == "REPO-TPL-01")
        .then(|| template_identity::run(rule, context))
        .or_else(|| identity::run(id, rule, context))
        .or_else(|| licensing::run(id, rule, context))
        .or_else(|| files::run(id, rule, context))
        .or_else(|| readme::run(id, rule, context))
        .or_else(|| git::run(id, rule, context))
        .or_else(|| automation::run(id, rule, context))
        .or_else(|| release::run(id, rule, context))
        .or_else(|| (id == "REPO-REL-08").then(|| release_record::run(context)))
        .or_else(|| classification::run(id, rule, context))
        .unwrap_or_else(|| {
            if let Some(reason) = rule.def.unbuilt_reason() {
                Verdict::unbuilt("unbuilt", reason)
            } else {
                Verdict::run_error(
                    "no_implementation_registered",
                    format!("{id} declares no unbuilt gate and has no check"),
                )
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
        FileState::TreeTruncated => Verdict::run_error(
            "tree_truncated",
            format!(
                "GitHub truncated the tree at {}, so whether {path} exists was never \
                 established",
                context.snapshot.commit
            ),
        ),
        FileState::Missing => Verdict::fail_at(
            "file_missing",
            path,
            format!("{subject} is absent"),
            Fix::new(FixGroup::ADD_FILE, format!("Add {path}.")),
        ),
        FileState::Symlink { target } => Verdict::fail_at(
            "file_is_a_symlink",
            path,
            format!("{path} is a symlink to `{target}` rather than a file"),
            Fix::new(
                FixGroup::REPLACE_SYMLINK,
                format!("Make {path} a regular file."),
            ),
        ),
        FileState::NotAFile { kind, mode } => Verdict::fail_at(
            "path_is_not_a_file",
            path,
            format!("{path} is a {kind:?} (mode {mode}) rather than a file"),
            Fix::new(
                FixGroup::REPLACE_ENTRY,
                format!("Make {path} a regular file."),
            ),
        ),
        FileState::OverBudget { size, limit } => Verdict::run_error(
            "file_over_budget",
            format!("{path} is {size} bytes, over the {limit} byte limit, so it was not read"),
        ),
        FileState::Unreadable(error) => Verdict::from_api_error(error),
        FileState::LocalUnreadable { detail } => {
            Verdict::run_error("local_path_unreadable", detail.clone())
        }
    }
}

/// The declared repository settings file, or the verdict explaining why not.
pub(crate) fn repo_settings(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
    match context.yaml(".github/airlock.yml") {
        ParsedFile::Parsed(document) => Ok(document),
        ParsedFile::ReadError(verdict) => Err(verdict),
        ParsedFile::Missing => Err(Box::new(Verdict::fail_at(
            "file_missing",
            ".github/airlock.yml",
            "the declared settings file is absent, so nothing is declared",
            Fix::new(
                FixGroup::ADD_FILE,
                "Add .github/airlock.yml declaring the repository's metadata.",
            ),
        ))),
        ParsedFile::NotAFile(_) => Err(Box::new(Verdict::fail_at(
            "path_is_not_a_file",
            ".github/airlock.yml",
            "the declared settings path is not a regular file",
            Fix::new(
                FixGroup::REPLACE_ENTRY,
                "Make .github/airlock.yml a regular file.",
            ),
        ))),
    }
}

/// The stable evidence code for a declaration airlock could read but not
/// understand.
pub(crate) const MALFORMED_DECLARATION: &str = "malformed_declaration";

/// The verdict for a field the credential did not disclose.
///
/// The check reports the observation — "the platform did not give me this
/// field" — and the rules decide what that means. A rule the rules
/// declares gated is structurally undecided: no retry on this surface can
/// answer it, and the declaration names the surface that can. A rule with no
/// declaration is a run that fell short of what it can normally do, so it stays
/// circumstantially undecided and keeps blocking. A check cannot promote itself
/// out of that by knowing something the rules do not.
pub(crate) fn undisclosed(def: &RuleDefinition, context: &AuditContext, subject: &str) -> Verdict {
    match def.disclosure_gate() {
        Some(gate) if gate.withholds_from(context.credential) => Verdict::withheld(gate, subject),
        // Either the rule declares no gate, or it declares one this run's
        // credential could have satisfied. Both mean the same thing: the field
        // should have been there and was not, which is a run that fell short.
        _ => Verdict::run_error(
            "field_undisclosed",
            format!(
                "{subject} was not disclosed to this credential ({}), and no declared \
                 disclosure gate explains it, so this run did not establish it",
                context.credential.code()
            ),
        ),
    }
}

/// Collect a sequence of strings, refusing one that is not entirely strings.
///
/// This is the audited-repository counterpart of the GitHub client's strict
/// decoders, and it exists for the same reason: an entry airlock cannot read
/// must never become one fewer item. `topics: [cli, 42, rust]` silently
/// yielding two topics is how a rule counts wrong, and how a topic is never
/// compared against the vocabulary that would have rejected it.
fn collect_strings<'a>(
    entries: impl IntoIterator<Item = (usize, Option<&'a str>)>,
    subject: &str,
) -> Result<Vec<String>, Box<Verdict>> {
    let mut values = Vec::new();
    for (index, entry) in entries {
        match entry {
            Some(value) => values.push(value.to_owned()),
            None => {
                return Err(Box::new(Verdict::run_error(
                    MALFORMED_DECLARATION,
                    format!(
                        "entry {} of {subject} is not a string, so the declaration could not be \
                         read",
                        index + 1
                    ),
                )))
            }
        }
    }
    Ok(values)
}

/// A sequence of strings under `key` in a YAML document.
///
/// `Ok(None)` means the key is absent, which is a different answer from an
/// empty or unreadable list.
pub(crate) fn yaml_strings(
    container: &Yaml,
    key: &str,
    subject: &str,
) -> Result<Option<Vec<String>>, Box<Verdict>> {
    let Some(value) = container.get(key) else {
        return Ok(None);
    };
    yaml_string_seq(value, subject).map(Some)
}

/// A YAML value that must be a sequence of strings.
pub(crate) fn yaml_string_seq(value: &Yaml, subject: &str) -> Result<Vec<String>, Box<Verdict>> {
    let Some(entries) = value.as_seq() else {
        return Err(Box::new(Verdict::run_error(
            MALFORMED_DECLARATION,
            format!("{subject} is a {} rather than a list", value.kind()),
        )));
    };
    collect_strings(
        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (index, entry.as_str())),
        subject,
    )
}

/// A sequence of strings under `key` in a JSON document.
pub(crate) fn json_strings(
    container: &serde_json::Value,
    key: &str,
    subject: &str,
) -> Result<Option<Vec<String>>, Box<Verdict>> {
    let Some(value) = container.get(key) else {
        return Ok(None);
    };
    let Some(entries) = value.as_array() else {
        return Err(Box::new(Verdict::run_error(
            MALFORMED_DECLARATION,
            format!("{subject} is not a list"),
        )));
    };
    collect_strings(
        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (index, entry.as_str())),
        subject,
    )
    .map(Some)
}

/// The declared topics, as strings.
///
/// `Ok(None)` means no `topics` key at all.
pub(crate) fn declared_topics(settings: &Yaml) -> Result<Option<Vec<String>>, Box<Verdict>> {
    yaml_strings(settings, "topics", "`topics` in .github/airlock.yml")
}

pub(crate) fn workflow_signals<'a>(text: &str, signals: &'a [&'a str]) -> Vec<&'a str> {
    signals
        .iter()
        .copied()
        .filter(|signal| text.contains(signal))
        .collect()
}

fn workflows_with_trigger<'a>(
    workflows: &[&'a Workflow],
    trigger: &str,
) -> Result<Vec<&'a Workflow>, Box<Verdict>> {
    let mut matching = Vec::new();
    for workflow in workflows {
        if workflow.has_trigger(trigger)? {
            matching.push(*workflow);
        }
    }
    Ok(matching)
}

fn first_workflow_with_trigger<'a>(
    workflows: &[&'a Workflow],
    trigger: &str,
) -> Result<Option<&'a Workflow>, Box<Verdict>> {
    for workflow in workflows {
        if workflow.has_trigger(trigger)? {
            return Ok(Some(*workflow));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Builders for check tests.

    use super::*;
    use crate::github::{EntryKind, Repository, Tree, TreeEntry};
    use crate::rules;
    use std::collections::BTreeMap;

    /// Owned inputs for repeatedly evaluating checks in one test.
    pub struct CheckFixture {
        pub snapshot: RepoSnapshot,
        policy: ResolvedPolicy,
    }

    impl CheckFixture {
        pub fn new(files: &[(&str, &str)]) -> Self {
            Self {
                snapshot: snapshot(files),
                policy: policy(),
            }
        }

        pub fn context(&self) -> AuditContext<'_> {
            context(&self.snapshot, &self.policy, workflows(&self.snapshot))
        }

        pub fn verdict(&self, id: &str) -> Verdict {
            evaluate(&rule(id), &self.context())
        }
    }

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
            allow_merge_commit: Some(false),
            allow_squash_merge: Some(true),
            allow_rebase_merge: Some(true),
            delete_branch_on_merge: Some(true),
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
            rules: Vec::new(),
            suppressions: Default::default(),

            accepted_version: crate::policy::current_generation(),
            exceptions: Default::default(),
        }
    }

    /// A rule instance for `id` at its registered severity.
    pub fn rule(id: &str) -> EffectiveRule {
        let def = rules::find(id).expect("the rule is registered");
        EffectiveRule {
            def,
            severity: def.severity,
            params: BTreeMap::new(),
            provenance: "test".to_owned(),
        }
    }

    /// A rule instance with parameters.
    pub fn rule_with(id: &str, params: &[(&str, serde_json::Value)]) -> EffectiveRule {
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
            maturity: Ok(crate::maturity::Observed {
                rung: crate::rules::Lifecycle::Released,
                baseline_tags: vec!["baseline".into()],
                release_tags: vec!["release".into()],
            }),
            template_revisions: Ok(Vec::new()),
            snapshot,
            policy,
            limits: Limits::default(),
            workflows,
            workflows_truncated: false,
            release_records: Ok(crate::release_records::ReleaseInputs::default()),
            tags: Ok(Paged::complete(Vec::new())),
            history: Ok(Paged::complete(Vec::new())),
            rulesets: Ok(Paged::complete(Vec::new())),
            branch_rules: Ok(Paged::complete(Vec::new())),
            // The audit surface: a credential enumerated and proved read-only
            // before first use.
            credential: CredentialCapability::ReadOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn api_gate_preserves_public_observation_and_template_credentials() {
        for (id, credential, observed, expected) in [
            ("REPO-REL-08", CredentialCapability::ReadOnly, false, true),
            (
                "REPO-REL-08",
                CredentialCapability::Unauthenticated,
                true,
                false,
            ),
            ("REPO-TPL-01", CredentialCapability::ReadOnly, true, false),
            (
                "REPO-TPL-01",
                CredentialCapability::Unauthenticated,
                true,
                true,
            ),
            (
                "REPO-FILE-01",
                CredentialCapability::Unauthenticated,
                false,
                false,
            ),
        ] {
            assert_eq!(api_gated(&rule(id), credential, observed), expected, "{id}");
        }
    }

    #[test]
    fn seeded_rules_report_later_rungs_as_out_of_scope_without_outcomes() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units: {sample: {path: .}}",
        )]);
        let mut context = fixture.context();
        context.maturity.as_mut().unwrap().rung = crate::rules::Lifecycle::Seeded;
        for id in ["REPO-TPL-01", "REPO-REL-08"] {
            let verdict = evaluate(&rule(id), &context);
            assert!(verdict.status.is_none(), "{id}");
            assert!(verdict.error.is_none(), "{id}");
            assert_eq!(verdict.routing.unwrap().reason, "out-of-scope", "{id}");
        }
        let seeded = evaluate(&rule("REPO-GIT-15"), &context);
        assert_eq!(seeded.status, Some(Status::Gap));
        assert!(seeded
            .fix
            .unwrap()
            .detail
            .contains("intentional tag --baseline"));
    }

    #[test]
    fn building_applies_template_identity_but_not_release_records() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units: {sample: {path: .}}",
        )]);
        let mut context = fixture.context();
        context.maturity.as_mut().unwrap().rung = crate::rules::Lifecycle::Building;
        assert!(applicability(&rule("REPO-TPL-01"), &context).is_ok());
        assert_eq!(
            applicability(&rule("REPO-REL-08"), &context)
                .unwrap_err()
                .routing
                .unwrap()
                .reason,
            "out-of-scope"
        );
        assert_eq!(
            evaluate(&rule("REPO-GIT-15"), &context).status,
            Some(Status::Met)
        );
    }

    #[test]
    fn unobserved_maturity_does_not_guess_or_block_independent_seeded_checks() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units: {sample: {path: .}}",
        )]);
        let mut context = fixture.context();
        context.maturity = Err("history was truncated".into());
        assert_eq!(
            evaluate(&rule("REPO-REL-08"), &context)
                .error
                .unwrap()
                .cause,
            "maturity_unobserved"
        );
        assert_eq!(
            evaluate(&rule("REPO-GIT-01"), &context).status,
            Some(Status::Met)
        );
    }

    #[test]
    fn release_unit_scope_is_one_case_of_the_shared_applicability_boundary() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.maturity = Err("not observed".into());
        let verdict = applicability(&rule("REPO-TPL-01"), &context).unwrap_err();
        assert_eq!(verdict.routing.unwrap().reason, "out-of-scope");
        assert!(verdict.error.is_none());
    }

    #[test]
    fn a_known_earlier_rung_does_not_read_later_rule_inputs() {
        let fixture = CheckFixture::new(&[(".intentional/config.yml", "release-units: [sample]")]);
        let mut context = fixture.context();
        context.maturity.as_mut().unwrap().rung = crate::rules::Lifecycle::Seeded;
        let verdict = evaluate(&rule("REPO-TPL-01"), &context);
        assert!(verdict.error.is_none());
        assert_eq!(verdict.routing.unwrap().reason, "out-of-scope");
        context.maturity.as_mut().unwrap().rung = crate::rules::Lifecycle::Building;
        assert!(evaluate(&rule("REPO-TPL-01"), &context).error.is_some());
    }

    #[test]
    fn a_withheld_field_is_structural_only_where_the_rules_declares_a_gate() {
        // The check reports one observation — the platform did not give me
        // this field — and the rules decide what it means. A rule that
        // declares a gate can only be settled with admin access, so it is
        // structural. A rule that declares no gate is a run that fell short,
        // so it stays circumstantial and keeps blocking. No check can promote
        // itself.
        let snapshot = snapshot(&[]);
        let policy = policy();
        let read_only = context(&snapshot, &policy, Vec::new());

        let declared = crate::rules::find("REPO-GIT-04").expect("registered");
        let verdict = undisclosed(declared, &read_only, "the merge-commit setting");
        assert_eq!(verdict.status, None);
        assert!(verdict.routing.is_some());
        let evidence = verdict.evidence.expect("evidence");
        assert_eq!(
            evidence.code,
            crate::rules::MERGE_SETTINGS_DISCLOSURE.evidence_code
        );
        assert!(
            evidence
                .detail
                .contains(crate::rules::Grant::CONTENTS_WRITE.code()),
            "the detail is built from the declaration: {}",
            evidence.detail
        );

        let undeclared = crate::rules::find("REPO-GIT-01").expect("registered");
        assert!(undeclared.disclosure_gate().is_none());
        let verdict = undisclosed(undeclared, &read_only, "the default branch");
        assert!(verdict.status.is_none() && verdict.routing.is_none() && verdict.error.is_some());
        assert!(verdict.routing.is_none());
        assert_eq!(
            verdict.evidence.expect("evidence").code,
            "field_undisclosed"
        );
    }

    #[test]
    fn a_credential_that_could_have_seen_the_field_is_not_excused_by_the_gate() {
        // The interactive session holds a write-capable credential, so the gate
        // does not apply to it. A field missing there is a run that fell short,
        // and it must keep blocking rather than inherit the audit surface's
        // permanent exemption.
        let snapshot = snapshot(&[]);
        let policy = policy();
        let mut write_capable = context(&snapshot, &policy, Vec::new());
        write_capable.credential = CredentialCapability::WriteCapable;

        let declared = crate::rules::find("REPO-GIT-04").expect("registered");
        let verdict = undisclosed(declared, &write_capable, "the merge-commit setting");

        assert_eq!(verdict.status, None);
        assert!(verdict.routing.is_none());
        assert!(declared.disclosure_gate().is_some_and(|gate| {
            !gate.withholds_from(CredentialCapability::WriteCapable)
                && gate.withholds_from(CredentialCapability::ReadOnly)
        }));
    }

    #[test]
    fn a_judgment_rule_reports_manual_without_running_anything() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-README-01"), &context);
        assert_eq!(verdict.status, None);
    }

    #[test]
    fn a_manual_schema_validation_rule_reports_manual() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-DOCS-05"), &context);
        assert_eq!(verdict.status, None);
    }

    #[test]
    fn release_unit_rules_run_when_units_are_declared() {
        let snapshot = snapshot(&[
            (
                ".intentional/config.yml",
                "release-units:\n  sample:\n    path: .\n",
            ),
            ("Cargo.toml", "[package]\nlicense = \"Apache-2.0\"\n"),
        ]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());

        for id in ["REPO-GIT-09", "REPO-TASK-04", "REPO-LIC-04"] {
            assert_eq!(
                evaluate(&rule(id), &context).status,
                Some(Status::Met),
                "{id}"
            );
        }
    }

    #[test]
    fn every_mechanical_rule_has_an_implementation() {
        // A mechanical rule with no arm in the dispatcher would silently
        // report unimplemented forever. Catch it here instead.
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        for def in crate::rules::RULES {
            if def.unbuilt_reason().is_some() {
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
    fn a_sequence_with_a_non_string_entry_is_malformed_not_shorter() {
        let document =
            yaml::parse_mapping("topics: [cli, 42, rust]\n", Limits::default().yaml).unwrap();
        let verdict = *declared_topics(&document).unwrap_err();
        assert_eq!(verdict.status, None);
        let evidence = verdict.evidence.unwrap();
        assert_eq!(evidence.code, MALFORMED_DECLARATION);
        assert!(evidence.detail.contains("entry 2"));
    }

    #[test]
    fn a_sequence_of_strings_is_read_whole() {
        let document =
            yaml::parse_mapping("topics: [cli, rust]\n", Limits::default().yaml).unwrap();
        assert_eq!(
            declared_topics(&document).unwrap(),
            Some(vec!["cli".to_owned(), "rust".to_owned()])
        );
    }

    #[test]
    fn an_absent_key_is_not_an_empty_list() {
        let document = yaml::parse_mapping("description: x\n", Limits::default().yaml).unwrap();
        assert_eq!(declared_topics(&document).unwrap(), None);
    }

    #[test]
    fn a_value_that_is_not_a_list_is_malformed() {
        let document = yaml::parse_mapping("topics: cli, rust\n", Limits::default().yaml).unwrap();
        let verdict = *declared_topics(&document).unwrap_err();
        assert_eq!(verdict.status, None);
        assert!(verdict
            .evidence
            .unwrap()
            .detail
            .contains("rather than a list"));
    }

    #[test]
    fn a_malformed_trigger_list_is_unreadable_rather_than_shorter() {
        let snapshot = snapshot(&[(
            ".github/workflows/x.yml",
            "on: [push, 3]\npermissions: {}\njobs: {}\n",
        )]);
        let parsed = workflows(&snapshot);
        let error = parsed[0].triggers().unwrap_err();
        assert_eq!(error.status, None);
        assert_eq!(error.evidence.unwrap().code, MALFORMED_DECLARATION);
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
            assert!(workflow.has_trigger("push").unwrap(), "{}", workflow.name);
        }
        assert!(parsed
            .iter()
            .find(|workflow| workflow.name == "c.yml")
            .unwrap()
            .pushes_to("main")
            .unwrap());
    }
}

#[cfg(test)]
mod outcome_gate_tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn an_unbuilt_boundary_requires_a_compiled_declaration() {
        let fixture = CheckFixture::new(&[(".gitignore", "target/\n")]);
        let declared = evaluate(&rule("REPO-FILE-03"), &fixture.context());
        assert_eq!(declared.routing.as_ref().unwrap().reason, "unbuilt");
        assert!(declared.status.is_none());

        // Invoke the same check through a definition with no unbuilt gate.
        let mut definition = *crate::rules::find("REPO-FILE-01").unwrap();
        definition.id = "REPO-FILE-03";
        let undeclared_rule = EffectiveRule {
            def: Box::leak(Box::new(definition)),
            ..rule("REPO-FILE-03")
        };
        let undeclared = evaluate(&undeclared_rule, &fixture.context());
        assert!(undeclared.routing.is_none());
        assert!(undeclared.status.is_none());
        assert_eq!(undeclared.error.unwrap().cause, "undeclared_gate");
    }
    #[test]
    fn an_out_of_scope_boundary_requires_a_compiled_declaration() {
        let fixture = CheckFixture::new(&[]);
        let declared = evaluate(&rule("REPO-LIC-04"), &fixture.context());
        assert_eq!(declared.routing.as_ref().unwrap().reason, "out-of-scope");
        assert!(declared.status.is_none());
        let mut definition = *crate::rules::find("REPO-FILE-01").unwrap();
        definition.id = "REPO-LIC-04";
        let undeclared_rule = EffectiveRule {
            def: Box::leak(Box::new(definition)),
            ..rule("REPO-LIC-04")
        };
        let undeclared = evaluate(&undeclared_rule, &fixture.context());
        assert!(undeclared.routing.is_none());
        assert!(undeclared.status.is_none());
        assert_eq!(undeclared.error.unwrap().cause, "undeclared_gate");
    }
}
