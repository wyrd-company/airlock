//! The audit result document.
//!
//! One audit run produces one findings document: the audited repository, the
//! resolved policy identity and digest, and one record per selected rule.
//! Decided findings, waivers, routing, unbuilt, out-of-scope, and run errors have
//! separate lists and summary counts. Every finding carries its statement and
//! severity inline, so a reader never has to look up what a bare rule
//! identifier meant.
//!
//! The JSON form is the contract; the text form is a rendering of it. Fields
//! are always present — null rather than omitted — and findings are ordered by
//! rule id, so two runs over the same inputs produce the same bytes.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{rules::RULES_VERSION, FixGroup};

/// The version of the JSON document shape.
pub const SCHEMA_VERSION: u32 = 2;

/// The result of an evaluated compiled requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Met,
    Gap,
}
impl Status {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Met => "met",
            Self::Gap => "gap",
        }
    }
    pub const ALL: &'static [Self] = &[Self::Met, Self::Gap];
}

/// A declared gate left this rule to another run or surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Routing {
    pub reason: String,
    pub settling_surface: String,
}

/// What the audit concluded overall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// The run completed with no blocking Gaps.
    Conformant,
    /// The run completed with at least one blocking Gap.
    Nonconformant,
    /// A run error prevented completion.
    Incomplete,
}

impl AuditResult {
    /// The process exit code carrying this outcome.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            AuditResult::Conformant => 0,
            AuditResult::Nonconformant => 1,
            AuditResult::Incomplete => 2,
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            AuditResult::Conformant => "conformant",
            AuditResult::Nonconformant => "nonconformant",
            AuditResult::Incomplete => "incomplete",
        }
    }
}

/// What airlock observed, with a stable code so consumers never parse prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// A stable code naming the observation, for example `file_present`.
    pub code: String,
    /// The repository path the observation is about, when it is about one.
    pub path: Option<String>,
    /// Human-readable detail. An adjunct to the code, never the contract.
    pub detail: String,
    /// The policy-owned capability declaration this evidence concerns.
    pub capability: Option<CapabilityDeclaration>,
    /// Per-parent template identities, when this is a template identity finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_identity: Option<crate::template_identity::TemplateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityDeclaration {
    pub property: String,
    pub value: String,
}

impl Evidence {
    /// Evidence about no particular path.
    #[must_use]
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            path: None,
            detail: detail.into(),
            capability: None,
            template_identity: None,
        }
    }

    /// Evidence about one repository path.
    #[must_use]
    pub fn at(code: impl Into<String>, path: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            path: Some(path.into()),
            detail: detail.into(),
            capability: None,
            template_identity: None,
        }
    }

    #[must_use]
    pub fn capability_undeclared(property: &str, value: &str) -> Self {
        Self {
            code: "capability_undeclared".to_owned(),
            path: None,
            detail: format!(
                "the repository has no organization custom property `{property}`; declare `{property}` as `{value}` when this capability holds"
            ),
            template_identity: None,
            capability: Some(CapabilityDeclaration {
                property: property.to_owned(),
                value: value.to_owned(),
            }),
        }
    }
}

/// What to do about a failure.
///
/// The fix group supports display and cross-rule grouping. The rule-level
/// join key and delivery fix kind live on [`FixClass`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    /// The declared family of actions this contextual remedy belongs to.
    pub fix_group: FixGroup,
    /// Human-readable detail.
    pub detail: String,
}

impl Fix {
    /// Build a fix.
    #[must_use]
    pub fn new(fix_group: FixGroup, detail: impl Into<String>) -> Self {
        Self {
            fix_group,
            detail: detail.into(),
        }
    }
}

/// The rule's declared fix classification, from the fix
/// model.
///
/// Rules defaults are joined onto every finding. A compiled Gap reason
/// can refine the default when the rule has fixes requiring different actors.
/// Exactly one of `fix_kind` and `none_reason` is set. The contextual
/// [`Fix`] says what to do here; this says who can do it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixClass {
    /// The fix kind the fix travels in, when there is one.
    pub fix_kind: Option<String>,
    /// The per-rule consumer join key, when there is one.
    pub code: Option<String>,
    /// What the fix would change, when there is one.
    pub change: Option<String>,
    /// Whether the change can be undone, when there is a fix.
    pub reversible: Option<bool>,
    /// Why no fix is offered, when none is.
    pub none_reason: Option<String>,
}

impl FixClass {
    /// Classify a release-record observation without changing rule-level defaults.
    #[must_use]
    pub fn for_observation(rule: &str, evidence: Option<&Evidence>) -> Self {
        let mut class = Self::for_rule(rule);
        if rule == "REPO-REL-08"
            && evidence.is_some_and(|e| {
                matches!(
                    e.code.as_str(),
                    "release-model-missing"
                        | "release-model-not-a-file"
                        | "release-model-unreadable"
                        | "release-model-schema-not-supported"
                )
            })
        {
            class.fix_kind = Some(crate::fix::FixKind::Agent.code().to_owned());
            class.code = Some("regenerate-release-model".to_owned());
            class.change =
                Some("Run intentional model and commit the supported Release Model.".to_owned());
        }
        class
    }

    /// The declared classification for a rule.
    ///
    /// A rule the rules do not know yields the shape with all five
    /// fields null — distinguishable from a declared no-fix, which
    /// always carries `none_reason`. The fix model's coverage test
    /// keeps that shape unreachable for registered rules; synthetic rule ids
    /// in tests are the only place it appears.
    #[must_use]
    pub fn for_rule(rule: &str) -> Self {
        match crate::fix::classify(rule) {
            Some(crate::fix::FixAvailability::Fix(definition)) => Self {
                fix_kind: Some(definition.fix_kind.code().to_owned()),
                code: Some(definition.code.to_owned()),
                change: Some(definition.change.to_owned()),
                reversible: Some(definition.reversible),
                none_reason: None,
            },
            Some(crate::fix::FixAvailability::NotFixable { reason, .. }) => Self {
                fix_kind: None,
                code: None,
                change: None,
                reversible: None,
                none_reason: Some((*reason).to_owned()),
            },
            None => Self {
                fix_kind: None,
                code: None,
                change: None,
                reversible: None,
                none_reason: None,
            },
        }
    }
}

/// An API failure that prevented a rule from being evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingError {
    /// The classified cause.
    pub cause: String,
    /// The endpoint that failed.
    pub endpoint: String,
    /// HTTP status, when there was a response.
    pub status: Option<u16>,
    /// GitHub's message, when there was one.
    pub message: Option<String>,
    /// GitHub's documentation link, when there was one.
    pub documentation_url: Option<String>,
    /// The permission the endpoint said it wanted.
    pub accepted_permissions: Option<String>,
    /// The GitHub request id, for support escalation.
    pub request_id: Option<String>,
    /// The version of the message-hint table that participated in
    /// classification.
    pub message_hints_version: u32,
}

/// Why a finding does not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionSource {
    Policy,
    RepositoryRequest,
}

impl SuppressionSource {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::RepositoryRequest => "repository_request",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suppression {
    /// `policy` when the policy suppressed it directly, `repository_request`
    /// when the audited repository asked and the policy allowed it.
    pub source: SuppressionSource,
    /// The reason the audited repository gave, when it asked.
    pub requested_reason: Option<String>,
    /// The reason the policy gave, when it suppressed directly.
    pub policy_reason: Option<String>,
    /// What authorised the suppression.
    pub authorized_by: String,
}

/// One rule's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Evaluated but not binding until its introduction generation is accepted.
    pub new: bool,
    /// The rule id.
    pub rule: String,
    /// The rule statement, verbatim.
    pub statement: String,
    /// The severity the effective policy gave the rule.
    pub severity: String,
    /// What the audit concluded.
    pub status: Option<Status>,
    /// What was observed.
    pub evidence: Option<Evidence>,
    /// What to do about it.
    pub fix: Option<Fix>,
    /// What closing this rule's gap takes, from the fix model.
    pub fix_class: FixClass,
    /// Why it does not count.
    pub suppression: Option<Suppression>,
    /// The observation source that decided it: `api` or `working-tree`.
    ///
    /// Null when no observation decided the finding — a judgment rule, a
    /// rule the rules have not implemented, or a platform rule in a run
    /// with no API credential.
    pub source: Option<String>,
    /// What stopped the evaluation.
    pub error: Option<FindingError>,
    /// The declared gate, when this rule was not evaluated here.
    pub routing: Option<Routing>,
}

impl Finding {
    #[must_use]
    pub fn blocks_completeness(&self) -> bool {
        self.status.is_none() && self.routing.is_none() && self.suppression.is_none()
    }
    #[must_use]
    pub fn status_code(&self) -> &str {
        self.status.map_or_else(
            || {
                if self.suppression.is_some() {
                    "waived"
                } else if let Some(route) = &self.routing {
                    if route.reason == "unbuilt" {
                        "unbuilt"
                    } else if route.reason == "out-of-scope" {
                        "out-of-scope"
                    } else {
                        "routed"
                    }
                } else {
                    "run-error"
                }
            },
            Status::code,
        )
    }
}

/// Something the audit noticed about the policy or the repository's requests
/// that is not about any one enabled rule.
///
/// A suppression request the policy did not authorise lands here: the finding
/// it targeted keeps its real status, and the attempt is on the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyObservationCode {
    InvalidSuppressionRequest,
    UnauthorizedSuppressionRequest,
}

impl PolicyObservationCode {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSuppressionRequest => "invalid_suppression_request",
            Self::UnauthorizedSuppressionRequest => "unauthorized_suppression_request",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyObservation {
    /// A stable code naming the observation.
    pub code: PolicyObservationCode,
    /// The rule it concerns, when it concerns one.
    pub rule: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

/// One rule instance in the effective, normalised policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EffectiveRuleRecord {
    /// Whether the rule is newer than the accepted generation.
    pub new: bool,
    /// The rule id.
    pub rule: String,
    /// The severity that applies after refinement.
    pub severity: String,
    /// The parameters that apply after refinement.
    pub params: BTreeMap<String, serde_json::Value>,
    /// Where the rule came from, for example `capability:base/licensing`.
    pub provenance: String,
}

/// The binary's own identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AirlockIdentity {
    /// The airlock version.
    pub version: String,
    /// The rules version.
    pub rules_version: String,
    /// The rules content digest.
    pub rules_digest: String,
}

impl AirlockIdentity {
    /// The identity of this binary.
    #[must_use]
    pub fn current(version: &str) -> Self {
        Self {
            version: version.to_owned(),
            rules_version: RULES_VERSION.to_owned(),
            rules_digest: crate::rules::digest(),
        }
    }
}

/// The audited repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditedRepository {
    /// `owner/name`.
    pub full_name: String,
    /// The numeric repository id, when the platform reported one.
    ///
    /// A working-tree run without a credential never saw the platform's
    /// record, so it carries no id rather than a made-up one.
    pub id: Option<u64>,
    /// The default branch.
    pub default_branch: String,
    /// The commit every git-backed fact was read at.
    pub audited_commit: String,
    /// When the settings snapshot was observed, which is a different moment
    /// from the commit.
    pub settings_observed_at: Option<String>,
}

/// One resolved source in the policy bundle.
///
/// Pinning reference data is only useful if a reader can see what it was
/// pinned to. The bundle digest says the inputs changed; these say which one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySourceIdentity {
    /// The reference name, or `policy` for the root document.
    pub name: String,
    /// Where it was resolved from: `owner/repo:path` or a local path.
    pub source: String,
    /// The commit it was pinned to, for a remote source.
    pub commit: Option<String>,
    /// The blob sha, for a remote source.
    pub blob_sha: Option<String>,
    /// A digest over the source's bytes.
    pub content_digest: String,
}

/// The policy the audit ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIdentity {
    /// The policy's declared name.
    pub name: String,
    /// Where it was resolved from.
    pub source: String,
    /// The commit it was pinned to, for a remote source.
    pub commit: Option<String>,
    /// Every source in the bundle, root first, each with what it pinned to.
    pub sources: Vec<PolicySourceIdentity>,
    /// The digest over the normalised policy and every referenced blob.
    pub bundle_digest: String,
}

/// Counts of decided rules and visible work not evaluated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub met: usize,
    pub gap: usize,
    pub waived: usize,
    pub routed: usize,
    pub unbuilt: usize,
    pub out_of_scope: usize,
    pub run_errors: usize,
}
impl Summary {
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        match status {
            Status::Met => self.met,
            Status::Gap => self.gap,
        }
    }
}

/// What each half of the audit was observed through.
///
/// One record per run, alongside the per-finding `source`: this says what
/// the run read, each finding says what decided it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationRecord {
    /// Where file-level rules were read from: `api` or `working-tree`.
    pub file_source: String,
    /// Where platform rules were read from: `api`, or null when no
    /// credential was supplied and platform rules were not observed.
    pub platform_source: Option<String>,
    /// The working tree that was observed, when one was.
    pub working_tree: Option<WorkingTreeObservation>,
}

impl ObservationRecord {
    /// The record for an API-only run.
    #[must_use]
    pub fn api() -> Self {
        Self {
            file_source: "api".to_owned(),
            platform_source: Some("api".to_owned()),
            working_tree: None,
        }
    }
}

/// The stated terms of a working-tree observation.
///
/// Every field here is a claim a reader would otherwise have to guess at,
/// which is exactly how a local result gets mistaken for a statement about
/// the default branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkingTreeObservation {
    /// The root of the observed working tree.
    pub root: String,
    /// The commit HEAD pointed at when the tree was observed.
    pub head_commit: String,
    /// Whether the tree differed from HEAD. Null when dirtiness could not be
    /// established — undetermined is never reported as clean.
    pub dirty: Option<bool>,
    /// Always true: the tree was evaluated as it stood, including
    /// uncommitted and untracked content.
    pub includes_uncommitted: bool,
    /// Always true: gitignored files were excluded, because a rule satisfied
    /// by an ignored file is not satisfied.
    pub ignored_files_excluded: bool,
    /// The default branch this run compared against, and whether it was
    /// observed from the clone's origin or assumed to be `main`.
    pub default_branch: String,
    /// True when `default_branch` was read from `refs/remotes/origin/HEAD`;
    /// false when it was assumed.
    pub default_branch_observed: bool,
}

/// The whole audit result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// The version of this document shape.
    pub schema_version: u32,
    /// The binary that produced it.
    pub airlock: AirlockIdentity,
    /// The repository it is about.
    pub repository: AuditedRepository,
    /// What the run observed each half through.
    pub observation: ObservationRecord,
    /// The policy it ran under.
    pub policy: PolicyIdentity,
    /// Every rule instance the policy compiled to.
    pub effective_policy: Vec<EffectiveRuleRecord>,
    /// Things noticed that are not about one enabled rule.
    pub policy_observations: Vec<PolicyObservation>,
    /// Evaluated rules only, ordered by rule id.
    pub findings: Vec<Finding>,
    pub waived: Vec<Finding>,
    pub routed: Vec<Finding>,
    pub unbuilt: Vec<Finding>,
    pub out_of_scope: Vec<Finding>,
    pub run_errors: Vec<Finding>,
    /// Counts per status.
    pub summary: Summary,
    /// Whether the run completed without a run error.
    pub complete: bool,
    /// Whether the observed Gaps include no blocking Gap.
    pub conformant: bool,
    /// The overall conclusion.
    pub outcome: AuditResult,
}

impl Report {
    pub fn entries(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .chain(&self.waived)
            .chain(&self.routed)
            .chain(&self.unbuilt)
            .chain(&self.out_of_scope)
            .chain(&self.run_errors)
    }

    /// Assemble a report, computing the summary and the outcome.
    ///
    /// Findings are sorted by rule id here, so ordering is a property of the
    /// document rather than of the order checks happened to finish in.
    #[must_use]
    pub fn assemble(
        airlock: AirlockIdentity,
        repository: AuditedRepository,
        observation: ObservationRecord,
        policy: PolicyIdentity,
        effective_policy: Vec<EffectiveRuleRecord>,
        policy_observations: Vec<PolicyObservation>,
        mut findings: Vec<Finding>,
    ) -> Self {
        findings.sort_by(|left, right| left.rule.cmp(&right.rule));

        let mut summary = Summary::default();
        let mut decided = Vec::new();
        let mut waived = Vec::new();
        let mut routed = Vec::new();
        let mut unbuilt = Vec::new();
        let mut out_of_scope = Vec::new();
        let mut run_errors = Vec::new();
        for mut finding in findings {
            if finding.suppression.is_some() || finding.severity == "none" {
                finding.status = None;
                waived.push(finding);
            } else if let Some(route) = &finding.routing {
                finding.status = None;
                if route.reason == "unbuilt" {
                    unbuilt.push(finding);
                } else if route.reason == "out-of-scope" {
                    out_of_scope.push(finding);
                } else {
                    routed.push(finding);
                }
            } else if finding.error.is_some() || finding.status.is_none() {
                finding.status = None;
                run_errors.push(finding);
            } else {
                match finding.status {
                    Some(Status::Met) => summary.met += 1,
                    Some(Status::Gap) => summary.gap += 1,
                    None => unreachable!(),
                }
                decided.push(finding);
            }
        }
        summary.waived = waived.len();
        summary.routed = routed.len();
        summary.unbuilt = unbuilt.len();
        summary.out_of_scope = out_of_scope.len();
        summary.run_errors = run_errors.len();
        let complete = run_errors.is_empty();
        let conformant = !decided
            .iter()
            .any(|f| f.status == Some(Status::Gap) && f.severity == "blocking" && !f.new);

        let outcome = if !complete {
            AuditResult::Incomplete
        } else if conformant {
            AuditResult::Conformant
        } else {
            AuditResult::Nonconformant
        };

        Self {
            schema_version: SCHEMA_VERSION,
            airlock,
            repository,
            observation,
            policy,
            effective_policy,
            policy_observations,
            findings: decided,
            waived,
            routed,
            unbuilt,
            out_of_scope,
            run_errors,
            summary,
            complete,
            conformant,
            outcome,
        }
    }

    /// The exit code this report carries.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.outcome.exit_code()
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::Finding;

    pub fn routed(mut finding: Finding) -> Finding {
        finding.status = None;
        finding.routing = Some(crate::findings::Routing {
            reason: "needs-administration".to_owned(),
            settling_surface: "interactive-session".to_owned(),
        });
        finding
    }
    pub fn unbuilt(mut finding: Finding) -> Finding {
        finding.status = None;
        finding.routing = Some(crate::findings::Routing {
            reason: "unbuilt".to_owned(),
            settling_surface: "A release with the compiled check implemented".to_owned(),
        });
        finding
    }
    pub fn waived(mut finding: Finding) -> Finding {
        finding.status = None;
        finding.severity = "none".to_owned();
        finding.suppression = Some(crate::findings::Suppression {
            source: crate::findings::SuppressionSource::Policy,
            requested_reason: None,
            policy_reason: Some("fixture waiver".to_owned()),
            authorized_by: "fixture policy".to_owned(),
        });
        finding
    }
}
