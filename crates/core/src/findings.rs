//! The audit result document.
//!
//! One audit run produces one findings document: the audited repository, the
//! resolved policy identity and digest, one finding per rule the effective
//! policy enabled, and a summary. Every finding carries its statement and
//! severity inline, so a reader never has to look up what a bare rule
//! identifier meant.
//!
//! The JSON form is the contract; the text form is a rendering of it. Fields
//! are always present — null rather than omitted — and findings are ordered by
//! rule id, so two runs over the same inputs produce the same bytes.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    registry::{Severity, REGISTRY_VERSION},
    ActionGroup,
};

/// The version of the JSON document shape.
pub const SCHEMA_VERSION: u32 = 1;

/// What an audit concluded about one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The assertion was evaluated and holds.
    Pass,
    /// The assertion was evaluated and does not hold.
    Fail,
    /// A judgment call. Conclusive: it needs a human. Never gates, never
    /// blocks completeness.
    Manual,
    /// A failure the policy authorised. Never gates.
    Suppressed,
    /// The capability condition that would have applied this rule was not met.
    /// Conclusive.
    Skipped,
    /// Enabled by policy, not yet built. Inconclusive.
    Unimplemented,
    /// Evaluation hit a resource bound, or a bounded scan could not prove the
    /// assertion. Inconclusive.
    Inconclusive,
    /// The fact requires admin access to verify. Inconclusive, and structurally
    /// so: this is the expected steady state of the read-only surface rather
    /// than something this run failed at, so it never blocks completeness. It
    /// is never a pass either — the assertion is still undecided, and it is
    /// named as its own group wherever gaps are reported.
    #[serde(rename = "admin-only")]
    AdminOnly,
    /// An API failure prevented evaluation. Inconclusive.
    Error,
}

/// Why an undecided finding is undecided.
///
/// Both kinds leave the assertion undecided, and neither is ever reported as a
/// pass. They differ in what a reader should conclude from seeing one, and
/// therefore in whether the run can be certified: a run that failed at
/// something it can normally do is not a result, while a run that reached the
/// edge of what its credential is allowed to see is working exactly as
/// mandated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Undecided {
    /// This run did not establish what it normally can: a truncated tree, a
    /// transient API failure, a file over budget, a rule not built yet. It
    /// blocks completeness, because retrying could answer it.
    Circumstantial,
    /// The fact requires admin access to verify, so no retry with this
    /// surface's read-only credential answers it. It does not block
    /// completeness; the answer lives on the interactive admin surface.
    Structural,
}

impl Undecided {
    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Circumstantial => "circumstantial",
            Self::Structural => "structural",
        }
    }
}

impl Status {
    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Manual => "manual",
            Status::Suppressed => "suppressed",
            Status::Skipped => "skipped",
            Status::Unimplemented => "unimplemented",
            Status::Inconclusive => "inconclusive",
            Status::AdminOnly => "admin-only",
            Status::Error => "error",
        }
    }

    /// Why the status leaves the assertion undecided, when it does.
    ///
    /// This is the single typed source of the structural-versus-circumstantial
    /// distinction. Every surface that treats undecided results differently —
    /// the completeness predicate, the plan, the agent work list, the rendered
    /// digest — asks this rather than matching evidence codes, so they cannot
    /// disagree about which unanswered questions stop a run.
    #[must_use]
    pub fn undecided(self) -> Option<Undecided> {
        match self {
            Status::Unimplemented | Status::Inconclusive | Status::Error => {
                Some(Undecided::Circumstantial)
            }
            Status::AdminOnly => Some(Undecided::Structural),
            Status::Pass | Status::Fail | Status::Manual | Status::Suppressed | Status::Skipped => {
                None
            }
        }
    }

    /// Whether the status leaves the assertion undecided.
    ///
    /// A *circumstantially* undecided result at a gate-relevant severity makes
    /// the whole audit incomplete. This is the property that stops airlock
    /// reporting success for work it did not do; see [`Status::undecided`] for
    /// which kind of undecided a status is.
    #[must_use]
    pub fn is_inconclusive(self) -> bool {
        self.undecided().is_some()
    }

    /// Every status, in taxonomy order.
    pub const ALL: &'static [Status] = &[
        Status::Pass,
        Status::Fail,
        Status::Manual,
        Status::Suppressed,
        Status::Skipped,
        Status::Unimplemented,
        Status::Inconclusive,
        Status::AdminOnly,
        Status::Error,
    ];
}

/// Which failing severities make an audit nonconformant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    /// Only blocking failures count.
    Blocking,
    /// Blocking and required failures count.
    Required,
}

impl Gate {
    /// Whether a failure at `severity` counts against conformance.
    #[must_use]
    pub fn enforces(self, severity: Severity) -> bool {
        match self {
            Gate::Blocking => severity == Severity::Blocking,
            Gate::Required => matches!(severity, Severity::Blocking | Severity::Required),
        }
    }

    /// Parse a gate from its machine-readable name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "blocking" => Some(Gate::Blocking),
            "required" => Some(Gate::Required),
            _ => None,
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Gate::Blocking => "blocking",
            Gate::Required => "required",
        }
    }
}

/// What the audit concluded overall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every enabled rule was decided and the gate is satisfied.
    Conformant,
    /// Every enabled rule was decided and the gate is not satisfied.
    Nonconformant,
    /// At least one gate-relevant rule was left undecided.
    Incomplete,
}

impl Outcome {
    /// The process exit code carrying this outcome.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Outcome::Conformant => 0,
            Outcome::Nonconformant => 1,
            Outcome::Incomplete => 2,
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Outcome::Conformant => "conformant",
            Outcome::Nonconformant => "nonconformant",
            Outcome::Incomplete => "incomplete",
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
}

impl Evidence {
    /// Evidence about no particular path.
    #[must_use]
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            path: None,
            detail: detail.into(),
        }
    }

    /// Evidence about one repository path.
    #[must_use]
    pub fn at(code: impl Into<String>, path: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            path: Some(path.into()),
            detail: detail.into(),
        }
    }
}

/// What to do about a failure.
///
/// The action group supports display and cross-rule grouping. The rule-level
/// join key and delivery lane live on [`RemediationClass`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Remediation {
    /// The declared family of actions this contextual remedy belongs to.
    pub action_group: ActionGroup,
    /// Human-readable detail.
    pub detail: String,
}

impl Remediation {
    /// Build a remediation.
    #[must_use]
    pub fn new(action_group: ActionGroup, detail: impl Into<String>) -> Self {
        Self {
            action_group,
            detail: detail.into(),
        }
    }
}

/// The rule's declared remediation classification, from the remediation
/// model.
///
/// This is registry-level data joined onto every finding: what closing the
/// rule's gap takes, regardless of what this audit observed. Exactly one of
/// `lane` and `none_reason` is set. The contextual [`Remediation`] on a
/// failing finding says what to do here; this says what kind of work that is
/// and who can do it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemediationClass {
    /// The lane the remediation travels in, when there is one.
    pub lane: Option<String>,
    /// The per-rule consumer join key, when there is one.
    pub code: Option<String>,
    /// What the remediation would change, when there is one.
    pub change: Option<String>,
    /// Whether the change can be undone, when there is a remediation.
    pub reversible: Option<bool>,
    /// Why no remediation is offered, when none is.
    pub none_reason: Option<String>,
}

impl RemediationClass {
    /// The declared classification for a rule.
    ///
    /// A rule the registry does not know yields the shape with all five
    /// fields null — distinguishable from a declared no-remediation, which
    /// always carries `none_reason`. The remediation model's coverage test
    /// keeps that shape unreachable for registered rules; synthetic rule ids
    /// in tests are the only place it appears.
    #[must_use]
    pub fn for_rule(rule: &str) -> Self {
        match crate::remediation::classify(rule) {
            Some(crate::remediation::Classification::Remediation(definition)) => Self {
                lane: Some(definition.lane.code().to_owned()),
                code: Some(definition.code.to_owned()),
                change: Some(definition.change.to_owned()),
                reversible: Some(definition.reversible),
                none_reason: None,
            },
            Some(crate::remediation::Classification::NotRemediable { reason, .. }) => Self {
                lane: None,
                code: None,
                change: None,
                reversible: None,
                none_reason: Some((*reason).to_owned()),
            },
            None => Self {
                lane: None,
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
    /// The rule id.
    pub rule: String,
    /// The rule statement, verbatim.
    pub statement: String,
    /// The severity the effective policy gave the rule.
    pub severity: String,
    /// What the audit concluded.
    pub status: Status,
    /// What was observed.
    pub evidence: Option<Evidence>,
    /// What to do about it.
    pub remediation: Option<Remediation>,
    /// What closing this rule's gap takes, from the remediation model.
    pub remediation_class: RemediationClass,
    /// Why it does not count.
    pub suppression: Option<Suppression>,
    /// The observation source that decided it: `api` or `working-tree`.
    ///
    /// Null when no observation decided the finding — a judgment rule, a
    /// rule the registry has not implemented, or a platform rule in a run
    /// with no API credential.
    pub source: Option<String>,
    /// What stopped the evaluation.
    pub error: Option<FindingError>,
}

impl Finding {
    /// Whether this finding leaves the assertion undecided under `gate`.
    ///
    /// This is the single completeness predicate used when assembling an
    /// audit and by projections that must identify the questions behind an
    /// incomplete result.
    ///
    /// Only a *circumstantially* undecided finding blocks: this run failed to
    /// establish something it can normally establish, so the result cannot be
    /// certified. A structurally undecided finding — one whose fact requires
    /// admin access to verify — is the read-only surface working as designed.
    /// Blocking on it would make the verdict permanently red, which carries no
    /// information, so it does not block. It is still never a pass, and
    /// [`Self::names_a_structural_gap`] keeps it visible.
    #[must_use]
    pub fn blocks_completeness(&self, gate: Gate) -> bool {
        let severity = Severity::parse(&self.severity).unwrap_or(Severity::Observation);
        gate.enforces(severity) && self.status.undecided() == Some(Undecided::Circumstantial)
    }

    /// Whether this finding names a gap that requires admin access to verify.
    ///
    /// The counterpart of [`Self::blocks_completeness`]: what does not gate
    /// must still be named, at every severity, or "my lane is clear" quietly
    /// becomes "the repository is aligned".
    #[must_use]
    pub fn names_a_structural_gap(&self) -> bool {
        self.status.undecided() == Some(Undecided::Structural)
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
pub struct EffectiveRule {
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
    /// The check registry version.
    pub registry_version: String,
    /// The check registry content digest.
    pub registry_digest: String,
}

impl AirlockIdentity {
    /// The identity of this binary.
    #[must_use]
    pub fn current(version: &str) -> Self {
        Self {
            version: version.to_owned(),
            registry_version: REGISTRY_VERSION.to_owned(),
            registry_digest: crate::registry::digest(),
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
    /// The gate the policy declared.
    pub gate: Gate,
}

/// How many findings landed in each status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Assertions that hold.
    pub pass: usize,
    /// Assertions that do not hold.
    pub fail: usize,
    /// Judgment calls waiting on a human.
    pub manual: usize,
    /// Failures the policy authorised.
    pub suppressed: usize,
    /// Rules whose capability condition was not met.
    pub skipped: usize,
    /// Rules enabled but not yet built.
    pub unimplemented: usize,
    /// Rules left undecided by a resource bound.
    pub inconclusive: usize,
    /// Rules whose fact requires admin access to verify.
    #[serde(rename = "admin-only")]
    pub admin_only: usize,
    /// Rules an API failure prevented evaluating.
    pub error: usize,
}

impl Summary {
    fn slot(&mut self, status: Status) -> &mut usize {
        match status {
            Status::Pass => &mut self.pass,
            Status::Fail => &mut self.fail,
            Status::Manual => &mut self.manual,
            Status::Suppressed => &mut self.suppressed,
            Status::Skipped => &mut self.skipped,
            Status::Unimplemented => &mut self.unimplemented,
            Status::Inconclusive => &mut self.inconclusive,
            Status::AdminOnly => &mut self.admin_only,
            Status::Error => &mut self.error,
        }
    }

    fn record(&mut self, status: Status) {
        *self.slot(status) += 1;
    }

    /// How many findings landed in one status.
    ///
    /// Lets a renderer walk [`Status::ALL`] rather than restating the fields,
    /// so a status cannot be added without every reader of the summary
    /// following it.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        let mut copy = self.clone();
        *copy.slot(status)
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
    pub effective_policy: Vec<EffectiveRule>,
    /// Things noticed that are not about one enabled rule.
    pub policy_observations: Vec<PolicyObservation>,
    /// One finding per enabled rule, ordered by rule id.
    pub findings: Vec<Finding>,
    /// Counts per status.
    pub summary: Summary,
    /// Whether every gate-relevant rule was decided.
    pub complete: bool,
    /// Whether the gate is satisfied.
    pub conformant: bool,
    /// The overall conclusion.
    pub outcome: Outcome,
}

impl Report {
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
        effective_policy: Vec<EffectiveRule>,
        policy_observations: Vec<PolicyObservation>,
        mut findings: Vec<Finding>,
    ) -> Self {
        findings.sort_by(|left, right| left.rule.cmp(&right.rule));

        let gate = policy.gate;
        let mut summary = Summary::default();
        let mut complete = true;
        let mut conformant = true;

        for finding in &findings {
            summary.record(finding.status);
            let severity = Severity::parse(&finding.severity).unwrap_or(Severity::Observation);
            if finding.blocks_completeness(gate) {
                complete = false;
            }
            if gate.enforces(severity) && finding.status == Status::Fail {
                conformant = false;
            }
        }

        let outcome = if !complete {
            Outcome::Incomplete
        } else if conformant {
            Outcome::Conformant
        } else {
            Outcome::Nonconformant
        };

        Self {
            schema_version: SCHEMA_VERSION,
            airlock,
            repository,
            observation,
            policy,
            effective_policy,
            policy_observations,
            findings,
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
mod tests {
    use super::*;

    fn finding(rule: &str, severity: Severity, status: Status) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: format!("statement for {rule}"),
            severity: severity.code().to_owned(),
            status,
            evidence: None,
            remediation: None,
            remediation_class: RemediationClass::for_rule(rule),
            suppression: None,
            source: None,
            error: None,
        }
    }

    fn report(gate: Gate, findings: Vec<Finding>) -> Report {
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "owner/name".to_owned(),
                id: Some(1),
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            ObservationRecord::api(),
            PolicyIdentity {
                name: "test".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                sources: Vec::new(),
                bundle_digest: "sha256:0".to_owned(),
                gate,
            },
            Vec::new(),
            Vec::new(),
            findings,
        )
    }

    #[test]
    fn a_clean_audit_is_conformant_and_exits_zero() {
        let report = report(
            Gate::Blocking,
            vec![
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                finding("REPO-FILE-02", Severity::Required, Status::Fail),
            ],
        );
        assert!(report.complete);
        assert!(report.conformant);
        assert_eq!(report.outcome, Outcome::Conformant);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_required_failure_gates_under_the_required_gate() {
        let report = report(
            Gate::Required,
            vec![finding("REPO-FILE-02", Severity::Required, Status::Fail)],
        );
        assert!(report.complete);
        assert!(!report.conformant);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn an_unimplemented_blocking_rule_makes_the_audit_incomplete() {
        let report = report(
            Gate::Blocking,
            vec![
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                finding("REPO-CI-02", Severity::Blocking, Status::Unimplemented),
            ],
        );
        assert!(!report.complete);
        assert_eq!(report.outcome, Outcome::Incomplete);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn incompleteness_outranks_nonconformance() {
        let report = report(
            Gate::Blocking,
            vec![
                finding("REPO-CI-02", Severity::Blocking, Status::Fail),
                finding("REPO-LIC-01", Severity::Blocking, Status::Error),
            ],
        );
        assert!(!report.conformant);
        assert_eq!(report.outcome, Outcome::Incomplete);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn a_manual_blocking_rule_never_gates_and_never_blocks_completeness() {
        let report = report(
            Gate::Blocking,
            vec![finding(
                "REPO-README-04",
                Severity::Blocking,
                Status::Manual,
            )],
        );
        assert!(report.complete);
        assert!(report.conformant);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_suppressed_blocking_rule_never_gates() {
        let report = report(
            Gate::Blocking,
            vec![finding(
                "REPO-CI-02",
                Severity::Blocking,
                Status::Suppressed,
            )],
        );
        assert!(report.conformant);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_skipped_rule_is_conclusive() {
        let report = report(
            Gate::Blocking,
            vec![finding("REPO-REL-04", Severity::Blocking, Status::Skipped)],
        );
        assert!(report.complete);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn an_inconclusive_observation_does_not_block_a_blocking_gate() {
        let report = report(
            Gate::Blocking,
            vec![finding(
                "REPO-FILE-14",
                Severity::Observation,
                Status::Inconclusive,
            )],
        );
        assert!(report.complete);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_structural_gap_at_a_gating_severity_leaves_the_run_complete() {
        // This fact requires admin access to verify, so a red read-only run
        // would be the permanent steady state and would carry no information.
        // It is still not a pass, and it is still named.
        let report = report(
            Gate::Required,
            vec![
                finding("REPO-GIT-04", Severity::Required, Status::AdminOnly),
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
            ],
        );
        assert!(report.complete);
        assert!(report.conformant);
        assert_eq!(report.outcome, Outcome::Conformant);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.summary.admin_only, 1);
        assert_eq!(report.summary.pass, 1);
        assert_ne!(report.findings[0].status, Status::Pass);
        assert!(report.findings[0].names_a_structural_gap());
        assert!(!report.findings[0].blocks_completeness(Gate::Required));
    }

    #[test]
    fn a_circumstantial_gap_at_a_gating_severity_still_stops_the_run() {
        for status in [Status::Inconclusive, Status::Error, Status::Unimplemented] {
            let report = report(
                Gate::Required,
                vec![finding("REPO-GIT-04", Severity::Required, status)],
            );
            assert!(!report.complete, "{status:?}");
            assert_eq!(report.exit_code(), 2, "{status:?}");
            assert!(!report.findings[0].names_a_structural_gap(), "{status:?}");
        }
    }

    #[test]
    fn every_undecided_status_declares_which_kind_of_undecided_it_is() {
        // The distinction is a total function over the taxonomy: a status
        // added without a kind cannot compile, and no surface has to guess.
        for status in Status::ALL {
            assert_eq!(
                status.is_inconclusive(),
                status.undecided().is_some(),
                "{status:?}"
            );
        }
        assert_eq!(Status::AdminOnly.undecided(), Some(Undecided::Structural));
        assert_eq!(
            Status::Inconclusive.undecided(),
            Some(Undecided::Circumstantial)
        );
        assert_eq!(Status::Pass.undecided(), None);
    }

    #[test]
    fn findings_are_ordered_by_rule_id() {
        let report = report(
            Gate::Blocking,
            vec![
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                finding("REPO-CI-02", Severity::Blocking, Status::Pass),
                finding("REPO-FILE-01", Severity::Blocking, Status::Pass),
            ],
        );
        let ids: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(ids, vec!["REPO-CI-02", "REPO-FILE-01", "REPO-LIC-01"]);
    }

    #[test]
    fn the_summary_counts_every_status() {
        let report = report(
            Gate::Blocking,
            vec![
                finding("REPO-AA-01", Severity::Observation, Status::Pass),
                finding("REPO-AA-02", Severity::Observation, Status::Fail),
                finding("REPO-AA-03", Severity::Observation, Status::Manual),
                finding("REPO-AA-04", Severity::Observation, Status::Suppressed),
                finding("REPO-AA-05", Severity::Observation, Status::Skipped),
                finding("REPO-AA-06", Severity::Observation, Status::Unimplemented),
                finding("REPO-AA-07", Severity::Observation, Status::Inconclusive),
                finding("REPO-AA-08", Severity::Observation, Status::AdminOnly),
                finding("REPO-AA-09", Severity::Observation, Status::Error),
            ],
        );
        assert_eq!(report.summary.pass, 1);
        assert_eq!(report.summary.fail, 1);
        assert_eq!(report.summary.manual, 1);
        assert_eq!(report.summary.suppressed, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.unimplemented, 1);
        assert_eq!(report.summary.inconclusive, 1);
        assert_eq!(report.summary.admin_only, 1);
        assert_eq!(report.summary.error, 1);
        assert_eq!(report.findings.len(), Status::ALL.len());
    }

    #[test]
    fn json_keys_are_snake_case_and_fields_are_present_not_omitted() {
        let report = report(
            Gate::Blocking,
            vec![finding("REPO-LIC-01", Severity::Blocking, Status::Pass)],
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["outcome"], "conformant");
        assert_eq!(json["airlock"]["registry_version"], REGISTRY_VERSION);
        let finding = &json["findings"][0];
        for key in ["evidence", "remediation", "suppression", "error"] {
            assert!(finding.get(key).unwrap().is_null(), "{key} should be null");
        }
    }
}
