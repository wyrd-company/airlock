//! The agent-lane projection of an audit report.
//!
//! This module does not evaluate a repository. It projects a fresh
//! [`Report`](crate::findings::Report) into the two remediation lanes an agent
//! can act in, while keeping operator-setting gaps and unanswered gating
//! questions visible.

use serde::Serialize;

use crate::findings::{
    AirlockIdentity, AuditedRepository, ObservationRecord, PolicyIdentity, Report, Status,
    Undecided,
};
use crate::remediation::Lane;

/// The version of the agent work-list JSON document.
pub const SCHEMA_VERSION: u32 = 1;

/// What the lane-scoped definition-of-done check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every gating question was settled and no agent-lane failure remains.
    AgentLaneClear,
    /// Every gating question was settled and agent-lane failures remain.
    AgentLaneWorkRemains,
    /// The audit could not settle every gate-relevant question.
    CouldNotSettle,
}

impl Outcome {
    /// The process exit code carrying this outcome.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::AgentLaneClear => 0,
            Self::AgentLaneWorkRemains => 1,
            Self::CouldNotSettle => 2,
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AgentLaneClear => "agent_lane_clear",
            Self::AgentLaneWorkRemains => "agent_lane_work_remains",
            Self::CouldNotSettle => "could_not_settle",
        }
    }
}

/// One outstanding gap with a declared remediation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkItem {
    /// The rule id and stable key for this item.
    pub rule: String,
    /// The rule statement.
    pub statement: String,
    /// The effective severity.
    pub severity: String,
    /// The per-rule remediation join key.
    pub remediation_code: String,
    /// What the remediation would change.
    pub change: String,
    /// The remediation lane.
    pub lane: String,
    /// What decided the finding: `api` or `working-tree`.
    pub source: Option<String>,
}

/// One failure whose remaining move belongs to a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorDeferredItem {
    /// The rule id and stable key for this item.
    pub rule: String,
    /// The rule statement.
    pub statement: String,
    /// The effective severity.
    pub severity: String,
    /// The remediation join key, when a setting remediation exists.
    pub remediation_code: Option<String>,
    /// What the remediation would change, when one exists.
    pub change: Option<String>,
    /// The remediation lane, when one exists.
    pub lane: Option<String>,
    /// Why no remediation is offered, when that is the declaration.
    pub none_reason: Option<String>,
    /// What decided the finding.
    pub source: Option<String>,
}

/// One question the audit did not settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsettledItem {
    /// The rule id and stable key for this item.
    pub rule: String,
    /// The undecided status.
    pub status: Status,
    /// Why the question is unanswered: this run fell short
    /// (`circumstantial`), or the mandated credential can never see it
    /// (`structural`).
    pub undecided: Option<Undecided>,
    /// The effective severity.
    pub severity: String,
    /// Whether this unanswered question blocks completeness under the gate.
    pub gating: bool,
    /// The evidence classification, when one was available.
    pub evidence_code: Option<String>,
    /// What decided the finding, if anything did.
    pub source: Option<String>,
}

/// One non-gating finding that remains relevant to a handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttentionItem {
    /// The rule id and stable key for this item.
    pub rule: String,
    /// The rule statement.
    pub statement: String,
    /// The finding status.
    pub status: Status,
    /// The effective severity.
    pub severity: String,
    /// What decided the finding, if anything did.
    pub source: Option<String>,
}

/// A counted collection whose items are ordered by rule id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkGroup<T> {
    /// Number of items in this group.
    pub count: usize,
    /// Items ordered by rule id.
    pub items: Vec<T>,
}

impl<T> WorkGroup<T> {
    fn new(items: Vec<T>) -> Self {
        Self {
            count: items.len(),
            items,
        }
    }
}

/// A lane-scoped definition-of-done result derived from one audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentWorkList {
    /// The version of this document shape.
    pub schema_version: u32,
    /// A permanent warning against reading this as repository conformance.
    pub scope: &'static str,
    /// The binary that produced the underlying audit.
    pub airlock: AirlockIdentity,
    /// The repository and commit the audit examined.
    pub repository: AuditedRepository,
    /// The sources that decided file and platform findings.
    pub observation: ObservationRecord,
    /// The policy identity and gate used by the audit.
    pub policy: PolicyIdentity,
    /// Outstanding deterministic and judgment file changes.
    pub agent_lane: WorkGroup<WorkItem>,
    /// Outstanding settings and no-remediation failures deferred to a person.
    pub operator_deferred: WorkGroup<OperatorDeferredItem>,
    /// Capability declarations a person must make before evaluation.
    pub needs_decision: WorkGroup<UnsettledItem>,
    /// Questions the audit could not settle, including non-gating ones.
    pub unsettled: WorkGroup<UnsettledItem>,
    /// Gaps this surface's mandated credential can never observe.
    ///
    /// These never gate — a permanently red lane says nothing — but they are
    /// listed at every severity, because an unobservable rule is not a passing
    /// rule and a clear lane is not an aligned repository. The remaining move
    /// is to verify them on a surface that can see them: the interactive
    /// session.
    pub unverifiable: WorkGroup<UnsettledItem>,
    /// Manual judgments still awaiting a person.
    pub manual: WorkGroup<AttentionItem>,
    /// Authorized failures that remain standing debt.
    pub suppressed: WorkGroup<AttentionItem>,
    /// The lane-scoped conclusion.
    pub outcome: Outcome,
}

impl AgentWorkList {
    /// Project an audit report without re-evaluating or caching any finding.
    #[must_use]
    pub fn from_report(report: &Report) -> Self {
        let mut agent = Vec::new();
        let mut operator = Vec::new();
        let mut decisions = Vec::new();
        let mut unsettled = Vec::new();
        let mut unverifiable = Vec::new();
        let mut manual = Vec::new();
        let mut suppressed = Vec::new();
        let mut classification_unsettled = false;

        for finding in &report.findings {
            if let Some(kind) = finding.status.undecided() {
                let item = UnsettledItem {
                    rule: finding.rule.clone(),
                    status: finding.status,
                    undecided: Some(kind),
                    severity: finding.severity.clone(),
                    gating: finding.blocks_completeness(report.policy.gate),
                    evidence_code: finding
                        .evidence
                        .as_ref()
                        .map(|evidence| evidence.code.clone()),
                    source: finding.source.clone(),
                };
                match kind {
                    // A structural gap belongs in its own group whatever its
                    // evidence code: it is not a question this surface can be
                    // asked again, so grouping it with the ones that can be
                    // would invite a retry that cannot work.
                    Undecided::Structural => unverifiable.push(item),
                    Undecided::Circumstantial => {
                        if item.evidence_code.as_deref() == Some("condition_undecided") {
                            decisions.push(item);
                        } else {
                            unsettled.push(item);
                        }
                    }
                }
                continue;
            }

            if matches!(finding.status, Status::Manual | Status::Suppressed) {
                let item = AttentionItem {
                    rule: finding.rule.clone(),
                    statement: finding.statement.clone(),
                    status: finding.status,
                    severity: finding.severity.clone(),
                    source: finding.source.clone(),
                };
                if finding.status == Status::Manual {
                    manual.push(item);
                } else {
                    suppressed.push(item);
                }
                continue;
            }

            if finding.status != Status::Fail {
                continue;
            }

            let class = &finding.remediation_class;
            if class.lane.is_none() && class.none_reason.is_some() {
                operator.push(OperatorDeferredItem {
                    rule: finding.rule.clone(),
                    statement: finding.statement.clone(),
                    severity: finding.severity.clone(),
                    remediation_code: None,
                    change: None,
                    lane: None,
                    none_reason: class.none_reason.clone(),
                    source: finding.source.clone(),
                });
                continue;
            }
            let (Some(lane), Some(code), Some(change)) = (&class.lane, &class.code, &class.change)
            else {
                classification_unsettled = true;
                unsettled.push(UnsettledItem {
                    rule: finding.rule.clone(),
                    status: finding.status,
                    undecided: None,
                    severity: finding.severity.clone(),
                    gating: true,
                    evidence_code: Some("remediation_class_undecided".to_owned()),
                    source: finding.source.clone(),
                });
                continue;
            };
            let Some(lane_kind) = Lane::parse(lane) else {
                classification_unsettled = true;
                unsettled.push(UnsettledItem {
                    rule: finding.rule.clone(),
                    status: finding.status,
                    undecided: None,
                    severity: finding.severity.clone(),
                    gating: true,
                    evidence_code: Some("remediation_lane_unknown".to_owned()),
                    source: finding.source.clone(),
                });
                continue;
            };
            let item = WorkItem {
                rule: finding.rule.clone(),
                statement: finding.statement.clone(),
                severity: finding.severity.clone(),
                remediation_code: code.clone(),
                change: change.clone(),
                lane: lane.clone(),
                source: finding.source.clone(),
            };
            match lane_kind {
                Lane::DeterministicFile | Lane::JudgmentFile => agent.push(item),
                Lane::OperatorSetting => operator.push(OperatorDeferredItem {
                    rule: item.rule,
                    statement: item.statement,
                    severity: item.severity,
                    remediation_code: Some(item.remediation_code),
                    change: Some(item.change),
                    lane: Some(item.lane),
                    none_reason: None,
                    source: item.source,
                }),
            }
        }

        let outcome = if !report.complete || classification_unsettled {
            Outcome::CouldNotSettle
        } else if agent.is_empty() {
            Outcome::AgentLaneClear
        } else {
            Outcome::AgentLaneWorkRemains
        };

        Self {
            schema_version: SCHEMA_VERSION,
            scope: "agent_lane_only_not_repository_conformance",
            airlock: report.airlock.clone(),
            repository: report.repository.clone(),
            observation: report.observation.clone(),
            policy: report.policy.clone(),
            agent_lane: WorkGroup::new(agent),
            operator_deferred: WorkGroup::new(operator),
            needs_decision: WorkGroup::new(decisions),
            unsettled: WorkGroup::new(unsettled),
            unverifiable: WorkGroup::new(unverifiable),
            manual: WorkGroup::new(manual),
            suppressed: WorkGroup::new(suppressed),
            outcome,
        }
    }

    /// The process exit code carrying this lane-scoped result.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.outcome.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Evidence, Finding, Gate, PolicyIdentity, RemediationClass};

    fn finding(rule: &str, status: Status, severity: &str, source: Option<&str>) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: format!("statement for {rule}"),
            severity: severity.to_owned(),
            status,
            evidence: Some(Evidence::new("fixture", "fixture observation")),
            remediation: None,
            remediation_class: RemediationClass::for_rule(rule),
            suppression: None,
            source: source.map(ToOwned::to_owned),
            error: None,
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        report_with_observation(findings, ObservationRecord::api())
    }

    fn report_with_observation(findings: Vec<Finding>, observation: ObservationRecord) -> Report {
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "owner/example".to_owned(),
                id: Some(1),
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            observation,
            PolicyIdentity {
                name: "fixture".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                sources: Vec::new(),
                bundle_digest: "sha256:fixture".to_owned(),
                gate: Gate::Blocking,
            },
            Vec::new(),
            Vec::new(),
            findings,
        )
    }

    #[test]
    fn file_failures_are_split_from_operator_failures_by_declared_lane() {
        let report = report(vec![
            finding(
                "REPO-META-01",
                Status::Fail,
                "blocking",
                Some("working-tree"),
            ),
            finding("REPO-NAME-01", Status::Fail, "blocking", Some("api")),
            finding(
                "REPO-LIC-01",
                Status::Fail,
                "blocking",
                Some("working-tree"),
            ),
        ]);

        let list = AgentWorkList::from_report(&report);

        assert_eq!(list.outcome, Outcome::AgentLaneWorkRemains);
        assert_eq!(list.exit_code(), 1);
        assert_eq!(list.agent_lane.count, 2);
        assert_eq!(
            list.agent_lane
                .items
                .iter()
                .map(|item| item.rule.as_str())
                .collect::<Vec<_>>(),
            ["REPO-LIC-01", "REPO-META-01"]
        );
        assert_eq!(
            list.agent_lane.items[0].remediation_code,
            "add-license-file"
        );
        assert_eq!(list.agent_lane.items[0].lane, "deterministic-file");
        assert_eq!(list.agent_lane.items[1].lane, "judgment-file");
        assert_eq!(list.operator_deferred.count, 1);
        assert_eq!(list.operator_deferred.items[0].rule, "REPO-NAME-01");
    }

    #[test]
    fn operator_work_never_prevents_an_agent_lane_clear_result() {
        let list = AgentWorkList::from_report(&report(vec![finding(
            "REPO-NAME-01",
            Status::Fail,
            "blocking",
            Some("api"),
        )]));

        assert_eq!(list.outcome, Outcome::AgentLaneClear);
        assert_eq!(list.exit_code(), 0);
        assert_eq!(list.agent_lane.count, 0);
        assert_eq!(list.operator_deferred.count, 1);
        assert_eq!(list.scope, "agent_lane_only_not_repository_conformance");
    }

    #[test]
    fn an_unanswered_gating_question_outranks_remaining_work() {
        let list = AgentWorkList::from_report(&report(vec![
            finding(
                "REPO-LIC-01",
                Status::Fail,
                "blocking",
                Some("working-tree"),
            ),
            finding("REPO-GIT-02", Status::Error, "blocking", None),
        ]));

        assert_eq!(list.outcome, Outcome::CouldNotSettle);
        assert_eq!(list.exit_code(), 2);
        assert_eq!(list.agent_lane.count, 1);
        assert_eq!(list.unsettled.count, 1);
        assert_eq!(list.unsettled.items[0].rule, "REPO-GIT-02");
        assert!(list.unsettled.items[0].gating);
    }

    #[test]
    fn declared_no_remediation_failures_are_deferred_to_the_operator() {
        let list = AgentWorkList::from_report(&report(vec![finding(
            "REPO-GIT-09",
            Status::Fail,
            "blocking",
            Some("api"),
        )]));

        assert_eq!(list.outcome, Outcome::AgentLaneClear);
        assert_eq!(list.operator_deferred.count, 1);
        assert_eq!(list.operator_deferred.items[0].rule, "REPO-GIT-09");
        assert!(list.operator_deferred.items[0].none_reason.is_some());
    }

    #[test]
    fn an_unknown_failure_classification_cannot_report_clear() {
        let list = AgentWorkList::from_report(&report(vec![finding(
            "RULE-UNKNOWN",
            Status::Fail,
            "observation",
            Some("api"),
        )]));

        assert_eq!(list.outcome, Outcome::CouldNotSettle);
        assert_eq!(list.unsettled.count, 1);
        assert_eq!(
            list.unsettled.items[0].evidence_code.as_deref(),
            Some("remediation_class_undecided")
        );
    }

    #[test]
    fn non_gating_unanswered_questions_remain_visible_without_gating() {
        let list = AgentWorkList::from_report(&report(vec![finding(
            "REPO-LIC-01",
            Status::Inconclusive,
            "observation",
            None,
        )]));

        assert_eq!(list.outcome, Outcome::AgentLaneClear);
        assert_eq!(list.unsettled.count, 1);
        assert!(!list.unsettled.items[0].gating);
    }

    #[test]
    fn structural_gaps_get_their_own_group_and_never_gate_the_lane() {
        let list = AgentWorkList::from_report(&report(vec![
            finding("REPO-GIT-04", Status::Unobservable, "required", Some("api")),
            finding("REPO-LIC-01", Status::Pass, "blocking", Some("api")),
        ]));

        assert_eq!(list.outcome, Outcome::AgentLaneClear);
        assert_eq!(list.exit_code(), 0);
        assert_eq!(list.unsettled.count, 0);
        assert_eq!(list.unverifiable.count, 1);
        let item = &list.unverifiable.items[0];
        assert_eq!(item.rule, "REPO-GIT-04");
        assert_eq!(item.undecided, Some(Undecided::Structural));
        assert!(
            !item.gating,
            "a gap the mandated credential can never observe does not gate"
        );
    }

    #[test]
    fn a_clear_lane_beside_a_structural_gap_still_names_the_gap() {
        // "My lane is clear" must never be read as "the repository is
        // aligned". The lane is clear and the rule is unverified, and the
        // document has to say both.
        let list = AgentWorkList::from_report(&report(vec![finding(
            "REPO-GIT-04",
            Status::Unobservable,
            "required",
            Some("api"),
        )]));

        assert_eq!(list.outcome, Outcome::AgentLaneClear);
        assert_eq!(list.scope, "agent_lane_only_not_repository_conformance");
        assert_eq!(list.unverifiable.count, 1);
        let text = crate::render::agent_work_list_text(&list);
        assert!(
            text.contains("unverifiable with this credential (never gates) (1)"),
            "{text}"
        );
        assert!(text.contains("REPO-GIT-04"), "{text}");
        assert!(
            text.contains("unverifiable with this credential: 1"),
            "{text}"
        );
    }

    #[test]
    fn a_structural_gap_does_not_hide_a_circumstantial_one() {
        let list = AgentWorkList::from_report(&report(vec![
            finding("REPO-GIT-04", Status::Unobservable, "required", Some("api")),
            finding("REPO-GIT-02", Status::Error, "blocking", None),
        ]));

        assert_eq!(list.outcome, Outcome::CouldNotSettle);
        assert_eq!(list.exit_code(), 2);
        assert_eq!(list.unverifiable.count, 1);
        assert_eq!(list.unsettled.count, 1);
        assert!(list.unsettled.items[0].gating);
    }

    #[test]
    fn capability_decisions_manual_judgments_and_suppressed_debt_are_distinct() {
        let mut decision = finding(
            "REPO-REL-01",
            Status::Inconclusive,
            "observation",
            Some("working-tree"),
        );
        decision.evidence = Some(Evidence::new(
            "condition_undecided",
            "the capability could not be selected",
        ));
        let list = AgentWorkList::from_report(&report(vec![
            decision,
            finding("REPO-DOCS-05", Status::Manual, "blocking", None),
            finding("REPO-LIC-01", Status::Suppressed, "blocking", Some("api")),
        ]));

        assert_eq!(list.needs_decision.count, 1);
        assert_eq!(list.needs_decision.items[0].rule, "REPO-REL-01");
        assert_eq!(list.manual.count, 1);
        assert_eq!(list.manual.items[0].rule, "REPO-DOCS-05");
        assert_eq!(list.suppressed.count, 1);
        assert_eq!(list.suppressed.items[0].rule, "REPO-LIC-01");
    }

    #[test]
    fn text_rendering_names_an_undetermined_working_tree() {
        let list = AgentWorkList::from_report(&report_with_observation(
            Vec::new(),
            ObservationRecord {
                file_source: "working-tree".to_owned(),
                platform_source: None,
                working_tree: Some(crate::findings::WorkingTreeObservation {
                    root: "/workspace".to_owned(),
                    head_commit: "b".repeat(40),
                    dirty: None,
                    includes_uncommitted: true,
                    ignored_files_excluded: true,
                    default_branch: "main".to_owned(),
                    default_branch_observed: false,
                }),
            },
        ));

        let text = crate::render::agent_work_list_text(&list);
        assert!(text.contains("files working-tree, platform not observed"));
        assert!(text.contains("(undetermined, includes uncommitted files)"));
    }
}
