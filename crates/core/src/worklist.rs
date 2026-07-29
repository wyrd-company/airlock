//! The agent-lane projection of an audit report.
//!
//! This module does not evaluate a repository. It projects a fresh
//! [`Report`](crate::findings::Report) into the two remediation lanes an agent
//! can act in, while keeping operator-setting gaps and unanswered gating
//! questions visible.

use serde::Serialize;

use crate::findings::{
    AirlockIdentity, AuditedRepository, ObservationRecord, PolicyIdentity, Report, Status,
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

/// One gate-relevant question the audit did not settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsettledItem {
    /// The rule id and stable key for this item.
    pub rule: String,
    /// The undecided status.
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
    /// Outstanding settings changes deferred to the operator.
    pub operator_deferred: WorkGroup<WorkItem>,
    /// Gate-relevant questions the audit could not settle.
    pub unsettled: WorkGroup<UnsettledItem>,
    /// The lane-scoped conclusion.
    pub outcome: Outcome,
}

impl AgentWorkList {
    /// Project an audit report without re-evaluating or caching any finding.
    #[must_use]
    pub fn from_report(report: &Report) -> Self {
        let mut agent = Vec::new();
        let mut operator = Vec::new();
        let mut unsettled = Vec::new();

        for finding in &report.findings {
            if finding.status.is_inconclusive() {
                let severity = crate::registry::Severity::parse(&finding.severity)
                    .unwrap_or(crate::registry::Severity::Observation);
                if report.policy.gate.enforces(severity) {
                    unsettled.push(UnsettledItem {
                        rule: finding.rule.clone(),
                        status: finding.status,
                        severity: finding.severity.clone(),
                        source: finding.source.clone(),
                    });
                }
                continue;
            }

            if finding.status != Status::Fail {
                continue;
            }

            let class = &finding.remediation_class;
            let (Some(lane), Some(code), Some(change)) = (&class.lane, &class.code, &class.change)
            else {
                continue;
            };
            let Some(lane_kind) = Lane::parse(lane) else {
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
                Lane::OperatorSetting => operator.push(item),
            }
        }

        let outcome = if !report.complete {
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
            unsettled: WorkGroup::new(unsettled),
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
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "owner/example".to_owned(),
                id: Some(1),
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            ObservationRecord::api(),
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
    }
}
