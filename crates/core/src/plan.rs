//! The plan: what airlock would change, derived from one observation.
//!
//! A plan is a *display*. It is computed from a report that has just been
//! observed, it is rendered, and it is discarded. Nothing consumes a plan as
//! input: aligning re-observes the rule it is about to close and decides from
//! what it then sees, never from a proposal computed earlier. A stored plan
//! would be a remembered observation wearing a different name, and airlock
//! never acts on a remembered observation.
//!
//! Deriving a plan is therefore pure and read-only. This module holds no
//! credential, reaches no endpoint, and has no path to one. It reads the
//! remediation each rule declares in [`crate::remediation`] and pairs it with
//! what the run observed, so that a person can see what closing the gaps would
//! take before anything is done about it.

use crate::findings::{Report, Status};
use crate::remediation::Lane;

/// One change airlock would make, and the observation that calls for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposedChange<'a> {
    /// The rule whose gap this would close.
    pub rule: &'a str,
    /// The rule's statement, verbatim from the registry.
    pub statement: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// What the run observed. Always an open gap: `fail`, or `suppressed`.
    pub status: Status,
    /// The rule's declared remediation code — the per-rule join key.
    pub code: &'a str,
    /// What the remediation would change.
    pub change: &'a str,
    /// The lane it travels in, which is who can apply it and through what
    /// surface.
    pub lane: Lane,
    /// Whether a later change of mind can undo it.
    pub reversible: bool,
    /// This failure is one the policy authorized. The authorization did not
    /// close the gap, so the change is still on offer, and it is standing debt
    /// rather than a fresh failure.
    pub authorized: bool,
    /// What this particular failure needs, where the run said something more
    /// specific than the rule's standing sentence.
    pub detail: Option<&'a str>,
}

/// An open gap airlock declares it cannot close, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnclosableGap<'a> {
    /// The rule whose gap is open.
    pub rule: &'a str,
    /// The rule's statement, verbatim from the registry.
    pub statement: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// What the run observed.
    pub status: Status,
    /// Why airlock offers no remediation. The only remaining move is a
    /// person's.
    pub reason: &'a str,
}

/// What airlock would change about a repository, as observed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<'a> {
    /// The changes on offer, ordered by lane and then by rule id.
    pub proposed: Vec<ProposedChange<'a>>,
    /// Open gaps airlock declares it cannot close.
    pub unclosable: Vec<UnclosableGap<'a>>,
    /// Whether the observation the plan is derived from was complete. An
    /// incomplete run leaves rules undecided, and an undecided rule may be
    /// hiding a change this plan does not name.
    pub complete: bool,
    /// Rules at a gating severity that ended undecided, so nothing can be
    /// concluded about them.
    pub undecided: Vec<&'a str>,
}

impl<'a> Plan<'a> {
    /// Derive the plan a report implies.
    ///
    /// A finding contributes a proposed change when it names an open gap —
    /// `fail`, or `suppressed`, which is an authorized failure whose gap is
    /// still open — and its rule declares a remediation. A finding whose rule
    /// declares no remediation contributes an unclosable gap instead, carrying
    /// the declared reason.
    ///
    /// Nothing else contributes. A `pass` has no gap; an undecided rule has no
    /// established gap to propose a change for, and proposing one would be
    /// acting on a question rather than an observation. Undecided rules are
    /// reported separately so the plan can say what it could not see.
    #[must_use]
    pub fn derive(report: &'a Report) -> Self {
        let mut proposed = Vec::new();
        let mut unclosable = Vec::new();
        let mut undecided = Vec::new();

        for finding in &report.findings {
            if finding.status.is_inconclusive() {
                undecided.push(finding.rule.as_str());
                continue;
            }
            if !is_open_gap(finding.status) {
                continue;
            }

            let class = &finding.remediation_class;
            match (
                class.code.as_deref(),
                class.change.as_deref(),
                class.lane.as_deref().and_then(Lane::parse),
                class.reversible,
                class.none_reason.as_deref(),
            ) {
                (Some(code), Some(change), Some(lane), Some(reversible), _) => {
                    proposed.push(ProposedChange {
                        rule: &finding.rule,
                        statement: &finding.statement,
                        severity: &finding.severity,
                        status: finding.status,
                        code,
                        change,
                        lane,
                        reversible,
                        authorized: finding.status == Status::Suppressed,
                        detail: finding
                            .remediation
                            .as_ref()
                            .map(|remediation| remediation.detail.as_str()),
                    });
                }
                (_, _, _, _, Some(reason)) => unclosable.push(UnclosableGap {
                    rule: &finding.rule,
                    statement: &finding.statement,
                    severity: &finding.severity,
                    status: finding.status,
                    reason,
                }),
                // A rule the registry does not classify at all. The remediation
                // model's coverage test keeps this unreachable for registered
                // rules, so there is nothing truthful to say about it here.
                _ => {}
            }
        }

        proposed.sort_by(|left, right| {
            lane_order(left.lane)
                .cmp(&lane_order(right.lane))
                .then_with(|| left.rule.cmp(right.rule))
        });
        unclosable.sort_by(|left, right| left.rule.cmp(right.rule));

        Self {
            proposed,
            unclosable,
            complete: report.complete,
            undecided,
        }
    }

    /// The proposed changes in one lane, in plan order.
    pub fn in_lane(&self, lane: Lane) -> impl Iterator<Item = &ProposedChange<'a>> {
        self.proposed
            .iter()
            .filter(move |change| change.lane == lane)
    }

    /// Whether the plan proposes nothing and declares nothing unclosable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty() && self.unclosable.is_empty()
    }
}

/// Whether a status names a gap that is open.
///
/// `suppressed` counts: the policy authorized the failure, which permitted it
/// without closing it. Folding an authorized failure in with the passes would
/// hide standing debt.
const fn is_open_gap(status: Status) -> bool {
    matches!(status, Status::Fail | Status::Suppressed)
}

/// The lanes in display order, most actionable first: what an operator can
/// close in this session, then what airlock can author on its own, then what
/// needs an author's judgment.
pub const DISPLAY_ORDER: &[Lane] = &[
    Lane::OperatorSetting,
    Lane::DeterministicFile,
    Lane::JudgmentFile,
];

/// Where a lane sits in [`DISPLAY_ORDER`].
const fn lane_order(lane: Lane) -> u8 {
    match lane {
        Lane::OperatorSetting => 0,
        Lane::DeterministicFile => 1,
        Lane::JudgmentFile => 2,
    }
}

/// What each lane means, in one line, for a reader deciding what to do next.
#[must_use]
pub const fn lane_gloss(lane: Lane) -> &'static str {
    match lane {
        Lane::OperatorSetting => {
            "a repository or organisation setting, applied directly in the interactive session"
        }
        Lane::DeterministicFile => "a file change airlock can author, delivered as a pull request",
        Lane::JudgmentFile => {
            "a file change an agent authors and a person reviews, delivered as a pull request"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        AirlockIdentity, AuditedRepository, Finding, Gate, ObservationRecord, PolicyIdentity,
        Remediation, RemediationClass, Suppression, SuppressionSource,
    };
    use crate::ActionGroup;

    fn finding(rule: &str, status: Status) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: format!("{rule} holds"),
            severity: "blocking".to_owned(),
            status,
            evidence: None,
            remediation: None,
            remediation_class: RemediationClass::for_rule(rule),
            suppression: None,
            source: Some("api".to_owned()),
            error: None,
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
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
                bundle_digest: format!("sha256:{}", "b".repeat(64)),
                gate: Gate::Blocking,
            },
            Vec::new(),
            Vec::new(),
            findings,
        )
    }

    #[test]
    fn a_failing_rule_proposes_the_change_its_rule_declares() {
        let report = report(vec![finding("REPO-GIT-04", Status::Fail)]);
        let plan = Plan::derive(&report);

        assert_eq!(plan.proposed.len(), 1);
        let change = plan.proposed[0];
        assert_eq!(change.rule, "REPO-GIT-04");
        assert_eq!(change.code, "disable-merge-commits");
        assert_eq!(change.lane, Lane::OperatorSetting);
        assert!(change.reversible);
        assert!(!change.authorized);
        assert!(change
            .change
            .contains("Disable merge commits in the live repository settings"));
    }

    #[test]
    fn a_passing_rule_proposes_nothing() {
        let report = report(vec![finding("REPO-GIT-04", Status::Pass)]);
        assert!(Plan::derive(&report).is_empty());
    }

    #[test]
    fn an_authorized_failure_keeps_its_change_on_offer_and_is_marked() {
        let mut open = finding("REPO-GIT-04", Status::Suppressed);
        open.suppression = Some(Suppression {
            source: SuppressionSource::Policy,
            requested_reason: None,
            policy_reason: Some("not yet".to_owned()),
            authorized_by: "policy".to_owned(),
        });
        let report = report(vec![open]);
        let plan = Plan::derive(&report);

        assert_eq!(plan.proposed.len(), 1);
        assert!(plan.proposed[0].authorized);
        assert_eq!(plan.proposed[0].code, "disable-merge-commits");
    }

    #[test]
    fn a_rule_declaring_no_remediation_is_reported_as_unclosable_with_its_reason() {
        let report = report(vec![finding("REPO-GIT-08", Status::Fail)]);
        let plan = Plan::derive(&report);

        assert!(plan.proposed.is_empty());
        assert_eq!(plan.unclosable.len(), 1);
        assert_eq!(plan.unclosable[0].rule, "REPO-GIT-08");
        assert!(plan.unclosable[0].reason.contains("history surgery"));
    }

    #[test]
    fn an_undecided_rule_proposes_nothing_and_is_named() {
        for status in [Status::Inconclusive, Status::Unimplemented, Status::Error] {
            let report = report(vec![finding("REPO-GIT-04", status)]);
            let plan = Plan::derive(&report);
            assert!(plan.is_empty(), "{status:?} proposed a change");
            assert_eq!(plan.undecided, vec!["REPO-GIT-04"], "{status:?}");
        }
    }

    #[test]
    fn changes_are_ordered_by_lane_then_rule() {
        let report = report(vec![
            finding("REPO-FILE-04", Status::Fail),
            finding("REPO-GIT-05", Status::Fail),
            finding("REPO-FILE-01", Status::Fail),
            finding("REPO-GIT-04", Status::Fail),
        ]);
        let plan = Plan::derive(&report);

        let order: Vec<&str> = plan.proposed.iter().map(|change| change.rule).collect();
        assert_eq!(
            order,
            vec!["REPO-GIT-04", "REPO-GIT-05", "REPO-FILE-04", "REPO-FILE-01"]
        );
    }

    #[test]
    fn the_contextual_detail_is_carried_when_the_run_gave_one() {
        let mut open = finding("REPO-GIT-04", Status::Fail);
        open.remediation = Some(Remediation::new(
            ActionGroup::CORRECT_MERGE_SETTINGS,
            "Merge commits are enabled.",
        ));
        let report = report(vec![open]);
        let plan = Plan::derive(&report);

        assert_eq!(plan.proposed[0].detail, Some("Merge commits are enabled."));
    }

    #[test]
    fn in_lane_selects_only_that_lane() {
        let report = report(vec![
            finding("REPO-GIT-04", Status::Fail),
            finding("REPO-FILE-04", Status::Fail),
        ]);
        let plan = Plan::derive(&report);

        let settings: Vec<&str> = plan
            .in_lane(Lane::OperatorSetting)
            .map(|change| change.rule)
            .collect();
        assert_eq!(settings, vec!["REPO-GIT-04"]);
    }

    #[test]
    fn every_lane_has_a_gloss() {
        for lane in Lane::ALL {
            assert!(!lane_gloss(*lane).trim().is_empty(), "{}", lane.code());
        }
    }

    #[test]
    fn the_display_order_covers_every_lane_and_agrees_with_the_sort() {
        assert_eq!(DISPLAY_ORDER.len(), Lane::ALL.len());
        for lane in Lane::ALL {
            assert!(DISPLAY_ORDER.contains(lane), "{}", lane.code());
        }
        for (position, lane) in DISPLAY_ORDER.iter().enumerate() {
            assert_eq!(usize::from(lane_order(*lane)), position, "{}", lane.code());
        }
    }
}
