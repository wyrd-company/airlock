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
//! fix each rule declares in [`crate::fix`] and pairs it with
//! what the run observed, so that a person can see what closing the gaps would
//! take before anything is done about it.

use crate::findings::{Report, Status};
use crate::fix::FixKind;
use crate::rules::{self, VerificationSurface};

/// One change airlock would make, and the observation that calls for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposedFix<'a> {
    /// The rule whose gap this would close.
    pub rule: &'a str,
    /// The rule's statement, verbatim from the rules.
    pub statement: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// The evaluated Gap that supports this proposed fix.
    pub status: Option<Status>,
    /// The rule's declared fix code — the per-rule join key.
    pub code: &'a str,
    /// What the fix would change.
    pub change: &'a str,
    /// The fix kind it travels in, which is who can apply it and through what
    /// surface.
    pub fix_kind: FixKind,
    /// Whether a later change of mind can undo it.
    pub reversible: bool,
    /// What this particular failure needs, where the run said something more
    /// specific than the rule's standing sentence.
    pub detail: Option<&'a str>,
}

/// A rule whose input could not be evaluated. Every run error blocks completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunErrorRule<'a> {
    /// The rule that could not be decided.
    pub rule: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// No outcome was established.
    pub status: Option<Status>,
    /// Always true for a run error, independent of severity.
    pub blocks_completeness: bool,
}

/// A declared gate names the other surface or implementation that settles this rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedRule<'a> {
    pub reason: &'a str,
    pub settling_surface: &'a str,
    /// The rule that was not evaluated here.
    pub rule: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// What the run said about why it could not be seen, when it said
    /// anything.
    pub detail: Option<&'a str>,
    /// The operator verification surface, for a declared disclosure gate.
    /// Other gates use settling_surface.
    pub verified_by: Option<VerificationSurface>,
}

/// An open gap airlock declares it cannot close, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnclosableGap<'a> {
    /// The rule whose gap is open.
    pub rule: &'a str,
    /// The rule's statement, verbatim from the rules.
    pub statement: &'a str,
    /// The severity the effective policy graded the rule at.
    pub severity: &'a str,
    /// What the run observed.
    pub status: Option<Status>,
    /// Why airlock offers no fix. The only remaining move is a
    /// person's.
    pub reason: &'a str,
}

/// What airlock would change about a repository, as observed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<'a> {
    /// The changes on offer, ordered by fix kind and then by rule id.
    pub proposed: Vec<ProposedFix<'a>>,
    /// Open gaps airlock declares it cannot close.
    pub unclosable: Vec<UnclosableGap<'a>>,
    /// Run errors are visible and prevent a complete audit.
    pub run_errors: Vec<RunErrorRule<'a>>,
    /// Declared routing, unbuilt, and out-of-scope boundaries, with their reasons and destinations.
    pub routed: Vec<RoutedRule<'a>>,
    pub waived: Vec<&'a crate::findings::Finding>,
}

impl<'a> Plan<'a> {
    /// Derive fixes only from evaluated Gaps. Waivers, routed rules, unbuilt
    /// checks, out-of-scope rules, and run errors remain visible without proposing an unobserved fix.
    #[must_use]
    pub fn derive(report: &'a Report) -> Self {
        let mut proposed = Vec::new();
        let mut unclosable = Vec::new();
        let mut run_errors = Vec::new();
        let mut routed = Vec::new();
        let mut waived = Vec::new();

        for finding in report.entries() {
            if finding.suppression.is_some() {
                waived.push(finding);
                continue;
            }
            if let Some(route) = &finding.routing {
                routed.push(RoutedRule {
                    reason: &route.reason,
                    settling_surface: &route.settling_surface,
                    rule: &finding.rule,
                    severity: &finding.severity,
                    detail: finding
                        .evidence
                        .as_ref()
                        .map(|e| e.detail.as_str())
                        .or(Some(&route.settling_surface)),
                    verified_by: rules::find(&finding.rule)
                        .and_then(rules::RuleDefinition::disclosure_gate)
                        .map(|gate| gate.verified_by),
                });
                continue;
            }
            if finding.blocks_completeness() {
                run_errors.push(RunErrorRule {
                    rule: &finding.rule,
                    severity: &finding.severity,
                    status: None,
                    blocks_completeness: true,
                });
                continue;
            }
            if !is_open_gap(finding.status) {
                continue;
            }

            let class = &finding.fix_class;
            match (
                class.code.as_deref(),
                class.change.as_deref(),
                class.fix_kind.as_deref().and_then(FixKind::parse),
                class.reversible,
                class.none_reason.as_deref(),
            ) {
                (Some(code), Some(change), Some(fix_kind), Some(reversible), _) => {
                    proposed.push(ProposedFix {
                        rule: &finding.rule,
                        statement: &finding.statement,
                        severity: &finding.severity,
                        status: finding.status,
                        code,
                        change,
                        fix_kind,
                        reversible,
                        detail: finding.fix.as_ref().map(|fix| fix.detail.as_str()),
                    });
                }
                (_, _, _, _, Some(reason)) => unclosable.push(UnclosableGap {
                    rule: &finding.rule,
                    statement: &finding.statement,
                    severity: &finding.severity,
                    status: finding.status,
                    reason,
                }),
                // A rule the rules do not classify at all. The fix
                // model's coverage test keeps this unreachable for registered
                // rules, so there is nothing truthful to say about it here.
                _ => {}
            }
        }

        proposed.sort_by(|left, right| {
            kind_order(left.fix_kind)
                .cmp(&kind_order(right.fix_kind))
                .then_with(|| left.rule.cmp(right.rule))
        });
        unclosable.sort_by(|left, right| left.rule.cmp(right.rule));
        routed.sort_by(|left, right| left.rule.cmp(right.rule));

        Self {
            proposed,
            unclosable,
            run_errors,
            routed,
            waived,
        }
    }

    /// Whether an run_errors rule leaves the run incomplete.
    ///
    /// Derived from the same per-finding predicate the audit assembles a
    /// report with, so a plan and the report it came from cannot disagree —
    /// and so a plan cannot contradict the rules it just printed.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        self.run_errors.iter().any(|rule| rule.blocks_completeness)
    }

    /// The proposed changes in one fix kind, in plan order.
    pub fn of_kind(&self, fix_kind: FixKind) -> impl Iterator<Item = &ProposedFix<'a>> {
        self.proposed
            .iter()
            .filter(move |change| change.fix_kind == fix_kind)
    }

    /// Whether the plan proposes nothing and declares nothing unclosable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty() && self.unclosable.is_empty()
    }
}

/// Only an evaluated Gap supports a proposed fix.
const fn is_open_gap(status: Option<Status>) -> bool {
    matches!(status, Some(Status::Gap))
}

/// The lanes in display order, most actionable first: what an operator can
/// close in this session, then what airlock can author on its own, then what
/// needs an author's judgment.
pub const DISPLAY_ORDER: &[FixKind] = &[FixKind::Operator, FixKind::Airlock, FixKind::Agent];

/// Where a fix kind sits in [`DISPLAY_ORDER`].
const fn kind_order(fix_kind: FixKind) -> u8 {
    match fix_kind {
        FixKind::Operator => 0,
        FixKind::Airlock => 1,
        FixKind::Agent => 2,
    }
}

/// What each fix kind means, in one line, for a reader deciding what to do next.
#[must_use]
pub const fn kind_gloss(fix_kind: FixKind) -> &'static str {
    match fix_kind {
        FixKind::Operator => {
            "a repository or organisation setting, applied directly in the interactive session"
        }
        FixKind::Airlock => "a file change airlock can author, delivered as a pull request",
        FixKind::Agent => {
            "a file change an agent authors and a person reviews, delivered as a pull request"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        AirlockIdentity, AuditedRepository, Finding, Fix, FixClass, ObservationRecord,
        PolicyIdentity,
    };
    use crate::FixGroup;

    fn finding(rule: &str, status: Option<Status>) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: format!("{rule} holds"),
            severity: "blocking".to_owned(),
            status,
            evidence: None,
            fix: None,
            fix_class: FixClass::for_rule(rule),
            suppression: None,
            source: Some("api".to_owned()),
            error: None,
            routing: None,
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
            },
            Vec::new(),
            Vec::new(),
            findings,
        )
    }

    #[test]
    fn a_failing_rule_proposes_the_change_its_rule_declares() {
        let report = report(vec![finding("REPO-GIT-04", Some(Status::Gap))]);
        let plan = Plan::derive(&report);

        assert_eq!(plan.proposed.len(), 1);
        let change = plan.proposed[0];
        assert_eq!(change.rule, "REPO-GIT-04");
        assert_eq!(change.code, "disable-merge-commits");
        assert_eq!(change.fix_kind, FixKind::Operator);
        assert!(change.reversible);
        assert!(change
            .change
            .contains("Disable merge commits in the live repository settings"));
    }

    #[test]
    fn a_passing_rule_proposes_nothing() {
        let report = report(vec![finding("REPO-GIT-04", Some(Status::Met))]);
        assert!(Plan::derive(&report).is_empty());
    }

    #[test]
    fn a_waiver_does_not_propose_a_fix_without_an_observed_gap() {
        let report = report(vec![crate::findings::fixtures::waived(finding(
            "REPO-GIT-04",
            None,
        ))]);
        assert!(Plan::derive(&report).proposed.is_empty());
        assert_eq!(report.waived.len(), 1);
    }

    #[test]
    fn a_rule_declaring_no_fix_is_reported_as_unclosable_with_its_reason() {
        let report = report(vec![finding("REPO-GIT-08", Some(Status::Gap))]);
        let plan = Plan::derive(&report);

        assert!(plan.proposed.is_empty());
        assert_eq!(plan.unclosable.len(), 1);
        assert_eq!(plan.unclosable[0].rule, "REPO-GIT-08");
        assert!(plan.unclosable[0].reason.contains("history surgery"));
    }

    #[test]
    fn an_undecided_rule_proposes_nothing_and_is_named() {
        for status in [None, None, None] {
            let report = report(vec![finding("REPO-GIT-04", status)]);
            let plan = Plan::derive(&report);
            assert!(plan.is_empty(), "{status:?} proposed a change");
            assert_eq!(plan.run_errors.len(), 1, "{status:?}");
            assert_eq!(plan.run_errors[0].rule, "REPO-GIT-04", "{status:?}");
            assert_eq!(plan.run_errors[0].status, status);
            assert!(
                plan.run_errors[0].blocks_completeness,
                "{status:?} at blocking severity under a blocking gate stops the run"
            );
        }
    }

    #[test]
    fn an_advisory_run_error_is_named_and_blocks_completeness() {
        let mut error = finding("REPO-GIT-04", None);
        error.severity = "advisory".to_owned();
        let report = report(vec![error]);
        let plan = Plan::derive(&report);
        assert!(plan.is_incomplete());
        assert!(!report.complete);
        assert_eq!(plan.run_errors.len(), 1);
    }

    #[test]
    fn an_admin_only_rule_is_named_separately_and_does_not_gate() {
        let mut routed = crate::findings::fixtures::routed(finding("REPO-GIT-04", None));
        routed.evidence = Some(crate::findings::Evidence::new(
            "merge_settings_unavailable",
            "the merge-commit setting cannot be verified with this credential",
        ));
        let report = report(vec![routed]);
        let plan = Plan::derive(&report);

        assert!(
            plan.proposed.is_empty(),
            "there is no observed gap to close"
        );
        assert!(
            plan.run_errors.is_empty(),
            "a rule no retry here can answer is not filed with the ones a retry could"
        );
        assert_eq!(plan.routed.len(), 1);
        assert_eq!(plan.routed[0].rule, "REPO-GIT-04");
        assert!(plan.routed[0]
            .detail
            .expect("the run said why")
            .contains("this credential"));
        assert!(
            !plan.is_incomplete(),
            "the surface working as mandated does not make the run incomplete"
        );
        assert_eq!(
            report.complete,
            !plan.is_incomplete(),
            "the plan and the report it came from must agree about the gate"
        );
    }

    #[test]
    fn changes_are_ordered_by_lane_then_rule() {
        let report = report(vec![
            finding("REPO-FILE-04", Some(Status::Gap)),
            finding("REPO-GIT-05", Some(Status::Gap)),
            finding("REPO-FILE-01", Some(Status::Gap)),
            finding("REPO-GIT-04", Some(Status::Gap)),
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
        let mut open = finding("REPO-GIT-04", Some(Status::Gap));
        open.fix = Some(Fix::new(
            FixGroup::CORRECT_MERGE_SETTINGS,
            "Merge commits are enabled.",
        ));
        let report = report(vec![open]);
        let plan = Plan::derive(&report);

        assert_eq!(plan.proposed[0].detail, Some("Merge commits are enabled."));
    }

    #[test]
    fn of_kind_selects_only_that_lane() {
        let report = report(vec![
            finding("REPO-GIT-04", Some(Status::Gap)),
            finding("REPO-FILE-04", Some(Status::Gap)),
        ]);
        let plan = Plan::derive(&report);

        let settings: Vec<&str> = plan
            .of_kind(FixKind::Operator)
            .map(|change| change.rule)
            .collect();
        assert_eq!(settings, vec!["REPO-GIT-04"]);
    }

    #[test]
    fn every_lane_has_a_gloss() {
        for fix_kind in FixKind::ALL {
            assert!(
                !kind_gloss(*fix_kind).trim().is_empty(),
                "{}",
                fix_kind.code()
            );
        }
    }

    #[test]
    fn the_display_order_covers_every_lane_and_agrees_with_the_sort() {
        assert_eq!(DISPLAY_ORDER.len(), FixKind::ALL.len());
        for fix_kind in FixKind::ALL {
            assert!(DISPLAY_ORDER.contains(fix_kind), "{}", fix_kind.code());
        }
        for (position, fix_kind) in DISPLAY_ORDER.iter().enumerate() {
            assert_eq!(
                usize::from(kind_order(*fix_kind)),
                position,
                "{}",
                fix_kind.code()
            );
        }
    }
}
