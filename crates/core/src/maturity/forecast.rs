//! Prospective evaluations from the same captured audit inputs.
//
// relationships:
//   references: maturity

use super::Observed;
use crate::checks::{self, AuditContext};
use crate::findings::{Finding, Status};
use crate::rules::{CredentialCapability, Lifecycle, Severity};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MaturityReport {
    pub observed: Option<Observed>,
    pub error: Option<String>,
    pub transitions: Vec<Transition>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Transition {
    pub rung: Lifecycle,
    pub adds: usize,
    pub already_met: usize,
    pub rules: Vec<TransitionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TransitionRule {
    pub rule: String,
    pub outcome: String,
    pub new: bool,
}

pub(crate) fn report(
    context: &AuditContext,
    findings: &[Finding],
    api_observed: bool,
) -> MaturityReport {
    let observed = match &context.maturity {
        Ok(observed) => observed,
        Err(error) => {
            return MaturityReport {
                observed: None,
                error: Some(error.detail()),
                transitions: Vec::new(),
            }
        }
    };
    let mut transitions = Vec::new();
    for &rung in Lifecycle::ALL.iter().filter(|&&rung| rung > observed.rung) {
        let mut future = context.clone();
        future.maturity = Ok(Observed {
            rung,
            ..observed.clone()
        });
        let mut rules = Vec::new();
        let mut already_met = 0;
        for rule in &context.policy.rules {
            if rule.def.lifecycle <= observed.rung
                || rule.severity == Severity::None
                || findings
                    .iter()
                    .any(|finding| finding.rule == rule.def.id && finding.suppression.is_some())
            {
                continue;
            }
            let verdict = match checks::applicability(rule, &future) {
                Err(boundary)
                    if boundary
                        .routing
                        .as_ref()
                        .is_some_and(|route| route.reason == "out-of-scope") =>
                {
                    continue
                }
                Err(boundary) => *boundary,
                Ok(())
                    if rule.def.needs_github_api()
                        && (!api_observed
                            || (rule.def.id == "REPO-TPL-01"
                                && context.credential
                                    == CredentialCapability::Unauthenticated)) =>
                {
                    checks::Verdict::needs_github_api()
                }
                Ok(()) => checks::evaluate(rule, &future),
            };
            already_met += usize::from(verdict.status == Some(Status::Met));
            let outcome = verdict
                .status
                .map(|status| status.code().to_owned())
                .or_else(|| verdict.routing.map(|routing| routing.reason))
                .unwrap_or_else(|| "run-error".to_owned());
            rules.push(TransitionRule {
                rule: rule.def.id.to_owned(),
                outcome,
                new: semver::Version::parse(rule.def.since).expect("compiled since is valid")
                    > context.policy.accepted_version,
            });
        }
        transitions.push(Transition {
            rung,
            adds: rules.len(),
            already_met,
            rules,
        });
    }
    MaturityReport {
        observed: Some(observed.clone()),
        error: None,
        transitions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixtures;

    #[test]
    fn crossing_a_rung_counts_only_added_rules_and_observed_passes() {
        let snapshot = fixtures::snapshot(&[("README.md", "# Sample\n")]);
        let mut policy = fixtures::policy();
        for (id, rung) in [
            ("REPO-FILE-01", Lifecycle::Building),
            ("REPO-FILE-02", Lifecycle::Released),
        ] {
            let mut rule = fixtures::rule(id);
            let mut definition = *rule.def;
            definition.lifecycle = rung;
            rule.def = Box::leak(Box::new(definition));
            policy.rules.push(rule);
        }
        policy.rules.push(fixtures::rule("REPO-GIT-01"));
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.maturity.as_mut().unwrap().rung = Lifecycle::Seeded;
        let forecast = report(&context, &[], true);
        assert_eq!(forecast.transitions[0].rung, Lifecycle::Building);
        assert_eq!(forecast.transitions[0].adds, 1);
        assert_eq!(forecast.transitions[0].already_met, 1);
        assert_eq!(forecast.transitions[1].adds, 2);
        assert_eq!(forecast.transitions[1].already_met, 1);
        assert_eq!(forecast.transitions[1].rules[1].outcome, "gap");
        assert_eq!(context.maturity.unwrap().rung, Lifecycle::Seeded);
    }

    #[test]
    fn prospective_rules_retain_accepted_generation_metadata() {
        let snapshot = fixtures::snapshot(&[]);
        let mut policy = fixtures::policy();
        policy.rules.push(fixtures::rule("REPO-REL-08"));
        policy.accepted_version = semver::Version::new(0, 5, 0);
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.maturity.as_mut().unwrap().rung = Lifecycle::Building;
        assert!(report(&context, &[], false).transitions[0].rules[0].new);
        policy.accepted_version = crate::policy::current_generation();
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.maturity.as_mut().unwrap().rung = Lifecycle::Building;
        assert!(!report(&context, &[], false).transitions[0].rules[0].new);
    }

    #[test]
    fn future_scope_and_waivers_do_not_inflate_added_rules() {
        let snapshot = fixtures::snapshot(&[]);
        let mut policy = fixtures::policy();
        policy.rules = vec![fixtures::rule("REPO-TPL-01"), fixtures::rule("REPO-REL-08")];
        policy.rules[1].severity = Severity::None;
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.maturity.as_mut().unwrap().rung = Lifecycle::Seeded;
        let forecast = report(&context, &[], false);
        assert!(forecast
            .transitions
            .iter()
            .all(|transition| transition.adds == 0));
    }

    #[test]
    fn future_missing_api_is_routed_without_claiming_a_pass() {
        let snapshot = fixtures::snapshot(&[]);
        let mut policy = fixtures::policy();
        policy.rules.push(fixtures::rule("REPO-REL-08"));
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.maturity.as_mut().unwrap().rung = Lifecycle::Building;
        let forecast = report(&context, &[], false);
        assert_eq!(forecast.transitions[0].adds, 1);
        assert_eq!(forecast.transitions[0].already_met, 0);
        assert_eq!(forecast.transitions[0].rules[0].outcome, "needs-github-api");
    }
}
