//! REPO-META-09.
//
// relationships:
//   references: rules

use crate::fix::not_fixable;
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-09",
    statement: "Any topic not in `topics.md` has been added to it",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare against `topics.md`",
    fix: not_fixable(
        "REPO-META-09",
        "The fix is an edit to the organisation's topic rules, which lives outside the audited repository.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: Some(&[]),
    disclosure_gate: None,
    unbuilt_reason: None,
};
