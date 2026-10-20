//! REPO-META-09.
//
// relationships:
//   references: rules

use crate::fix::not_fixable;
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-09",
    statement: "Any topic not in `topics.md` has been added to it",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[Parameter { name: "topics", default: ParameterDefault::Required }],
    guidance: "Compare against `topics.md`",
    fix: not_fixable(
        "REPO-META-09",
        "The fix is an edit to the organisation's topic list, which lives outside the audited repository.",
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: Some(&[]),
    disclosure_gate: None,
    unbuilt_reason: None,
};
