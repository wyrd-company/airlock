//! REPO-GIT-10.
//
// relationships:
//   references: rules

use crate::fix::not_fixable;
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

/// The default history scan budget.
pub(crate) const DEFAULT_MAX_COMMITS: usize = 1_000;

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-10",
    statement: "History contains no merge commits",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[Parameter {
        name: "max-commits",
        default: ParameterDefault::Integer(DEFAULT_MAX_COMMITS as u64),
    }],
    guidance: "`git log --merges`",
    fix: not_fixable(
        "REPO-GIT-10",
        "Closing it means rewriting published history, which airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
