//! REPO-GIT-08.
//
// relationships:
//   references: rules

use crate::fix::not_fixable;
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-08",
    statement: "Tags carry no `v` prefix",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "`git tag`",
    fix: not_fixable(
        "REPO-GIT-08",
        "Closing it means deleting and recreating published tags — history surgery airlock does not automate.",
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
