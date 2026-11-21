//! REPO-META-07.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-07",
    statement: "Topics include at least one artifact-type and one ecosystem term",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[Parameter {
        name: "topics",
        default: ParameterDefault::Required,
    }],
    guidance: "Compare against `topics.md`",
    fix: fix(
        "add-artifact-and-ecosystem-topics",
        "REPO-META-07",
        FixKind::Agent,
        "Add an artifact-type and an ecosystem term to the declared topics.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: Some(&["artifact-type", "ecosystem"]),
    disclosure_gate: None,
    unbuilt_reason: None,
};
