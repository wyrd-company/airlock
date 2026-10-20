//! REPO-META-10.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-10",
    statement: "No org-name topic is declared",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[Parameter {
        name: "org-names",
        default: ParameterDefault::Strings(&[]),
    }],
    guidance: "File contents",
    fix: fix(
        "remove-org-name-topics",
        "REPO-META-10",
        FixKind::Airlock,
        "Remove org-name topics from the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
