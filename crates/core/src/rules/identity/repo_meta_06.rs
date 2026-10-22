//! REPO-META-06.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-06",
    statement: "Between three and eight topics are declared",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[
        Parameter {
            name: "min-topics",
            default: ParameterDefault::Integer(3),
        },
        Parameter {
            name: "max-topics",
            default: ParameterDefault::Integer(8),
        },
    ],
    guidance: "File contents",
    fix: fix(
        "adjust-topic-count",
        "REPO-META-06",
        FixKind::Agent,
        "Add or remove declared topics to land within the required count.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
