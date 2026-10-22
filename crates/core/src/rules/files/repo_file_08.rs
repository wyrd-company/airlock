//! REPO-FILE-08.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-08",
    statement: "`.github/renovate.json` exists and extends the org preset",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[Parameter {
        name: "renovate-preset",
        default: ParameterDefault::String("github>{owner}/.github"),
    }],
    guidance: "File contents",
    fix: fix(
        "add-renovate-config",
        "REPO-FILE-08",
        FixKind::Airlock,
        "Add `.github/renovate.json` extending the org preset.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: true,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
