//! REPO-FILE-08.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Parameter, ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-08",
    statement: "`.github/renovate.json` exists and extends the org preset",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[Parameter {
        name: "renovate-preset",
        default: ParameterDefault::String("github>{owner}/.github"),
    }],
    guidance: "File contents",
    remediation: remediation(
        "add-renovate-config",
        "REPO-FILE-08",
        Lane::DeterministicFile,
        "Add `.github/renovate.json` extending the org preset.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: true,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
