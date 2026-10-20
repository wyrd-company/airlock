//! REPO-FILE-08.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-08",
    statement: "`.github/renovate.json` exists and extends the org preset",
    severity: Severity::Required,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
