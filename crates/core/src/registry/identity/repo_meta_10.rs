//! REPO-META-10.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-10",
    statement: "No org-name topic is declared",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[Parameter {
        name: "org-names",
        default: ParameterDefault::Strings(&[]),
    }],
    guidance: "File contents",
    remediation: remediation(
        "remove-org-name-topics",
        "REPO-META-10",
        Lane::DeterministicFile,
        "Remove org-name topics from the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
