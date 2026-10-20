//! REPO-META-10.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Parameter, ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-10",
    statement: "No org-name topic is declared",
    severity: Severity::Advisory,
    section: Section::Identity,
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
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
