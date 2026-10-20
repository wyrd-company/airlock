//! REPO-META-06.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Parameter, ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
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
    remediation: remediation(
        "adjust-topic-count",
        "REPO-META-06",
        Lane::JudgmentFile,
        "Add or remove declared topics to land within the required count.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
