//! REPO-META-06.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-06",
    statement: "Between three and eight topics are declared",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
