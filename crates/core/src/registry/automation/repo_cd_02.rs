//! REPO-CD-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-02",
    statement: "A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*`",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
    params: &[Parameter { name: "tag-pattern", default: ParameterDefault::String("[0-9]*.[0-9]*.[0-9]*") }],
    guidance: "Workflow contents",
    remediation: remediation(
        "add-tag-trigger",
        "REPO-CD-02",
        Lane::DeterministicFile,
        "Trigger CD on tags matching the release tag pattern.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
