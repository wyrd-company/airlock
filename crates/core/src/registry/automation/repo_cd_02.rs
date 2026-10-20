//! REPO-CD-02.
//
// relationships:
//   references: registry

use crate::registry::{
    CheckDefinition, Lifecycle, Observation, Parameter, ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-02",
    statement: "A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*`",
    severity: Severity::Advisory,
    section: Section::Automation,
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
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
