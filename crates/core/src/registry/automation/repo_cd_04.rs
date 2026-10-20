//! REPO-CD-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-04",
    statement: "CD sets `concurrency` with `cancel-in-progress: false`",
    severity: Severity::Blocking,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "set-cd-concurrency",
        "REPO-CD-04",
        Lane::DeterministicFile,
        "Set CD `concurrency` with `cancel-in-progress: false`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
