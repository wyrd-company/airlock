//! REPO-REL-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-04",
    statement: "Release is `workflow_dispatch` on a pinned source SHA",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "redesign-release-trigger",
        "REPO-REL-04",
        Lane::JudgmentFile,
        "Make release a `workflow_dispatch` on a pinned source SHA.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
