//! REPO-REL-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-05",
    statement: "The release workflow asserts the pinned SHA equals current `main`",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-sha-is-main",
        "REPO-REL-05",
        Lane::JudgmentFile,
        "Assert in the release workflow that the pinned SHA equals current `main`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
