//! REPO-AGENT-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-02",
    statement: "`AGENTS.md` contains nothing discoverable by reading the repository",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "remove-discoverable-agents-content",
        "REPO-AGENT-02",
        Lane::JudgmentFile,
        "Remove from `AGENTS.md` anything discoverable by reading the repository.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
