//! REPO-AGENT-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-01",
    statement: "`AGENTS.md` covers what the repository is, commands by reference, repository-specific conventions, what not to touch, and where docs live",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "write-agents-coverage",
        "REPO-AGENT-01",
        Lane::JudgmentFile,
        "Cover in `AGENTS.md` what the repository is, commands by reference, conventions, what not to touch, and where docs live.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
