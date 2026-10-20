//! REPO-AGENT-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-03",
    statement: "`AGENTS.md` does not restate the README or `CONTRIBUTING.md`",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Compare",
    remediation: remediation(
        "deduplicate-agents-content",
        "REPO-AGENT-03",
        Lane::JudgmentFile,
        "Remove `AGENTS.md` content that restates the README or `CONTRIBUTING.md`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
