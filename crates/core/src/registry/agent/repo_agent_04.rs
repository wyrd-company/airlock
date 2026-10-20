//! REPO-AGENT-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-AGENT-04",
    statement: "`CONTRIBUTING.md` contains no command sequences beyond `task check`",
    severity: Severity::Advisory,
    section: Section::Agent,
    params: &[],
    guidance: "Read",
    remediation: remediation(
        "trim-contributing-commands",
        "REPO-AGENT-04",
        Lane::JudgmentFile,
        "Trim `CONTRIBUTING.md` command sequences down to `task check`.",
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
