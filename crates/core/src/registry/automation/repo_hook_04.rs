//! REPO-HOOK-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-04",
    statement: "Hooks invoke tasks rather than raw commands",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "invoke-tasks-from-hooks",
        "REPO-HOOK-04",
        Lane::JudgmentFile,
        "Point hooks at tasks instead of raw commands.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
