//! REPO-TASK-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-TASK-06",
    statement: "Include namespaces match release unit ids",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Compare against `.intentional/config.yml`",
    remediation: remediation(
        "align-include-namespaces",
        "REPO-TASK-06",
        Lane::DeterministicFile,
        "Rename include namespaces to match release unit ids.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
