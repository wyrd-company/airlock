//! REPO-META-07.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-07",
    statement: "Topics include at least one artifact-type and one ecosystem term",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: remediation(
        "add-artifact-and-ecosystem-topics",
        "REPO-META-07",
        Lane::JudgmentFile,
        "Add an artifact-type and an ecosystem term to the declared topics.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
