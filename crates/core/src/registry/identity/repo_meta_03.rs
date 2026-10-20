//! REPO-META-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-03",
    statement: "The description expands any acronym on first use",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Read it",
    remediation: remediation(
        "expand-description-acronyms",
        "REPO-META-03",
        Lane::JudgmentFile,
        "Rewrite the declared description to expand each acronym on first use.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
