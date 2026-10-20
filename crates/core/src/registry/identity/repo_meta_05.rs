//! REPO-META-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-05",
    statement: "The description agrees with the README's opening line",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare",
    remediation: remediation(
        "align-description-and-readme",
        "REPO-META-05",
        Lane::JudgmentFile,
        "Align the declared description with the README's opening line.",
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
