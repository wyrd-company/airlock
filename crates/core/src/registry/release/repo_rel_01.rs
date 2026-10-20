//! REPO-REL-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-01",
    statement: "`.intentional/config.yml` exists and declares release units",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "declare-release-units",
        "REPO-REL-01",
        Lane::JudgmentFile,
        "Add `.intentional/config.yml` declaring this repository's release units.",
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
