//! REPO-CD-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-01",
    statement: "A repository that delivers anything has `.github/workflows/cd.yml`",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-cd-workflow",
        "REPO-CD-01",
        Lane::JudgmentFile,
        "Add a `.github/workflows/cd.yml` delivering what this repository ships.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
