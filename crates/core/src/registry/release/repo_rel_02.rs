//! REPO-REL-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-02",
    statement: "A `CHANGELOG.md` exists at each release unit's declared path",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "Compare against `.intentional/config.yml`",
    remediation: remediation(
        "add-unit-changelogs",
        "REPO-REL-02",
        Lane::DeterministicFile,
        "Add a `CHANGELOG.md` skeleton at each release unit's declared path.",
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
