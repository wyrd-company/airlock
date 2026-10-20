//! REPO-NAME-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-NAME-01",
    statement: "The name is `lower-kebab-case`; no underscores, camelCase, or PascalCase",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Repository name",
    remediation: remediation(
        "rename-repository-kebab",
        "REPO-NAME-01",
        Lane::OperatorSetting,
        "Rename the repository to lower-kebab-case.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
