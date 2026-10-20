//! REPO-DOCS-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-03",
    statement: "Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "File inspection",
    remediation: remediation(
        "rename-artifact-files",
        "REPO-DOCS-03",
        Lane::JudgmentFile,
        "Rename artifact files to lower-kebab slugs without type prefixes or `id:` fields.",
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
