//! REPO-DOCS-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-DOCS-03",
    statement: "Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "File inspection",
    fix: fix(
        "rename-artifact-files",
        "REPO-DOCS-03",
        FixKind::Agent,
        "Rename artifact files to lower-kebab slugs without type prefixes or `id:` fields.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
