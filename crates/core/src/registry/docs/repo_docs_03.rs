//! REPO-DOCS-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-03",
    statement: "Artifact filenames are lower-kebab slugs with no type prefix and no `id:` field",
    severity: Severity::Observation,
    section: Section::Docs,
    evaluation: Evaluation::Manual,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
