//! REPO-DOCS-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-04",
    statement: "A tool publishing docs to `wyrd.foo` has `docs/docs.yml`",
    severity: Severity::Required,
    section: Section::Docs,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "File presence plus the recorded decision",
    remediation: remediation(
        "add-docs-manifest",
        "REPO-DOCS-04",
        Lane::JudgmentFile,
        "Add `docs/docs.yml` for publication to `wyrd.foo`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
