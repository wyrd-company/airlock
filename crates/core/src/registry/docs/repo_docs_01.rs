//! REPO-DOCS-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-01",
    statement: "User-facing pages sit at the top level of `docs/`",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "Directory listing",
    remediation: remediation(
        "move-user-facing-docs",
        "REPO-DOCS-01",
        Lane::JudgmentFile,
        "Move user-facing pages to the top level of `docs/`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
