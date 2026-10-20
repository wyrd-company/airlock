//! REPO-DOCS-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-02",
    statement: "Engineering artifacts sit in `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "Directory listing",
    remediation: remediation(
        "move-engineering-artifacts",
        "REPO-DOCS-02",
        Lane::JudgmentFile,
        "Move engineering artifacts into `docs/decisions/`, `docs/technical-designs/`, or `docs/spikes/`.",
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
