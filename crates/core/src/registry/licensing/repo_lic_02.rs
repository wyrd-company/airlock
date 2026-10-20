//! REPO-LIC-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-02",
    statement: "The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Judgment against the category table",
    remediation: remediation(
        "replace-license",
        "REPO-LIC-02",
        Lane::JudgmentFile,
        "Replace the licence with the one the repository's category calls for.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
