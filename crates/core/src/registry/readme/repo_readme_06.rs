//! REPO-README-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-06",
    statement: "Where a demo exists, its `.tape` source is committed",
    severity: Severity::Advisory,
    section: Section::Readme,
    // Mechanical scope: the committed-demo proxy is a regular file whose
    // basename is `demo.gif`, matching the repository VHS convention.
    // REPO-README-05 retains the judgment of what other media is a demo.
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "commit-tape-source",
        "REPO-README-06",
        Lane::JudgmentFile,
        "Commit the demo's `.tape` source.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
