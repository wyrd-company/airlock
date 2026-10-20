//! REPO-LIC-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-03",
    statement: "The repository is not dual-licensed `MIT OR Apache-2.0`",
    severity: Severity::Blocking,
    section: Section::Licensing,
    params: &[],
    guidance: "`LICENSE`, package metadata",
    remediation: remediation(
        "replace-dual-license",
        "REPO-LIC-03",
        Lane::JudgmentFile,
        "Replace the dual `MIT OR Apache-2.0` licence with the single licence the category calls for.",
        false,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
