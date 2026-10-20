//! REPO-README-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-README-03",
    statement: "An installation section covers every supported channel",
    severity: Severity::Blocking,
    section: Section::Readme,
    params: &[],
    guidance: "Compare against published channels",
    remediation: remediation(
        "write-install-section",
        "REPO-README-03",
        Lane::JudgmentFile,
        "Write an installation section covering every supported channel.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
