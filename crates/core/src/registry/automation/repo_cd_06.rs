//! REPO-CD-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-06",
    statement: "CD asserts every required publication credential is present before doing any work",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-credentials-up-front",
        "REPO-CD-06",
        Lane::JudgmentFile,
        "Assert every required publication credential before CD does any work.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
