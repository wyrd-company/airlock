//! REPO-CD-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CD-05",
    statement:
        "A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release",
    severity: Severity::Blocking,
    section: Section::Automation,
    params: &[],
    guidance: "Dispatch inputs and their use",
    remediation: remediation(
        "restrict-dispatch-to-redelivery",
        "REPO-CD-05",
        Lane::JudgmentFile,
        "Restrict the CD `workflow_dispatch` to re-delivering an existing tag.",
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
