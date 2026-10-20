//! REPO-CD-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CD-05",
    statement:
        "A CD `workflow_dispatch` can only re-deliver an existing tag, never create a release",
    severity: Severity::Blocking,
    section: Section::Automation,
    params: &[],
    guidance: "Dispatch inputs and their use",
    fix: fix(
        "restrict-dispatch-to-redelivery",
        "REPO-CD-05",
        FixKind::Agent,
        "Restrict the CD `workflow_dispatch` to re-delivering an existing tag.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
