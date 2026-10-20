//! REPO-REL-06.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-REL-06",
    statement: "The release workflow asserts a successful push-event CI run for exactly that SHA",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[],
    guidance: "Workflow contents",
    remediation: remediation(
        "assert-ci-passed-for-sha",
        "REPO-REL-06",
        Lane::JudgmentFile,
        "Assert in the release workflow a successful push-event CI run for exactly that SHA.",
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
