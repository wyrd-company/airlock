//! REPO-META-11.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-11",
    statement: "The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "declare-merge-settings",
        "REPO-META-11",
        Lane::DeterministicFile,
        "Declare squash and rebase enabled, merge commits disabled, and head-branch auto-delete in `.github/repo-settings.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
