//! REPO-META-11.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-11",
    statement: "The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "declare-merge-settings",
        "REPO-META-11",
        FixKind::Airlock,
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
