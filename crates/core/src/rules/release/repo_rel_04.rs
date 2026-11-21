//! REPO-REL-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-REL-04",
    statement: "Release is `workflow_dispatch` on a pinned source SHA",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[],
    guidance: "Workflow contents",
    fix: fix(
        "redesign-release-trigger",
        "REPO-REL-04",
        FixKind::Agent,
        "Make release a `workflow_dispatch` on a pinned source SHA.",
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
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
