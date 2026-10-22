//! REPO-FILE-17.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-17",
    statement: "`.github/workflows/audit.yml` exists and triggers on a schedule and on demand",
    severity: Severity::Blocking,
    section: Section::Files,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "add-audit-workflow",
        "REPO-FILE-17",
        FixKind::Airlock,
        "Add the scheduled, on-demand `.github/workflows/audit.yml`.",
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
    unbuilt_reason: None,
};
