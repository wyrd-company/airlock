//! REPO-CI-09.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CI-09",
    statement:
        "The scheduled audit workflow supplies `secrets.AIRLOCK_TOKEN` to the Airlock audit action",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents and repository identity",
    fix: fix(
        "supply-airlock-token",
        "REPO-CI-09",
        FixKind::Airlock,
        "Supply `secrets.AIRLOCK_TOKEN` to the canonical Airlock audit action as `AIRLOCK_TOKEN`.",
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
