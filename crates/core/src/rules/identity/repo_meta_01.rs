//! REPO-META-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-META-01",
    statement: "`.github/airlock.yml` declares a description",
    severity: Severity::Blocking,
    section: Section::Identity,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "declare-description",
        "REPO-META-01",
        FixKind::Agent,
        "Add a `description` to `.github/airlock.yml`.",
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
