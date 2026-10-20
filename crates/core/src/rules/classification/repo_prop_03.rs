//! REPO-PROP-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-PROP-03",
    statement: "`.github/airlock.yml` declares no custom property values",
    severity: Severity::Blocking,
    section: Section::Classification,
    params: &[],
    guidance: "File contents",
    fix: fix(
        "remove-custom-property-values",
        "REPO-PROP-03",
        FixKind::Airlock,
        "Remove custom property values from `.github/airlock.yml`.",
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
