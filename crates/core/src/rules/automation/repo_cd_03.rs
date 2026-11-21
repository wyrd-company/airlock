//! REPO-CD-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CD-03",
    statement: "A repository deploying a site or service triggers CD on push to the default branch",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents",
    fix: fix(
        "add-push-trigger",
        "REPO-CD-03",
        FixKind::Airlock,
        "Trigger CD on push to the default branch.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: true,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
