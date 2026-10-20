//! REPO-PROP-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-PROP-04",
    statement: "No workflow writes organization custom properties",
    severity: Severity::Blocking,
    section: Section::Classification,
    params: &[],
    guidance: "Workflow contents",
    fix: fix(
        "remove-property-writing-workflows",
        "REPO-PROP-04",
        FixKind::Agent,
        "Remove workflow steps that write organization custom properties.",
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
