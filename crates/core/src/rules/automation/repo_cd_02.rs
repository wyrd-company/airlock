//! REPO-CD-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CD-02",
    statement: "A repository publishing a versioned artifact triggers CD on tags matching `[0-9]*.[0-9]*.[0-9]*`",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[Parameter { name: "tag-pattern", default: ParameterDefault::String("[0-9]*.[0-9]*.[0-9]*") }],
    guidance: "Workflow contents",
    fix: fix(
        "add-tag-trigger",
        "REPO-CD-02",
        FixKind::Airlock,
        "Trigger CD on tags matching the release tag pattern.",
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
