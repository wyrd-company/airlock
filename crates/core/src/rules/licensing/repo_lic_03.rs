//! REPO-LIC-03.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-03",
    statement: "The repository is not dual-licensed `MIT OR Apache-2.0`",
    severity: Severity::Blocking,
    section: Section::Licensing,
    params: &[],
    guidance: "`LICENSE`, package metadata",
    fix: fix(
        "replace-dual-license",
        "REPO-LIC-03",
        FixKind::Agent,
        "Replace the dual `MIT OR Apache-2.0` licence with the single licence the category calls for.",
        false,
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
