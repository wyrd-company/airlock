//! REPO-LIC-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-02",
    statement: "The license matches the repository's category: Apache-2.0 by default, CC0-1.0 for specs and schemas, MIT for plumbing, or a matched ecosystem license",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "Compare the observed license with the declared category: Apache-2.0 by default, CC0-1.0 for specifications or schemas, MIT for plumbing that moves bits without an invention, or the explicitly selected ecosystem license. Review classification when the repository's purpose changes; do not silently choose another category to accept its existing license.",
    fix: fix(
        "replace-license",
        "REPO-LIC-02",
        FixKind::Agent,
        "Replace the licence with the one the repository's category calls for.",
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
    unbuilt_reason: Some("The compiled check is not built yet"),
};
