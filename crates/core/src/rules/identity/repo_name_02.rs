//! REPO-NAME-02.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-NAME-02",
    statement: "A dotted name is used only where the repository is a deployable site and the name is its hostname",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Repository name",
    fix: fix(
        "rename-repository-undotted",
        "REPO-NAME-02",
        FixKind::Operator,
        "Rename the repository so only a deployable site named for its hostname carries a dot.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
