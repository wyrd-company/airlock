//! REPO-DOCS-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-DOCS-04",
    statement: "A tool publishing docs to `wyrd.foo` has `docs/docs.yml`",
    severity: Severity::Advisory,
    section: Section::Docs,
    params: &[],
    guidance: "File presence plus the recorded decision",
    fix: fix(
        "add-docs-manifest",
        "REPO-DOCS-04",
        FixKind::Agent,
        "Add `docs/docs.yml` for publication to `wyrd.foo`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
