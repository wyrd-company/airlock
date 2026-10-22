//! REPO-README-06.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-README-06",
    statement: "Where a demo exists, its `.tape` source is committed",
    severity: Severity::Advisory,
    section: Section::Readme,
    // Mechanical scope: the committed-demo proxy is a regular file whose
    // basename is `demo.gif`, matching the repository VHS convention.
    // REPO-README-05 retains the judgment of what other media is a demo.
    params: &[],
    guidance: "File presence",
    fix: fix(
        "commit-tape-source",
        "REPO-README-06",
        FixKind::Agent,
        "Commit the demo's `.tape` source.",
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
