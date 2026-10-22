//! REPO-LIC-04.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-LIC-04",
    statement: "A repository publishing to a registry declares the license in package metadata",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "`package.json`, `Cargo.toml`, `pubspec.yaml`",
    fix: fix(
        "declare-package-license",
        "REPO-LIC-04",
        FixKind::Airlock,
        "Declare the repository licence in the package metadata of each publishing release unit.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
