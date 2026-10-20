//! REPO-LIC-04.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-04",
    statement: "A repository publishing to a registry declares the license in package metadata",
    severity: Severity::Advisory,
    section: Section::Licensing,
    params: &[],
    guidance: "`package.json`, `Cargo.toml`, `pubspec.yaml`",
    remediation: remediation(
        "declare-package-license",
        "REPO-LIC-04",
        Lane::DeterministicFile,
        "Declare the repository licence in the package metadata of each publishing release unit.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
