//! REPO-LIC-04.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-LIC-04",
    statement: "A repository publishing to a registry declares the license in package metadata",
    severity: Severity::Required,
    section: Section::Licensing,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::ReleaseUnitsDeclared,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
