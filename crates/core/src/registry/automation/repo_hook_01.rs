//! REPO-HOOK-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-01",
    statement: "`pre-commit` runs `format` and `lint` on staged files only",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-pre-commit-hook",
        "REPO-HOOK-01",
        Lane::DeterministicFile,
        "Configure `pre-commit` to run `format` and `lint` on staged files only.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("A remaining requirement has no compiled check yet"),
};
