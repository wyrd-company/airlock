//! REPO-CI-09.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-09",
    statement:
        "The scheduled audit workflow supplies `secrets.AIRLOCK_TOKEN` to the Airlock audit action",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents and repository identity",
    remediation: remediation(
        "supply-airlock-token",
        "REPO-CI-09",
        Lane::DeterministicFile,
        "Supply `secrets.AIRLOCK_TOKEN` to the canonical Airlock audit action as `AIRLOCK_TOKEN`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
