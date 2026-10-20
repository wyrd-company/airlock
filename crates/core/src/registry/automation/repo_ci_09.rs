//! REPO-CI-09.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-CI-09",
    statement:
        "The scheduled audit workflow supplies `secrets.AIRLOCK_TOKEN` to the Airlock audit action",
    severity: Severity::Required,
    section: Section::Automation,
    evaluation: Evaluation::Mechanical,
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
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
