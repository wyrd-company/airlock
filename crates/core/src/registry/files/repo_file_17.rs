//! REPO-FILE-17.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-17",
    statement: "`.github/workflows/audit.yml` exists and triggers on a schedule and on demand",
    severity: Severity::Blocking,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "add-audit-workflow",
        "REPO-FILE-17",
        Lane::DeterministicFile,
        "Add the standard scheduled, on-demand `.github/workflows/audit.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
