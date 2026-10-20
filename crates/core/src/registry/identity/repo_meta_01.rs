//! REPO-META-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-01",
    statement: "`.github/repo-settings.yml` declares a description",
    severity: Severity::Blocking,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "declare-description",
        "REPO-META-01",
        Lane::JudgmentFile,
        "Add a `description` to `.github/repo-settings.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
