//! REPO-META-11.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-11",
    statement: "The declared merge settings are squash and rebase enabled, merge commits disabled, head branches auto-deleted",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "declare-merge-settings",
        "REPO-META-11",
        Lane::DeterministicFile,
        "Declare squash and rebase enabled, merge commits disabled, and head-branch auto-delete in `.github/repo-settings.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
