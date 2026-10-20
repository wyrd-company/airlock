//! REPO-META-09.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-09",
    statement: "Any topic not in `topics.md` has been added to it",
    severity: Severity::Required,
    section: Section::Identity,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: not_remediable(
        "REPO-META-09",
        "The fix is an edit to the organisation's topic registry, which lives outside the audited repository.",
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
