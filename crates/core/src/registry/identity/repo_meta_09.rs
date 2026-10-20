//! REPO-META-09.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::not_remediable;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-META-09",
    statement: "Any topic not in `topics.md` has been added to it",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Compare against `topics.md`",
    remediation: not_remediable(
        "REPO-META-09",
        "The fix is an edit to the organisation's topic registry, which lives outside the audited repository.",
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
