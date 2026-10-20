//! REPO-FILE-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-02",
    statement: "`CONTRIBUTING.md` exists in the repository, not only at org level",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "File presence",
    remediation: remediation(
        "add-contributing",
        "REPO-FILE-02",
        Lane::JudgmentFile,
        "Write a repository-level `CONTRIBUTING.md`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: None,
};
