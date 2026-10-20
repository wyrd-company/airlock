//! REPO-FILE-12.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-12",
    statement: "`CLAUDE.md` exists and is a symlink to `AGENTS.md`",
    severity: Severity::Required,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`git ls-files -s CLAUDE.md` — mode `120000`",
    remediation: remediation(
        "add-claude-symlink",
        "REPO-FILE-12",
        Lane::DeterministicFile,
        "Add `CLAUDE.md` as a symlink to `AGENTS.md`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
