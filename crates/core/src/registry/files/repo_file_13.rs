//! REPO-FILE-13.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-FILE-13",
    statement:
        "No agent harness configuration is committed — no `.claude/`, `.cursor/`, or equivalent",
    severity: Severity::Required,
    section: Section::Files,
    evaluation: Evaluation::Mechanical,
    params: &[Parameter {
        name: "forbidden-paths",
        default: ParameterDefault::Strings(&[
            ".claude",
            ".cursor",
            ".windsurf",
            ".codex",
            ".aider.conf.yml",
            ".github/copilot-instructions.md",
        ]),
    }],
    guidance: "File presence",
    remediation: remediation(
        "remove-agent-harness-config",
        "REPO-FILE-13",
        Lane::DeterministicFile,
        "Remove committed agent harness configuration directories.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
