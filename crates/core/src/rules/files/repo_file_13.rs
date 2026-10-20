//! REPO-FILE-13.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-13",
    statement:
        "No agent harness configuration is committed — no `.claude/`, `.cursor/`, or equivalent",
    severity: Severity::Advisory,
    section: Section::Files,
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
    fix: fix(
        "remove-agent-harness-config",
        "REPO-FILE-13",
        FixKind::Airlock,
        "Remove committed agent harness configuration directories.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
