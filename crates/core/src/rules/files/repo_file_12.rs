//! REPO-FILE-12.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-FILE-12",
    statement: "`CLAUDE.md` exists and is a symlink to `AGENTS.md`",
    severity: Severity::Advisory,
    section: Section::Files,
    params: &[],
    guidance: "`git ls-files -s CLAUDE.md` — mode `120000`",
    fix: fix(
        "add-claude-symlink",
        "REPO-FILE-12",
        FixKind::Airlock,
        "Add `CLAUDE.md` as a symlink to `AGENTS.md`.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
