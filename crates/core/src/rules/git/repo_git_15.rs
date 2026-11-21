//! REPO-GIT-15: the repository has an Intentional baseline.
//
// relationships:
//   references: maturity

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-15",
    since: "0.6.0",
    allow_override: true,
    statement: "The repository has ended seeding with an Intentional baseline tag",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "Captured Intentional tag records and Git ancestry",
    fix: fix(
        "establish-baseline",
        "REPO-GIT-15",
        FixKind::Operator,
        "Use intentional tag --baseline to establish the repository's baseline tag.",
        false,
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
