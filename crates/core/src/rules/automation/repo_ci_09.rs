//! REPO-CI-09.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-CI-09",
    statement: "The scheduled audit workflow runs the Airlock audit action in repository mode \
                with the run's own `GITHUB_TOKEN`, or in central mode with the `airlock-safe` \
                variables, and reads no `AIRLOCK_TOKEN` secret",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "Workflow contents and repository identity",
    fix: fix(
        "supply-run-token",
        "REPO-CI-09",
        FixKind::Airlock,
        "Give the canonical Airlock audit action `token: ${{ github.token }}` in repository mode \
         and remove `AIRLOCK_TOKEN`.",
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
