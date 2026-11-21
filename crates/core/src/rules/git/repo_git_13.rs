//! REPO-GIT-13.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-GIT-13",
    statement: "A GitHub App's identity is a variable named `<APP>_APP_ID`; only its private key is a secret, named `<APP>_APP_PRIVATE_KEY`",
    severity: Severity::Advisory,
    section: Section::Git,
    params: &[],
    guidance: "Workflow source",
    fix: fix(
        "rename-app-credentials",
        "REPO-GIT-13",
        FixKind::Operator,
        "Rename the GitHub App identity to an `<APP>_APP_ID` variable and its private key to an `<APP>_APP_PRIVATE_KEY` secret.",
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
