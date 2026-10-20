//! REPO-ORG-01.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-ORG-01",
    statement: "The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good",
    severity: Severity::Advisory,
    section: Section::Identity,
    params: &[],
    guidance: "Judgment",
    fix: fix(
        "transfer-repository",
        "REPO-ORG-01",
        FixKind::Operator,
        "Transfer the repository to the org its audience implies.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
