//! REPO-GIT-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-03",
    statement: "Those rulesets require pull requests, allow only squash and rebase, and require linear history",
    severity: Severity::Blocking,
    section: Section::Git,
    params: &[],
    guidance: "`gh api repos/{o}/{r}/rules/branches/main`",
    remediation: remediation(
        "tighten-org-rulesets",
        "REPO-GIT-03",
        Lane::OperatorSetting,
        "Configure the rulesets to require pull requests, allow only squash and rebase, and require linear history.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
