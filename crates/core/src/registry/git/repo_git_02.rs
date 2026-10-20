//! REPO-GIT-02.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-02",
    statement: "The repository is covered by organization-sourced rulesets on its default branch",
    severity: Severity::Blocking,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`gh api repos/{o}/{r}/rulesets?includes_parents=true`",
    remediation: remediation(
        "attach-org-rulesets",
        "REPO-GIT-02",
        Lane::OperatorSetting,
        "Attach organization-sourced rulesets to the default branch.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
