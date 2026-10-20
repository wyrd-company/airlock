//! REPO-GIT-07.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-07",
    statement: "Wikis, Projects, and Discussions are off unless deliberately used",
    severity: Severity::Observation,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "`gh repo view`",
    remediation: remediation(
        "disable-unused-features",
        "REPO-GIT-07",
        Lane::OperatorSetting,
        "Turn off wikis, projects, and discussions that are not deliberately used.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
