//! REPO-GIT-07.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-07",
    statement: "Wikis, Projects, and Discussions are off unless deliberately used",
    severity: Severity::Advisory,
    section: Section::Git,
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
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
