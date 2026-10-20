//! REPO-HOOK-02.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-02",
    statement: "`commit-msg` validates conventional commit format",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-commit-msg-hook",
        "REPO-HOOK-02",
        Lane::DeterministicFile,
        "Configure `commit-msg` to validate conventional commit format.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some("Some evidence requires a compiled check that is not built yet"),
};
