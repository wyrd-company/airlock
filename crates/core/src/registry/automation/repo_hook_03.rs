//! REPO-HOOK-03.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-HOOK-03",
    statement: "`pre-push` runs nothing or lint only",
    severity: Severity::Advisory,
    section: Section::Automation,
    params: &[],
    guidance: "`.config/lefthook.yml`",
    remediation: remediation(
        "configure-pre-push-hook",
        "REPO-HOOK-03",
        Lane::DeterministicFile,
        "Configure `pre-push` to run nothing or lint only.",
        true,
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
