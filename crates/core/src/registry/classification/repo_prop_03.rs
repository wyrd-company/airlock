//! REPO-PROP-03.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-PROP-03",
    statement: "`.github/repo-settings.yml` declares no custom property values",
    severity: Severity::Blocking,
    section: Section::Classification,
    evaluation: Evaluation::Mechanical,
    params: &[],
    guidance: "File contents",
    remediation: remediation(
        "remove-custom-property-values",
        "REPO-PROP-03",
        Lane::DeterministicFile,
        "Remove custom property values from `.github/repo-settings.yml`.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::FileTree,
    disclosure_gate: None,
    evaluation_reason: None,
};
