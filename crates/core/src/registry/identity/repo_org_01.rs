//! REPO-ORG-01.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Section, Severity,
};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-ORG-01",
    statement: "The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good",
    severity: Severity::Observation,
    section: Section::Identity,
    evaluation: Evaluation::Manual,
    params: &[],
    guidance: "Judgment",
    remediation: remediation(
        "transfer-repository",
        "REPO-ORG-01",
        Lane::OperatorSetting,
        "Transfer the repository to the org its audience implies.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
