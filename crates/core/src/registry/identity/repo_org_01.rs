//! REPO-ORG-01.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-ORG-01",
    statement: "The repository is in the org its audience implies: `boblangley` if overfit to Bob, `wyrd-company` if a stranger benefits, `flapstack` if a vendor-neutral public good",
    severity: Severity::Advisory,
    section: Section::Identity,
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
    observation: Observation::Platform,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some("The compiled check is not built yet"),
};
