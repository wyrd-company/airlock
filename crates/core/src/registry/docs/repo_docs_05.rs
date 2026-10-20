//! REPO-DOCS-05.
//
// relationships:
//   references: registry

use crate::registry::{CheckDefinition, Lifecycle, Observation, Section, Severity};
use crate::remediation::{remediation, Lane};

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-DOCS-05",
    statement: "Schema-bound YAML artifacts follow their schema where one exists",
    severity: Severity::Advisory,
    section: Section::Docs,
    // Manual: schema references may resolve outside the bounded repository
    // snapshot. The registry-owned evaluation reason records why partial
    // validation was rejected and is surfaced in listings and findings.
    params: &[],
    guidance: "schemas may resolve outside the bounded repository snapshot",
    remediation: remediation(
        "conform-yaml-to-schema",
        "REPO-DOCS-05",
        Lane::JudgmentFile,
        "Fix schema-bound YAML artifacts to follow their schema.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    disclosure_gate: None,
    unbuilt_reason: Some(
        "Schema discovery can leave the bounded repository snapshot. Partial validation \
                 of only in-snapshot schemas was rejected because a manual finding communicates \
                 the whole-repository judgment consistently; mixing passes with inconclusive \
                 results based on schema location would make identical artifact classes gate \
                 differently.",
    ),
};
