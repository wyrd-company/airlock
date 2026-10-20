//! REPO-DOCS-05.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-DOCS-05",
    statement: "Schema-bound YAML artifacts follow their schema where one exists",
    severity: Severity::Advisory,
    section: Section::Docs,
    // Manual: schema references may resolve outside the bounded repository
    // snapshot. The rules-owned evaluation reason records why partial
    // validation was rejected and is surfaced in listings and findings.
    params: &[],
    guidance: "schemas may resolve outside the bounded repository snapshot",
    fix: fix(
        "conform-yaml-to-schema",
        "REPO-DOCS-05",
        FixKind::Agent,
        "Fix schema-bound YAML artifacts to follow their schema.",
        true,
    ),
    lifecycle: Lifecycle::Seeded,
    observation: Observation::FileTree,
    api_gate: false,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: Some(
        "Schema discovery can leave the bounded repository snapshot. Partial validation \
                 of only in-snapshot schemas was rejected because a manual finding communicates \
                 the whole-repository judgment consistently; mixing passes with inconclusive \
                 results based on schema location would make identical artifact classes gate \
                 differently.",
    ),
};
