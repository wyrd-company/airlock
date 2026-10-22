//! REPO-REL-08.
//
// relationships:
//   references: rules

use crate::fix::{fix, FixKind};
use crate::rules::{Lifecycle, Observation, RuleDefinition, Section, Severity};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-REL-08",
    statement: "Every release of a Release Unit whose release-record policy is required has a release record on its primary tag",
    severity: Severity::Advisory,
    section: Section::Release,
    params: &[],
    guidance: "Read the committed Release Model and primary annotated tag records, then compare published GitHub Releases. Fix release-model-missing, release-model-not-a-file, release-model-unreadable, and release-model-schema-not-supported by running intentional model with a supported producer and committing .intentional/release-model.json (agent reasoning). Fix release-record-missing by publishing a GitHub Release on the missing primary tag (operator). Routed needs-github-api requires a credentialed API-tree audit or Action. Truncated listings and API failures require a complete rerun; they are run errors, not Gaps.",
    fix: fix(
        "publish-release-record",
        "REPO-REL-08",
        FixKind::Operator,
        "Publish each required GitHub Release; regenerate and commit an absent or invalid Release Model.",
        true,
    ),
    since: "0.6.0",
    allow_override: true,
    lifecycle: Lifecycle::Released,
    observation: Observation::Platform,
    api_gate: true,
    owner_gate: false,
    release_units_gate: false,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
