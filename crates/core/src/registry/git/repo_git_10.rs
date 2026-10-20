//! REPO-GIT-10.
//
// relationships:
//   references: registry

use crate::registry::{
    Applicability, CheckDefinition, Evaluation, Lifecycle, Observation, Parameter,
    ParameterDefault, Section, Severity,
};
use crate::remediation::not_remediable;

/// The default history scan budget.
pub(crate) const DEFAULT_MAX_COMMITS: usize = 1_000;

pub(crate) const STANDARD: CheckDefinition = CheckDefinition {
    id: "REPO-GIT-10",
    statement: "History contains no merge commits",
    severity: Severity::Required,
    section: Section::Git,
    evaluation: Evaluation::Mechanical,
    params: &[Parameter {
        name: "max-commits",
        default: ParameterDefault::Integer(DEFAULT_MAX_COMMITS as u64),
    }],
    guidance: "`git log --merges`",
    remediation: not_remediable(
        "REPO-GIT-10",
        "Closing it means rewriting published history, which airlock does not automate.",
    ),
    lifecycle: Lifecycle::Seeded,
    applicability: Applicability::Always,
    observation: Observation::Platform,
    disclosure_gate: None,
    evaluation_reason: None,
};
