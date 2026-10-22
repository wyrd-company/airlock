//! Template identity rule.
//
// relationships:
//   implements: release-process-conformance

use crate::fix::{fix, FixKind};
use crate::rules::{
    Lifecycle, Observation, Parameter, ParameterDefault, RuleDefinition, Section, Severity,
};

pub(crate) const RULE: RuleDefinition = RuleDefinition {
    id: "REPO-TPL-01",
    statement: "The repository applies each template the organization expects, at an accepted revision and with only accepted parts",
    severity: Severity::Blocking,
    section: Section::Release,
    params: &[
        Parameter { name: "templates", default: ParameterDefault::Required },
        Parameter { name: "record-path", default: ParameterDefault::String(".toha.json") },
    ],
    guidance: "Read the configured applied record as JSON at the audited revision. For record-missing, record-not-a-file, record-unreadable, record-schema-not-supported, application-missing, revision-not-accepted, revision-not-git or part-not-accepted, apply, update or baseline with Toha, select accepted parts, and commit the result. Organization exceptions alone configure templates and record-path; allow-override: false.",
    fix: fix("apply-accepted-template", "REPO-TPL-01", FixKind::Agent, "Apply, update or baseline with Toha, select accepted parts, and commit the applied record.", true),
    since: "0.6.0",
    allow_override: false,
    lifecycle: Lifecycle::Building,
    observation: Observation::FileTree,
    api_gate: true,
    owner_gate: false,
    release_units_gate: true,
    required_topic_categories: None,
    disclosure_gate: None,
    unbuilt_reason: None,
};
