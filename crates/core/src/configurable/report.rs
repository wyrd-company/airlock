// ---
// relationships:
//   references: report
// ---

//! Additive report contract, independent of the current CLI projection.

use super::config::{ConfigSource, Lifecycle, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultKind {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flavor {
    Passed,
    NotApplicable,
    Waived,
    Gap,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Value,
    Floor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    Organization,
    Repository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionResult {
    pub index: usize,
    pub result: ResultKind,
    pub flavor: Flavor,
    pub diagnostic: Option<Diagnostic>,
    /// Selected expected value. Raw repository content is not copied here.
    pub expected: Value,
    pub probe: String,
    pub pointer: String,
    pub evaluation: String,
    /// SHA-256 of selected JSON. Raw file contents are not retained.
    pub observed_digest: Option<String>,
    pub reason: String,
    pub fix: Fix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Fix {
    Action {
        fixer: Fixer,
        action: String,
        input: Value,
    },
    Agent {
        guidance: String,
    },
    NotFixable {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fixer {
    Person,
    Airlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceResult {
    pub source: Source,
    pub config_commit: String,
    pub mode: Mode,
    pub statement: Option<String>,
    pub reason: Option<String>,
    pub relaxation_reason: Option<String>,
    pub severity: Severity,
    pub result: ResultKind,
    pub flavor: Flavor,
    pub diagnostic: Option<Diagnostic>,
    pub conditions: Vec<ConditionResult>,
    pub fixes: Vec<Fix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub id: String,
    pub result: ResultKind,
    pub flavor: Flavor,
    /// Highest failing severity; highest instance severity when all pass.
    pub severity: Severity,
    pub instances: Vec<InstanceResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentResult {
    pub id: String,
    /// None means matching could not be decided. It never means unassigned.
    pub matched: Option<bool>,
    pub diagnostic: Option<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    pub rule: String,
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryReport {
    pub repository: String,
    pub audited_commit: String,
    pub maturity: Lifecycle,
    pub repository_config: Option<ConfigSource>,
    pub assignments: Vec<AssignmentResult>,
    pub rules: Vec<RuleResult>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub account: String,
    pub organization_config: ConfigSource,
    pub repositories: Vec<RepositoryReport>,
    pub unassigned_repositories: Vec<String>,
}
