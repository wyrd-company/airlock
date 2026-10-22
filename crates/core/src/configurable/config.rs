// ---
// relationships:
//   references: config-source
// ---

//! Configuration snapshots. Rule bodies remain independent fallible documents.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::rules::{Lifecycle, Severity};
use crate::{limits::YamlLimits, yaml::Yaml};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSource {
    pub repository: String,
    pub path: String,
    /// Full hexadecimal commit OID (40 or 64 digits), supplied by the loader.
    pub commit: String,
}

#[derive(Debug, Clone)]
pub struct ConfigSnapshot<T> {
    pub source: ConfigSource,
    pub document: T,
}

pub const DEFAULT_CONFIG_PATH: &str = ".github/airlock.yml";

/// Low-level readers take object ids. Resolve a ref once before calling them.
pub(crate) fn is_commit_oid(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl<T: serde::de::DeserializeOwned> ConfigSnapshot<T> {
    /// Read this exact source commit through the existing GitHub client.
    /// Absence is explicit; unreadable/truncated input returns an error.
    /// Callers resolve any ref once to a full OID and verify the read-only
    /// credential before invoking this loader. No ref is resolved here.
    pub async fn read_at<G: crate::github::GitHub>(
        client: &G,
        source: ConfigSource,
        limits: crate::limits::Limits,
    ) -> Result<Option<Self>, String> {
        use super::probe::{GitHubProbes, ProbeProvider, RepositoryTarget};
        let (owner, repo) = source
            .repository
            .split_once('/')
            .filter(|(owner, repo)| !owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
            .ok_or("config source needs owner/repository")?;
        if !is_commit_oid(&source.commit) || source.path.trim().is_empty() {
            return Err(
                "configuration source needs a full hexadecimal commit object id and path".into(),
            );
        }
        let target = RepositoryTarget {
            owner: owner.into(),
            name: repo.into(),
            commit: source.commit.clone(),
            maturity: Lifecycle::Seeded,
        };
        let mut provider = GitHubProbes::new(client, limits);
        let output = provider
            .observe(
                &target,
                &ProbeRequest {
                    kind: "file-content".into(),
                    input: serde_json::json!({"path":source.path}),
                },
            )
            .await?;
        if output["kind"] == "missing" {
            return Ok(None);
        }
        if output["kind"] != "file" {
            return Err("configuration path is not a regular file".into());
        }
        Self::load(
            source,
            output["contents"]
                .as_str()
                .ok_or("configuration content was not observed")?,
            limits.yaml,
        )
        .map(Some)
    }

    /// Parse with the existing bounded, duplicate-key-rejecting YAML loader.
    /// Envelope errors stop loading; invalid rule bodies are reported per rule.
    pub fn load(source: ConfigSource, text: &str, limits: YamlLimits) -> Result<Self, String> {
        if !is_commit_oid(&source.commit) || source.path.trim().is_empty() {
            return Err(
                "configuration source needs a full hexadecimal commit object id and path".into(),
            );
        }
        let yaml = crate::yaml::parse_mapping(text, limits).map_err(|e| e.to_string())?;
        let document = serde_json::from_value(json(yaml)?).map_err(|e| e.to_string())?;
        Ok(Self { source, document })
    }
}

fn json(value: Yaml) -> Result<Value, String> {
    Ok(match value {
        Yaml::Null => Value::Null,
        Yaml::Bool(v) => v.into(),
        Yaml::Int(v) => v.into(),
        Yaml::Float(v) => serde_json::Number::from_f64(v)
            .ok_or("non-finite configuration number")?
            .into(),
        Yaml::String(v) => v.into(),
        Yaml::Seq(v) => Value::Array(v.into_iter().map(json).collect::<Result<_, _>>()?),
        Yaml::Map(v) => Value::Object(
            v.into_iter()
                .map(|(k, v)| Ok((k, json(v)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct OrganizationConfig {
    pub rules: BTreeMap<String, Value>,
    pub assignments: BTreeMap<String, Assignment>,
    /// Organization-owned replacements for a repository; each needs a reason.
    #[serde(default)]
    pub repositories: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    #[serde(default)]
    pub rules: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    /// All conditions must pass. An empty list is an explicit catch-all.
    pub conditions: Vec<Condition>,
    pub probes: BTreeMap<String, ProbeRequest>,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProbeRequest {
    pub kind: String,
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Setting<T> {
    pub floor: T,
    pub value: T,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SeveritySchedule {
    Uniform(Setting<Severity>),
    ByMaturity {
        seeded: Setting<Severity>,
        building: Setting<Severity>,
        released: Setting<Severity>,
        stable: Setting<Severity>,
    },
}

impl SeveritySchedule {
    pub fn at(&self, maturity: Lifecycle) -> &Setting<Severity> {
        match self {
            Self::Uniform(s) => s,
            Self::ByMaturity {
                seeded,
                building,
                released,
                stable,
            } => match maturity {
                Lifecycle::Seeded => seeded,
                Lifecycle::Building => building,
                Lifecycle::Released => released,
                Lifecycle::Stable => stable,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Condition {
    /// A name in this rule or assignment's probes map.
    pub probe: String,
    /// JSON Pointer into the probe output; the empty string selects it all.
    pub pointer: String,
    pub evaluation: String,
    pub setting: Setting<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Rule {
    pub statement: String,
    pub probes: BTreeMap<String, ProbeRequest>,
    pub conditions: Vec<Condition>,
    pub severity: SeveritySchedule,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub fix: Option<FixDeclaration>,
}

/// Declarations complete or replace derivation, or explicitly block a fix.
/// Actions are plans only. This module has no executor or mutating endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FixDeclaration {
    Complete { input: Value },
    Action { action: String, input: Value },
    Agent { guidance: String },
    Block { reason: String },
}
