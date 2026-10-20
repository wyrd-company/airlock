//! Template identity input gathering at one audited revision.
//
// relationships:
//   implements: release-process-conformance

pub(crate) mod config;

use crate::document::{self, DocumentError};
use crate::github::{ApiError, ErrorCause, GitHub};
use crate::policy::ResolvedPolicy;
use crate::rules::Severity;
use crate::snapshot::{FileState, RepoSnapshot};
use config::{ExpectedTemplate, RULE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::LazyLock;

pub(crate) const SCHEMA_ID: &str = "https://wyrd.foo/toha/schemas/applied-record/1";
const SCHEMA: &str = include_str!("../../schemas/toha/applied-record-1.schema.yml");
static VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let value: Value =
        serde_norway::from_str(SCHEMA).expect("embedded Toha schema is JSON-compatible YAML");
    jsonschema::options()
        .offline()
        .build(&value)
        .expect("embedded Toha schema compiles offline")
});

pub(crate) fn read(bytes: &[u8]) -> Result<Value, DocumentError> {
    let value = document::read(bytes, SCHEMA_ID, &VALIDATOR)?;
    let mut pairs = BTreeSet::new();
    for (index, application) in value["applications"]
        .as_array()
        .expect("schema validated applications")
        .iter()
        .enumerate()
    {
        if !pairs.insert((
            application["source"].as_str(),
            application["target"].as_str(),
        )) {
            return Err(DocumentError::Invalid(format!(
                "/applications/{index}: duplicate source/target pair (unique source/target)"
            )));
        }
    }
    Ok(value)
}

pub(crate) fn application<'a>(record: &'a Value, expected: &ExpectedTemplate) -> Option<&'a Value> {
    record["applications"]
        .as_array()?
        .iter()
        .find(|a| a["source"] == expected.source && a["target"] == expected.target)
}

/// A captured parent revision and its ancestry comparisons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateRevision {
    pub source: String,
    pub target: String,
    pub resolved_ref: String,
    pub resolved_minimum: Option<String>,
    pub reachability: Option<String>,
    pub minimum_ancestry: Option<String>,
}

/// A selected parent and every reason its application does or does not conform.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TemplateItem {
    pub expected: ExpectedTemplate,
    pub found: Option<Value>,
    pub other_targets: Vec<String>,
    pub revision: Option<TemplateRevision>,
    pub outcome: String,
    pub reasons: Vec<String>,
}

/// Structured evidence preserves each expected parent, including whole-record failures.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TemplateEvidence {
    pub record_path: String,
    pub audited_commit: String,
    pub items: Vec<TemplateItem>,
}

/// Reject links at every component, even when the final record is absent.
pub(crate) fn non_file_path(snapshot: &RepoSnapshot, path: &str) -> bool {
    let components: Vec<_> = path.split('/').collect();
    (1..=components.len()).any(|end| {
        let prefix = components[..end].join("/");
        snapshot.entry(&prefix).is_some_and(|e| {
            if end == components.len() {
                !e.kind.is_file()
            } else {
                e.kind != crate::github::EntryKind::Tree
            }
        })
    })
}

pub(crate) async fn gather<G: GitHub>(
    client: &G,
    snapshot: &RepoSnapshot,
    policy: &ResolvedPolicy,
) -> Result<Vec<TemplateRevision>, ApiError> {
    let Some(rule) = policy.rule(RULE).filter(|r| r.severity != Severity::None) else {
        return Ok(Vec::new());
    };
    if policy
        .suppressions
        .direct_for(RULE, &snapshot.repository.full_name)
        .is_some()
    {
        return Ok(Vec::new());
    }
    // The compiled release-unit boundary is settled before any template API read.
    let in_scope = snapshot
        .file(".intentional/config.yml")
        .text()
        .and_then(|text| crate::yaml::parse_mapping(text, snapshot.limits.yaml).ok())
        .and_then(|doc| {
            doc.get("release-units")
                .and_then(crate::yaml::Yaml::as_map)
                .map(|entries| !entries.is_empty())
        })
        .unwrap_or(false);
    if !in_scope {
        return Ok(Vec::new());
    }
    let entries = config::expected(rule)
        .map_err(|e| ApiError::local(ErrorCause::Malformed, "policy", e.to_string()))?;
    let path = config::record_path(rule);
    if non_file_path(snapshot, path) {
        return Ok(Vec::new());
    }
    let FileState::Content { bytes, .. } = snapshot.file(path) else {
        return Ok(Vec::new());
    };
    let Ok(record) = read(bytes) else {
        return Ok(Vec::new());
    };
    let mut results = Vec::new();
    for expected in entries {
        let (owner, repo) =
            config::source(&expected.source).expect("configuration validated source");
        let resolved_ref = client
            .resolve_commit(owner, repo, &expected.reference)
            .await?;
        let resolved_minimum = match &expected.minimum {
            Some(reference) => Some(client.resolve_commit(owner, repo, reference).await?),
            None => None,
        };
        let commit = application(&record, &expected).and_then(|a| a["commit"].as_str());
        let reachability = match commit {
            Some(commit) => Some(
                client
                    .compare_status(owner, repo, commit, &resolved_ref)
                    .await?,
            ),
            None => None,
        };
        let minimum_ancestry = match (commit, &resolved_minimum) {
            (Some(commit), Some(minimum)) => {
                Some(client.compare_status(owner, repo, minimum, commit).await?)
            }
            _ => None,
        };
        results.push(TemplateRevision {
            source: expected.source.clone(),
            target: expected.target.clone(),
            resolved_ref,
            resolved_minimum,
            reachability,
            minimum_ancestry,
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn vendored_toha_record_schema_provenance_matches_bytes_and_identity() {
        let provenance: Value =
            serde_json::from_str(include_str!("../../schemas/toha/provenance.json")).unwrap();
        let schema: Value = serde_norway::from_str(SCHEMA).unwrap();
        assert_eq!(schema["$id"], SCHEMA_ID);
        assert_eq!(provenance["schema_id"], SCHEMA_ID);
        assert_eq!(
            provenance["sha256"],
            hex::encode(Sha256::digest(SCHEMA.as_bytes()))
        );
        assert_eq!(provenance["commit"].as_str().unwrap().len(), 40);
    }
    #[test]
    fn template_reader_agrees_with_producer_schema_corpus() {
        let valid = include_bytes!("../../tests/fixtures/toha/valid.json");
        assert!(read(valid).is_ok());
        for bytes in [
            include_bytes!("../../tests/fixtures/toha/missing-application-parts.json").as_slice(),
            include_bytes!("../../tests/fixtures/toha/missing-record-schema.json"),
            include_bytes!("../../tests/fixtures/toha/missing-mode.json"),
        ] {
            assert!(read(bytes).is_err());
        }
    }
}
