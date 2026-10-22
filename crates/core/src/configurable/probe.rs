// ---
// relationships:
//   implements: configurable-rules
// ---

//! Demand-driven read-only observation adapters. The GitHub adapter accepts
//! the existing read-only client trait; credential verification stays with the
//! caller, as with the existing audit. No credential is read by this module.

use super::config::{Lifecycle, ProbeRequest};
use crate::{
    github::{CustomPropertyValueKind, GitHub, Tree},
    limits::Limits,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct RepositoryTarget {
    pub owner: String,
    pub name: String,
    /// A resolved commit, never a moving branch name.
    pub commit: String,
    /// The observed rung from core::maturity, not a config declaration.
    pub maturity: Lifecycle,
}
impl RepositoryTarget {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

pub struct ProbeSchema {
    pub input: Value,
    pub output: Value,
}

#[allow(async_fn_in_trait)]
pub trait ProbeProvider {
    fn schema(&self, kind: &str) -> Option<ProbeSchema>;
    async fn observe(
        &mut self,
        target: &RepositoryTarget,
        request: &ProbeRequest,
    ) -> Result<Value, String>;
}

pub struct GitHubProbes<'a, G> {
    client: &'a G,
    limits: Limits,
    trees: BTreeMap<(String, String), Tree>,
    bytes_read: usize,
}

impl<'a, G: GitHub> GitHubProbes<'a, G> {
    pub fn new(client: &'a G, limits: Limits) -> Self {
        Self {
            client,
            limits,
            trees: BTreeMap::new(),
            bytes_read: 0,
        }
    }
    async fn file(&mut self, target: &RepositoryTarget, path: &str) -> Result<Value, String> {
        let key = (target.full_name(), target.commit.clone());
        if !self.trees.contains_key(&key) {
            let tree = self
                .client
                .tree(&target.owner, &target.name, &target.commit)
                .await
                .map_err(|e| e.to_string())?;
            if tree.entries.len() > self.limits.max_tree_entries {
                return Err("tree entry budget exceeded".into());
            }
            self.trees.insert(key.clone(), tree);
        }
        let tree = &self.trees[&key];
        let Some(entry) = tree
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .cloned()
        else {
            return if tree.truncated {
                Err("file absence cannot be decided from a truncated tree".into())
            } else {
                Ok(json!({"exists":false,"kind":"missing","contents":null,"blob":null}))
            };
        };
        if !entry.kind.is_file() {
            return Ok(json!({"exists":false,"kind":"not-a-file","contents":null,"blob":null}));
        }
        let remaining = self.limits.max_total_bytes.saturating_sub(self.bytes_read);
        let budget = self.limits.max_blob_bytes.min(remaining);
        if entry.size.is_some_and(|size| size > budget as u64) {
            return Err("file byte budget exceeded".into());
        }
        let bytes = self
            .client
            .blob(&target.owner, &target.name, &entry.sha)
            .await
            .map_err(|e| e.to_string())?;
        self.bytes_read = self.bytes_read.saturating_add(bytes.len());
        if bytes.len() > budget {
            return Err("file byte budget exceeded".into());
        }
        let contents = String::from_utf8(bytes).map_err(|_| "file content is not UTF-8")?;
        Ok(json!({"exists":true,"kind":"file","contents":contents,"blob":entry.sha}))
    }
}

impl<G: GitHub> ProbeProvider for GitHubProbes<'_, G> {
    fn schema(&self, kind: &str) -> Option<ProbeSchema> {
        let empty = json!({"type":"object","additionalProperties":false});
        Some(match kind {
            "file-content" => ProbeSchema {
                input: json!({"type":"object","required":["path"],"properties":{"path":{"type":"string","minLength":1}},"additionalProperties":false}),
                output: json!({"type":"object","required":["exists","kind","contents","blob"],"properties":{"exists":{"type":"boolean"},"kind":{"enum":["missing","not-a-file","file"]},"contents":{"type":["string","null"]},"blob":{"type":["string","null"]}},"additionalProperties":false}),
            },
            "repository" => ProbeSchema {
                input: empty,
                output: json!({"type":"object","required":["name","visibility","default-branch","has-wiki","has-projects","has-discussions","has-issues","description","observed-at"],"properties":{"name":{"type":"string"},"visibility":{"type":"string"},"default-branch":{"type":"string"},"has-wiki":{"type":"boolean"},"has-projects":{"type":"boolean"},"has-discussions":{"type":"boolean"},"has-issues":{"type":"boolean"},"description":{"type":["string","null"]},"observed-at":{"type":["string","null"]},"allow-merge-commit":{"type":"boolean"},"allow-squash-merge":{"type":"boolean"},"allow-rebase-merge":{"type":"boolean"},"delete-branch-on-merge":{"type":"boolean"}},"additionalProperties":false}),
            },
            "topics" => ProbeSchema {
                input: empty,
                output: json!({"type":"array","items":{"type":"string"}}),
            },
            "custom-properties" => ProbeSchema {
                input: empty,
                output: json!({"type":"object","additionalProperties":{"type":["string","array","null"],"items":{"type":"string"}}}),
            },
            _ => return None,
        })
    }
    async fn observe(
        &mut self,
        target: &RepositoryTarget,
        request: &ProbeRequest,
    ) -> Result<Value, String> {
        match request.kind.as_str() {
            "file-content" => {
                self.file(
                    target,
                    request.input["path"]
                        .as_str()
                        .ok_or("file-content needs path")?,
                )
                .await
            }
            "repository" => {
                let r = self
                    .client
                    .repository(&target.owner, &target.name)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut output = json!({"name":r.name,"visibility":r.visibility,"default-branch":r.default_branch,"has-wiki":r.has_wiki,"has-projects":r.has_projects,"has-discussions":r.has_discussions,"has-issues":r.has_issues,"description":r.description,"observed-at":r.observed_at});
                for (key, value) in [
                    ("allow-merge-commit", r.allow_merge_commit),
                    ("allow-squash-merge", r.allow_squash_merge),
                    ("allow-rebase-merge", r.allow_rebase_merge),
                    ("delete-branch-on-merge", r.delete_branch_on_merge),
                ] {
                    if let Some(value) = value {
                        output[key] = value.into();
                    }
                }
                Ok(output)
            }
            "topics" => self
                .client
                .topics(&target.owner, &target.name)
                .await
                .map(|v| json!(v))
                .map_err(|e| e.to_string()),
            "custom-properties" => {
                let values = self
                    .client
                    .custom_property_values(&target.owner, &target.name)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut result = serde_json::Map::new();
                for property in values {
                    let value = match property.value {
                        CustomPropertyValueKind::String(v) => json!(v),
                        CustomPropertyValueKind::Strings(v) => json!(v),
                        CustomPropertyValueKind::Null => Value::Null,
                    };
                    result.insert(property.property_name, value);
                }
                Ok(Value::Object(result))
            }
            _ => Err("probe type is not implemented".into()),
        }
    }
}
