//! Organization-owned expected template identities.
//
// relationships:
//   implements: release-process-conformance

use crate::policy::EffectiveRule;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const RULE: &str = "REPO-TPL-01";
pub(crate) const RECORD: &str = ".toha.json";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTemplate {
    pub source: String,
    #[serde(default = "root")]
    pub target: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub minimum: Option<String>,
    #[serde(default)]
    pub parts: Vec<String>,
}

fn root() -> String {
    ".".into()
}

pub(crate) fn path(value: &str, root_allowed: bool) -> bool {
    (root_allowed && value == ".")
        || (!value.is_empty()
            && !value.contains('\\')
            && !value.split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | ".." | ".git")
                    || (part.len() >= 2
                        && part.as_bytes()[0].is_ascii_alphabetic()
                        && part.as_bytes()[1] == b':')
            }))
}

pub(crate) fn source(value: &str) -> Option<(&str, &str)> {
    let value = value.strip_prefix("gh:")?;
    let (repository, directory) = value
        .split_once('#')
        .map_or((value, None), |(r, p)| (r, Some(p)));
    if directory.is_some_and(|p| !path(p, false)) {
        return None;
    }
    let (owner, repo) = repository.split_once('/')?;
    let valid = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    (valid(owner) && valid(repo)).then_some((owner, repo))
}

pub(crate) fn expected(rule: &EffectiveRule) -> Result<Vec<ExpectedTemplate>> {
    let value = rule
        .params
        .get("templates")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    if value.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("minimum").is_some_and(|v| !v.is_string()))
    }) {
        return Err(Error::Policy(format!(
            "{RULE} minimum must be a ref string when present"
        )));
    }
    let entries: Vec<ExpectedTemplate> = serde_json::from_value(value)
        .map_err(|e| Error::Policy(format!("{RULE} templates: {e}")))?;
    let mut pairs = BTreeSet::new();
    for entry in &entries {
        if source(&entry.source).is_none()
            || !path(&entry.target, true)
            || entry.reference.trim().is_empty()
            || entry.minimum.as_ref().is_some_and(|v| v.trim().is_empty())
        {
            return Err(Error::Policy(format!(
                "{RULE} invalid source, target, ref or minimum for {}",
                entry.source
            )));
        }
        if !pairs.insert((&entry.source, &entry.target)) {
            return Err(Error::Policy(format!(
                "{RULE} duplicate source/target pair"
            )));
        }
        let mut parts = BTreeSet::new();
        for part in &entry.parts {
            if part.is_empty()
                || !part.as_bytes()[0].is_ascii_alphanumeric()
                || !part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
                || !parts.insert(part)
            {
                return Err(Error::Policy(format!(
                    "{RULE} invalid or duplicate part name {part}"
                )));
            }
        }
    }
    Ok(entries)
}

pub(crate) fn record_path(rule: &EffectiveRule) -> &str {
    rule.param_str("record-path").unwrap_or(RECORD)
}

pub(crate) fn validate(rule: &EffectiveRule) -> Result<()> {
    if rule
        .params
        .get("record-path")
        .is_some_and(|v| !v.as_str().is_some_and(|s| path(s, false)))
    {
        return Err(Error::Policy(format!(
            "{RULE} record-path must be a repository-relative file path"
        )));
    }
    expected(rule)?;
    Ok(())
}
