//! Policy resolution, pinning, and normalisation.
//!
//! Organization configuration and committed repository requests refine compiled
//! rules through reasoned exceptions. Sources are pinned and bounded before
//! evaluation. Configuration does not select rules or define predicates.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::github::GitHub;
use crate::limits::Limits;
use crate::rules::{self, RuleDefinition, Severity, RULES_VERSION};
use crate::snapshot::read_file_at;
use crate::yaml::{self, Yaml};
use crate::{Error, Result};

mod compilation;
mod digest;
mod exceptions;
mod fetch;
mod references;
mod source;

use compilation::*;
use digest::*;
use fetch::*;

pub(crate) fn reject_unknown_keys(
    document: &Yaml,
    allowed: &[&str],
    error: impl Fn(&str) -> Error,
) -> Result<()> {
    if let Some(key) = document.keys().find(|key| !allowed.contains(key)) {
        return Err(error(key));
    }
    Ok(())
}

/// Where a policy comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// A file in a GitHub repository.
    Remote {
        /// The owning account.
        owner: String,
        /// The repository name.
        repo: String,
        /// The path within the repository.
        path: String,
        /// The ref to resolve, or the default branch when absent.
        reference: Option<String>,
    },
    /// A file on disk, for development and tests.
    Local(PathBuf),
}

/// One rule instance in the effective, normalised policy.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveRule {
    /// The rules definition.
    pub def: &'static RuleDefinition,
    /// The severity after refinement.
    pub severity: Severity,
    /// The parameters after refinement.
    pub params: BTreeMap<String, serde_json::Value>,
    /// Where the rule came from.
    pub provenance: String,
}

impl EffectiveRule {
    /// An integer parameter, falling back to its compiled default.
    #[must_use]
    pub fn param_u64(&self, name: &str) -> Option<u64> {
        self.params
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .or_else(|| match self.def.parameter_default(name)? {
                crate::rules::ParameterDefault::Integer(value) => Some(value),
                _ => None,
            })
    }

    /// A string parameter, falling back to its compiled default.
    #[must_use]
    pub fn param_str(&self, name: &str) -> Option<&str> {
        self.params
            .get(name)
            .and_then(serde_json::Value::as_str)
            .or_else(|| match self.def.parameter_default(name)? {
                crate::rules::ParameterDefault::String(value) => Some(value),
                _ => None,
            })
    }

    /// A string parameter with literal owner substitution in the default only.
    /// An owner-dependent default does not resolve without an observed owner.
    #[must_use]
    pub fn param_str_for_owner(&self, name: &str, owner: Option<&str>) -> Option<String> {
        resolve_string_parameter(self.def, &self.params, name, owner)
    }

    /// A list parameter, falling back to its compiled default.
    ///
    /// `Ok(None)` means neither the policy nor the rule defines it. An entry
    /// that is not a string is a malformed parameter rather than one fewer value: a policy
    /// declaring `org-names: [wyrd-company, 42]` must not quietly check
    /// against one org name.
    ///
    /// # Errors
    ///
    /// Returns the offending entry's position when the parameter is not a list
    /// of strings.
    pub fn param_strings(
        &self,
        name: &str,
    ) -> std::result::Result<Option<Vec<String>>, MalformedParam> {
        let Some(value) = self.params.get(name) else {
            return Ok(match self.def.parameter_default(name) {
                Some(crate::rules::ParameterDefault::Strings(values)) => {
                    Some(values.iter().map(|value| (*value).to_owned()).collect())
                }
                _ => None,
            });
        };
        let Some(entries) = value.as_array() else {
            return Err(MalformedParam {
                rule: self.def.id,
                param: name.to_owned(),
                detail: "is not a list".to_owned(),
            });
        };
        let mut values = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let Some(entry) = entry.as_str() else {
                return Err(MalformedParam {
                    rule: self.def.id,
                    param: name.to_owned(),
                    detail: format!("has a non-string entry at position {}", index + 1),
                });
            };
            values.push(entry.to_owned());
        }
        Ok(Some(values))
    }
}

/// Resolve the same string parameter for evaluation and file authoring.
pub(crate) fn resolve_string_parameter(
    definition: &RuleDefinition,
    params: &BTreeMap<String, serde_json::Value>,
    name: &str,
    owner: Option<&str>,
) -> Option<String> {
    if let Some(value) = params.get(name).and_then(serde_json::Value::as_str) {
        return Some(value.to_owned());
    }
    let rules::ParameterDefault::String(value) = definition.parameter_default(name)? else {
        return None;
    };
    if value.contains("{owner}") {
        let owner = owner.filter(|owner| !owner.is_empty())?;
        Some(value.replace("{owner}", owner))
    } else {
        Some(value.to_owned())
    }
}

/// A policy parameter airlock could read but not understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedParam {
    /// The rule the parameter belongs to.
    pub rule: &'static str,
    /// The parameter name.
    pub param: String,
    /// What is wrong with it.
    pub detail: String,
}

impl std::fmt::Display for MalformedParam {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the `{}` parameter on {} {}",
            self.param, self.rule, self.detail
        )
    }
}

/// A suppression the policy grants directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectSuppression {
    /// The rule it suppresses.
    pub rule: String,
    /// The repository it applies to, or every repository under the policy.
    pub repository: Option<String>,
    /// Why.
    pub reason: String,
}

/// Who may suppress what.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionAuthority {
    /// Suppressions the policy grants outright.
    pub direct: Vec<DirectSuppression>,
    /// Rules an audited repository may ask to suppress for itself.
    pub allow_repo_requests: BTreeSet<String>,
}

impl SuppressionAuthority {
    /// The direct suppression covering `rule` for `repository`, if any.
    #[must_use]
    pub fn direct_for(&self, rule: &str, repository: &str) -> Option<&DirectSuppression> {
        self.direct.iter().find(|suppression| {
            suppression.rule == rule
                && suppression
                    .repository
                    .as_ref()
                    .is_none_or(|target| target == repository)
        })
    }
}

/// A suppression the audited repository asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionRequest {
    /// The rule it asks to suppress.
    pub rule: String,
    /// Why. An empty reason makes the request invalid.
    pub reason: String,
}

/// One source that went into the policy bundle.
///
/// The point of pinning reference data is that a reader of a findings document
/// can see *which* blob produced the bundle digest, so every field here is
/// reported rather than folded away into the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSource {
    /// The reference name, or `policy` for the root document.
    pub name: String,
    /// Where it was resolved from: `owner/repo:path` or a local path.
    pub source: String,
    /// The commit it was pinned to, for a remote source.
    pub commit: Option<String>,
    /// The blob sha, for a remote source.
    pub blob_sha: Option<String>,
    /// A digest over the source's bytes, which is what a local source pins to.
    pub content_digest: String,
}

impl BundleSource {
    /// The immutable identity, as one string, for the bundle digest.
    #[must_use]
    pub fn identity(&self) -> String {
        match (&self.commit, &self.blob_sha) {
            (Some(commit), Some(blob)) => format!("{}@{commit}#{blob}", self.source),
            (Some(commit), None) => format!("{}@{commit}", self.source),
            _ => format!("{}#{}", self.source, self.content_digest),
        }
    }
}

/// A policy, resolved, pinned, and normalised.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// The accepted Airlock generation.
    pub accepted_version: semver::Version,
    /// Organization-owned reasoned exceptions.
    pub exceptions: BTreeMap<String, Exception>,
    /// The organization name derived from its source.
    pub name: String,
    /// Where it came from.
    pub source: String,
    /// The commit it was pinned to, for a remote source.
    pub commit: Option<String>,
    /// The digest over the normalised policy and every referenced blob.
    pub bundle_digest: String,
    /// Every source in the bundle, in resolution order.
    pub sources: Vec<BundleSource>,
    /// The effective rule instances, ordered by rule id.
    pub rules: Vec<EffectiveRule>,
    /// Who may suppress what.
    pub suppressions: SuppressionAuthority,
}

impl ResolvedPolicy {
    /// The effective configuration for a compiled rule id.
    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&EffectiveRule> {
        self.rules.iter().find(|rule| rule.def.id == id)
    }
}

pub(crate) const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "version",
    "exceptions",
    "description",
    "topics",
    "merge",
    "features",
    "visibility",
    "properties",
];

/// Reasoned per-rule configuration. Repository entries are requests.
#[derive(Debug, Clone, Default)]
pub struct Exception {
    pub reason: String,
    pub severity: Option<Severity>,
    pub params: BTreeMap<String, serde_json::Value>,
    pub allow_override: Option<bool>,
    pub repositories: BTreeMap<String, Exception>,
}

/// Resolve, pin, and normalise a policy.
///
/// # Errors
///
/// Every failure here is a policy error: the audit cannot run, and the caller
/// exits 2.
pub async fn resolve<G: GitHub>(
    client: &G,
    source: &PolicySource,
    limits: &Limits,
) -> Result<ResolvedPolicy> {
    let mut bundle = Vec::new();
    // The bundle has one aggregate byte budget across the root policy and
    // every reference. Each source is capped at whatever is still left, so a
    // blob that would exceed it is refused before it is fetched.
    let mut budget = ByteBudget::new(limits.max_total_bytes);
    let loaded = load_source(client, source, limits, &mut budget).await?;
    let text = to_text(&source.label(), loaded.bytes)?;
    bundle.push(BundleSource {
        name: "policy".to_owned(),
        source: source.label(),
        commit: loaded.commit,
        blob_sha: loaded.blob_sha,
        content_digest: content_digest(&text),
    });

    let mut document = yaml::parse_mapping(&text, limits.yaml)
        .map_err(|error| Error::Policy(format!("{}: {error}", source.label())))?;

    references::resolve_references(
        client,
        source,
        &mut document,
        limits,
        &mut bundle,
        &mut budget,
    )
    .await?;
    compile(source, &document, bundle)
}

/// The current accepted generation for programmatically constructed configurations.
#[must_use]
pub fn current_generation() -> semver::Version {
    semver::Version::parse(RULES_VERSION).expect("compiled generation is valid")
}

impl ResolvedPolicy {
    /// Resolve organization scope and authorized committed repository requests.
    /// Unapproved requests are retained for the audit's policy observations.
    pub(crate) fn for_repository(
        &self,
        name: &str,
        text: Option<&str>,
        limits: &Limits,
    ) -> Result<Self> {
        let mut result = self.clone();
        let document = text
            .map(|text| {
                yaml::parse_mapping(text, limits.yaml)
                    .map_err(|e| Error::Policy(format!(".github/airlock.yml: {e}")))
            })
            .transpose()?;
        // The reserved repository carries organization configuration, not requests.
        let organization = name.rsplit('/').next() == Some(".github");
        let requests = if organization {
            BTreeMap::new()
        } else if let Some(document) = &document {
            compilation::validate_document(document)?;
            let version = compilation::accepted_version(document)?;
            if version < self.accepted_version {
                return Err(Error::Policy(format!(
                    "repository version {version} is below organization version {}",
                    self.accepted_version
                )));
            }
            result.accepted_version = version;
            exceptions::parse(document, true)?
        } else {
            BTreeMap::new()
        };
        for rule in &mut result.rules {
            let grant = self.exceptions.get(rule.def.id);
            let scoped = grant.and_then(|e| e.repositories.get(name));
            let allowed = !requests
                .get(rule.def.id)
                .is_some_and(|r| r.allow_override.is_some())
                && rule.def.allow_override()
                && grant.and_then(|e| e.allow_override) != Some(false)
                && scoped.and_then(|e| e.allow_override) != Some(false);
            if rule.def.params.iter().any(|p| {
                matches!(p.default, rules::ParameterDefault::Required)
                    && !rule.params.contains_key(p.name)
            }) && grant.and_then(|e| e.severity) != Some(Severity::None)
            {
                rule.severity = grant.and_then(|e| e.severity).unwrap_or(rule.def.severity);
            }
            if let Some(scoped) = scoped {
                exceptions::apply(rule, scoped)?;
            }
            if allowed {
                result
                    .suppressions
                    .allow_repo_requests
                    .insert(rule.def.id.into());
                if let Some(request) = requests
                    .get(rule.def.id)
                    .filter(|r| r.allow_override.is_none())
                {
                    exceptions::apply(rule, request)?;
                }
            }
            exceptions::validate_required(rule)?;
            let exception = if allowed {
                requests
                    .get(rule.def.id)
                    .filter(|r| r.allow_override.is_none())
            } else {
                None
            }
            .or(scoped)
            .or(grant);
            if rule.severity == Severity::None {
                if let Some(exception) = exception {
                    result.suppressions.direct.push(DirectSuppression {
                        rule: rule.def.id.into(),
                        repository: Some(name.into()),
                        reason: exception.reason.clone(),
                    });
                }
            }
        }
        Ok(result)
    }
}

pub(crate) use compilation::{accepted_version, validate_document};
pub(crate) fn repository_exceptions(document: &Yaml) -> Result<BTreeMap<String, Exception>> {
    exceptions::parse(document, true)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn parameter_json(value: &Yaml) -> serde_json::Value {
    compilation::to_json(value)
}

#[cfg(test)]
mod template_exception_tests;
