//! Policy resolution, pinning, and normalisation.
//!
//! A policy selects capabilities, refines the checks they bring in, and
//! declares who may suppress what. It cannot express predicates: the checks
//! themselves are the only place logic lives.
//!
//! Before anything is evaluated the policy and every transitive reference are
//! resolved to immutable identities and hashed into one bundle digest, so an
//! audit result names exactly the inputs that produced it. Anything airlock
//! cannot resolve, parse, or recognise is a policy error — never a silently
//! narrower audit.
//!
//! Suppression authority lives in the policy. The audited repository may only
//! *request* a suppression, and a request is honoured only where the policy
//! named that rule. The artefact being judged never controls the exceptions to
//! the judge.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::findings::Gate;
use crate::github::GitHub;
use crate::limits::Limits;
use crate::registry::{self, CheckDef, Section, Severity, REGISTRY_VERSION};
use crate::snapshot::read_file_at;
use crate::yaml::{self, Yaml};
use crate::{Error, Result};

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

impl PolicySource {
    /// The canonical policy location for an owner.
    #[must_use]
    pub fn default_for_owner(owner: &str) -> Self {
        PolicySource::Remote {
            owner: owner.to_owned(),
            repo: ".github".to_owned(),
            path: "airlock/policy.yml".to_owned(),
            reference: None,
        }
    }

    /// Parse a `--policy` value.
    ///
    /// # Errors
    ///
    /// Returns a policy error when the value is neither a local path nor a
    /// well-formed `owner/repo:path[@ref]` reference.
    pub fn parse(value: &str) -> Result<Self> {
        if value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with('/')
            || value.starts_with('~')
        {
            return Ok(PolicySource::Local(PathBuf::from(value)));
        }

        let Some((repository, rest)) = value.split_once(':') else {
            return Err(Error::Policy(format!(
                "`{value}` is neither a local path (starting `./`, `../`, or `/`) nor an \
                 `owner/repo:path[@ref]` reference"
            )));
        };
        let Some((owner, repo)) = repository.split_once('/') else {
            return Err(Error::Policy(format!(
                "`{value}` should name a repository as `owner/repo:path[@ref]`"
            )));
        };
        let (path, reference) = match rest.split_once('@') {
            Some((path, reference)) => (path, Some(reference.to_owned())),
            None => (rest, None),
        };
        if owner.is_empty() || repo.is_empty() || path.is_empty() {
            return Err(Error::Policy(format!(
                "`{value}` has an empty owner, repository, or path"
            )));
        }
        Ok(PolicySource::Remote {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            path: path.to_owned(),
            reference,
        })
    }

    /// A stable label for output.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            PolicySource::Remote {
                owner,
                repo,
                path,
                reference,
            } => match reference {
                Some(reference) => format!("{owner}/{repo}:{path}@{reference}"),
                None => format!("{owner}/{repo}:{path}"),
            },
            PolicySource::Local(path) => path.display().to_string(),
        }
    }
}

/// A named condition a capability may be applied under.
///
/// Conditions are built into airlock. A policy names one; it cannot define one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// The capability always applies.
    Always,
    /// The capability applies when the repository declares release units.
    IntentionalConfigPresent,
}

impl Condition {
    /// Parse a condition by name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "always" => Some(Condition::Always),
            "intentional-config-present" => Some(Condition::IntentionalConfigPresent),
            _ => None,
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Condition::Always => "always",
            Condition::IntentionalConfigPresent => "intentional-config-present",
        }
    }
}

/// One rule instance in the effective, normalised policy.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleInstance {
    /// The registry definition.
    pub def: &'static CheckDef,
    /// The severity after refinement.
    pub severity: Severity,
    /// The parameters after refinement.
    pub params: BTreeMap<String, serde_json::Value>,
    /// Where the rule came from.
    pub provenance: String,
    /// The condition the capability that brought it in applies under.
    pub condition: Condition,
}

impl RuleInstance {
    /// A parameter as an integer, when the policy set one.
    #[must_use]
    pub fn param_u64(&self, name: &str) -> Option<u64> {
        self.params.get(name)?.as_u64()
    }

    /// A parameter as a string, when the policy set one.
    #[must_use]
    pub fn param_str(&self, name: &str) -> Option<&str> {
        self.params.get(name)?.as_str()
    }

    /// A parameter as a list of strings, when the policy set one.
    #[must_use]
    pub fn param_strings(&self, name: &str) -> Option<Vec<String>> {
        Some(
            self.params
                .get(name)?
                .as_array()?
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect(),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSource {
    /// The reference name, or `policy` for the root document.
    pub name: String,
    /// The immutable identity the source resolved to.
    pub identity: String,
    /// A digest over the source's bytes.
    pub content_digest: String,
}

/// A policy, resolved, pinned, and normalised.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// The policy's declared name.
    pub name: String,
    /// Where it came from.
    pub source: String,
    /// The commit it was pinned to, for a remote source.
    pub commit: Option<String>,
    /// The digest over the normalised policy and every referenced blob.
    pub bundle_digest: String,
    /// Every source in the bundle, in resolution order.
    pub sources: Vec<BundleSource>,
    /// Which failing severities make an audit nonconformant.
    pub gate: Gate,
    /// The effective rule instances, ordered by rule id.
    pub rules: Vec<RuleInstance>,
    /// Who may suppress what.
    pub suppressions: SuppressionAuthority,
    /// Reference data, by name.
    pub reference_data: BTreeMap<String, Yaml>,
}

impl ResolvedPolicy {
    /// The rule instance for `id`, if the policy enabled it.
    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&RuleInstance> {
        self.rules.iter().find(|rule| rule.def.id == id)
    }
}

const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "version",
    "name",
    "requires-registry",
    "gate",
    "capabilities",
    "apply",
    "checks",
    "suppressions",
    "reference-data",
];

const POLICY_SCHEMA_VERSION: i64 = 1;

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
    let (commit, bytes) = load_source(client, source, limits, &mut budget).await?;
    let text = to_text(&source.label(), bytes)?;
    bundle.push(BundleSource {
        name: "policy".to_owned(),
        identity: match &commit {
            Some(commit) => format!("{}@{commit}", source.label()),
            None => format!("{}#{}", source.label(), content_digest(&text)),
        },
        content_digest: content_digest(&text),
    });

    let document = yaml::parse_mapping(&text, limits.yaml)
        .map_err(|error| Error::Policy(format!("{}: {error}", source.label())))?;

    let reference_data =
        resolve_references(client, source, &document, limits, &mut bundle, &mut budget).await?;

    compile(source, &document, reference_data, bundle)
}

/// What is left of the policy bundle's aggregate byte budget.
///
/// A per-file cap alone lets sixteen individually legal references add up to
/// far more than one audit is allowed to hold, so the budget is spent down
/// rather than re-applied.
#[derive(Debug, Clone, Copy)]
struct ByteBudget {
    total: usize,
    used: usize,
}

impl ByteBudget {
    fn new(total: usize) -> Self {
        Self { total, used: 0 }
    }

    fn remaining(&self) -> usize {
        self.total.saturating_sub(self.used)
    }

    /// The most one source may occupy: the smaller of the per-blob cap and
    /// whatever the bundle has left.
    fn cap_for(&self, per_source: usize) -> usize {
        per_source.min(self.remaining())
    }

    fn spend(&mut self, label: &str, bytes: usize) -> Result<()> {
        if bytes > self.remaining() {
            return Err(Error::Policy(format!(
                "the policy bundle exceeds its {} byte budget at {label}; {} bytes were already \
                 read and this source adds {bytes}",
                self.total, self.used
            )));
        }
        self.used += bytes;
        Ok(())
    }
}

async fn load_source<G: GitHub>(
    client: &G,
    source: &PolicySource,
    limits: &Limits,
    budget: &mut ByteBudget,
) -> Result<(Option<String>, Vec<u8>)> {
    let cap = budget.cap_for(limits.max_blob_bytes);
    match source {
        PolicySource::Local(path) => {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                Error::Policy(format!("cannot read policy {}: {error}", path.display()))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(Error::Policy(format!(
                    "{} is a symlink; airlock never follows a link to reach a file it will trust",
                    path.display()
                )));
            }
            if metadata.len() as usize > cap {
                return Err(Error::Policy(format!(
                    "{} is {} bytes, over the {cap} bytes the policy bundle has left of its {} \
                     byte budget",
                    path.display(),
                    metadata.len(),
                    limits.max_total_bytes
                )));
            }
            let bytes = std::fs::read(path).map_err(|error| Error::Io {
                path: path.clone(),
                source: error,
            })?;
            budget.spend(&path.display().to_string(), bytes.len())?;
            Ok((None, bytes))
        }
        PolicySource::Remote {
            owner,
            repo,
            path,
            reference,
        } => {
            let target = reference.as_deref().unwrap_or("HEAD");
            let commit = client
                .resolve_commit(owner, repo, target)
                .await
                .map_err(|error| {
                    Error::Policy(format!(
                        "cannot resolve `{target}` in {owner}/{repo}: {error}"
                    ))
                })?;
            // `read_file_at` compares the tree entry's declared size against
            // the cap, so an oversized blob is refused before it is fetched.
            let file = read_file_at(client, owner, repo, &commit, path, cap)
                .await
                .map_err(|error| {
                    Error::Policy(format!("cannot read {owner}/{repo}:{path}: {error}"))
                })?;
            let Some((_, bytes)) = file else {
                return Err(Error::Policy(format!(
                    "no policy at {owner}/{repo}:{path}@{commit}. Airlock ships no built-in \
                     policy, so there is nothing to audit against."
                )));
            };
            budget.spend(&format!("{owner}/{repo}:{path}"), bytes.len())?;
            Ok((Some(commit), bytes))
        }
    }
}

fn to_text(label: &str, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::Policy(format!("{label} is not valid UTF-8")))
}

fn content_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Resolve `reference-data`, transitively, pinned, bounded, and cycle-free.
async fn resolve_references<G: GitHub>(
    client: &G,
    root: &PolicySource,
    document: &Yaml,
    limits: &Limits,
    bundle: &mut Vec<BundleSource>,
    budget: &mut ByteBudget,
) -> Result<BTreeMap<String, Yaml>> {
    let mut resolved = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<(String, String, usize)> = Vec::new();

    collect_references(document, 0, &mut queue)?;

    let mut count = 0;
    while let Some((name, reference, depth)) = queue.pop() {
        if depth > limits.max_policy_reference_depth {
            return Err(Error::Policy(format!(
                "reference `{name}` is nested deeper than the {} level limit",
                limits.max_policy_reference_depth
            )));
        }
        count += 1;
        if count > limits.max_policy_references {
            return Err(Error::Policy(format!(
                "the policy bundle has more than the {} reference limit",
                limits.max_policy_references
            )));
        }
        if !seen.insert(reference.clone()) {
            return Err(Error::Policy(format!(
                "reference `{reference}` is reached twice; the policy bundle must be acyclic"
            )));
        }

        let source = resolve_reference_source(root, &reference)?;
        let (commit, bytes) = load_source(client, &source, limits, budget).await?;
        let text = to_text(&source.label(), bytes)?;
        bundle.push(BundleSource {
            name: name.clone(),
            identity: match &commit {
                Some(commit) => format!("{}@{commit}", source.label()),
                None => format!("{}#{}", source.label(), content_digest(&text)),
            },
            content_digest: content_digest(&text),
        });

        let parsed = yaml::parse_mapping(&text, limits.yaml)
            .map_err(|error| Error::Policy(format!("{}: {error}", source.label())))?;
        collect_references(&parsed, depth + 1, &mut queue)?;
        resolved.insert(name, parsed);
    }

    Ok(resolved)
}

fn collect_references(
    document: &Yaml,
    depth: usize,
    queue: &mut Vec<(String, String, usize)>,
) -> Result<()> {
    let Some(references) = document.get("reference-data") else {
        return Ok(());
    };
    let Some(entries) = references.as_map() else {
        return Err(Error::Policy(format!(
            "`reference-data` should be a mapping of name to source, found {}",
            references.kind()
        )));
    };
    for (name, value) in entries {
        let Some(reference) = value.as_str() else {
            return Err(Error::Policy(format!(
                "reference `{name}` should be a string source, found {}",
                value.kind()
            )));
        };
        queue.push((name.clone(), reference.to_owned(), depth));
    }
    Ok(())
}

/// A reference resolves relative to the policy it came from: a local policy may
/// reference local files, a remote one may not reach the auditing machine's
/// disk.
fn resolve_reference_source(root: &PolicySource, reference: &str) -> Result<PolicySource> {
    let source = PolicySource::parse(reference)?;
    match (&source, root) {
        (PolicySource::Local(path), PolicySource::Remote { .. }) => Err(Error::Policy(format!(
            "a remote policy cannot reference the local file `{}`",
            path.display()
        ))),
        (PolicySource::Local(path), PolicySource::Local(root)) => {
            // Resolve relative to the policy file, not the working directory.
            let base = root.parent().unwrap_or_else(|| Path::new("."));
            Ok(PolicySource::Local(base.join(path)))
        }
        _ => Ok(source),
    }
}

fn compile(
    source: &PolicySource,
    document: &Yaml,
    reference_data: BTreeMap<String, Yaml>,
    sources: Vec<BundleSource>,
) -> Result<ResolvedPolicy> {
    for key in document.keys() {
        if !KNOWN_TOP_LEVEL_KEYS.contains(&key) {
            return Err(Error::Policy(format!(
                "unknown policy key `{key}`; airlock accepts {}",
                KNOWN_TOP_LEVEL_KEYS.join(", ")
            )));
        }
    }

    match document.get("version").and_then(Yaml::as_i64) {
        Some(POLICY_SCHEMA_VERSION) => {}
        Some(other) => {
            return Err(Error::Policy(format!(
                "policy schema version {other} is not supported; airlock understands version \
                 {POLICY_SCHEMA_VERSION}"
            )))
        }
        None => {
            return Err(Error::Policy(
                "the policy must declare `version: 1`".to_owned(),
            ))
        }
    }

    let name = document
        .get("name")
        .and_then(Yaml::as_str)
        .ok_or_else(|| Error::Policy("the policy must declare a `name`".to_owned()))?
        .to_owned();

    check_registry_requirement(document)?;

    let gate = match document.get("gate").and_then(Yaml::as_str) {
        Some(value) => Gate::parse(value).ok_or_else(|| {
            Error::Policy(format!(
                "unknown gate `{value}`; airlock accepts `blocking` or `required`"
            ))
        })?,
        None => {
            return Err(Error::Policy(
                "the policy must declare a `gate` of `blocking` or `required`".to_owned(),
            ))
        }
    };

    let capabilities = read_capabilities(document)?;
    let conditions = read_apply(document, &capabilities)?;
    let mut rules = expand_capabilities(&capabilities, &conditions);
    apply_check_refinements(document, &mut rules)?;

    let suppressions = read_suppressions(document, &rules)?;

    let mut rules: Vec<RuleInstance> = rules.into_values().collect();
    rules.sort_by(|left, right| left.def.id.cmp(right.def.id));

    let bundle_digest = bundle_digest(&sources, &rules, gate);

    Ok(ResolvedPolicy {
        name,
        source: source.label(),
        commit: sources
            .first()
            .and_then(|first| first.identity.split('@').next_back().map(ToOwned::to_owned))
            .filter(|_| matches!(source, PolicySource::Remote { .. })),
        bundle_digest,
        sources,
        gate,
        rules,
        suppressions,
        reference_data,
    })
}

fn check_registry_requirement(document: &Yaml) -> Result<()> {
    let Some(requirement) = document.get("requires-registry") else {
        return Ok(());
    };
    let Some(requirement) = requirement.as_str() else {
        return Err(Error::Policy(
            "`requires-registry` should be a semver requirement string".to_owned(),
        ));
    };
    let requirement = semver::VersionReq::parse(requirement).map_err(|error| {
        Error::Policy(format!(
            "`requires-registry: {requirement}` is not a semver requirement: {error}"
        ))
    })?;
    let version = semver::Version::parse(REGISTRY_VERSION).map_err(|error| {
        Error::Policy(format!("the compiled registry version is invalid: {error}"))
    })?;
    if !requirement.matches(&version) {
        return Err(Error::Policy(format!(
            "this airlock carries check registry {REGISTRY_VERSION}, which does not satisfy the \
             policy's `requires-registry: {requirement}`"
        )));
    }
    Ok(())
}

fn read_capabilities(document: &Yaml) -> Result<Vec<(String, Vec<Section>)>> {
    let Some(capabilities) = document.get("capabilities") else {
        return Err(Error::Policy(
            "the policy must declare at least one capability".to_owned(),
        ));
    };
    let Some(entries) = capabilities.as_map() else {
        return Err(Error::Policy(format!(
            "`capabilities` should be a mapping of capability name to sections, found {}",
            capabilities.kind()
        )));
    };
    if entries.is_empty() {
        return Err(Error::Policy(
            "the policy must declare at least one capability".to_owned(),
        ));
    }

    let mut capabilities = Vec::new();
    for (capability, value) in entries {
        let Some(sections) = value.as_seq() else {
            return Err(Error::Policy(format!(
                "capability `{capability}` should list sections, found {}",
                value.kind()
            )));
        };
        let mut parsed = Vec::new();
        for section in sections {
            let Some(section) = section.as_str() else {
                return Err(Error::Policy(format!(
                    "capability `{capability}` should list section names as strings"
                )));
            };
            let section = Section::parse(section).ok_or_else(|| {
                Error::Policy(format!(
                    "unknown section `{section}` in capability `{capability}`; airlock knows {}",
                    Section::ALL
                        .iter()
                        .map(|section| section.code())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            parsed.push(section);
        }
        capabilities.push((capability.clone(), parsed));
    }
    Ok(capabilities)
}

fn read_apply(
    document: &Yaml,
    capabilities: &[(String, Vec<Section>)],
) -> Result<BTreeMap<String, Condition>> {
    let mut conditions: BTreeMap<String, Condition> = capabilities
        .iter()
        .map(|(name, _)| (name.clone(), Condition::Always))
        .collect();

    let Some(apply) = document.get("apply") else {
        return Ok(conditions);
    };
    let Some(entries) = apply.as_map() else {
        return Err(Error::Policy(format!(
            "`apply` should be a mapping of capability name to condition, found {}",
            apply.kind()
        )));
    };

    for (capability, value) in entries {
        if !conditions.contains_key(capability) {
            return Err(Error::Policy(format!(
                "`apply` names capability `{capability}`, which `capabilities` does not declare"
            )));
        }
        let condition = match value {
            Yaml::String(name) => Condition::parse(name).ok_or_else(|| {
                Error::Policy(format!(
                    "unknown condition `{name}` on capability `{capability}`"
                ))
            })?,
            Yaml::Map(_) => {
                let when = value.get("when").and_then(Yaml::as_str).ok_or_else(|| {
                    Error::Policy(format!(
                        "capability `{capability}` should be applied `always` or under a `when:` \
                         condition"
                    ))
                })?;
                for key in value.keys() {
                    if key != "when" {
                        return Err(Error::Policy(format!(
                            "unknown key `{key}` in the `apply` entry for `{capability}`"
                        )));
                    }
                }
                Condition::parse(when).ok_or_else(|| {
                    Error::Policy(format!(
                        "unknown condition `{when}` on capability `{capability}`"
                    ))
                })?
            }
            other => {
                return Err(Error::Policy(format!(
                    "the `apply` entry for `{capability}` should be a condition name or a `when:` \
                     mapping, found {}",
                    other.kind()
                )))
            }
        };
        conditions.insert(capability.clone(), condition);
    }
    Ok(conditions)
}

/// Expand capabilities into rule instances.
///
/// A rule reachable through more than one capability is instantiated once; the
/// first capability that names it, in declaration order, owns its provenance.
fn expand_capabilities(
    capabilities: &[(String, Vec<Section>)],
    conditions: &BTreeMap<String, Condition>,
) -> BTreeMap<&'static str, RuleInstance> {
    let mut rules: BTreeMap<&'static str, RuleInstance> = BTreeMap::new();
    for (capability, sections) in capabilities {
        let condition = conditions
            .get(capability)
            .copied()
            .unwrap_or(Condition::Always);
        for section in sections {
            for def in registry::in_section(*section) {
                rules.entry(def.id).or_insert_with(|| RuleInstance {
                    def,
                    severity: def.severity,
                    params: BTreeMap::new(),
                    provenance: format!("capability:{capability}/{section}"),
                    condition,
                });
            }
        }
    }
    rules
}

fn apply_check_refinements(
    document: &Yaml,
    rules: &mut BTreeMap<&'static str, RuleInstance>,
) -> Result<()> {
    let Some(checks) = document.get("checks") else {
        return Ok(());
    };
    let Some(entries) = checks.as_map() else {
        return Err(Error::Policy(format!(
            "`checks` should be a mapping of rule id to refinement, found {}",
            checks.kind()
        )));
    };

    for (id, refinement) in entries {
        let def = registry::find(id).ok_or_else(|| {
            Error::Policy(format!(
                "`checks` names `{id}`, which is not a rule airlock knows"
            ))
        })?;
        if !rules.contains_key(def.id) {
            return Err(Error::Policy(format!(
                "`checks` refines `{id}`, which no enabled capability brings in"
            )));
        }
        let Some(fields) = refinement.as_map() else {
            return Err(Error::Policy(format!(
                "the `checks` entry for `{id}` should be a mapping, found {}",
                refinement.kind()
            )));
        };
        for (key, _) in fields {
            if !["params", "severity", "enabled"].contains(&key.as_str()) {
                return Err(Error::Policy(format!(
                    "unknown key `{key}` in the `checks` entry for `{id}`; airlock accepts \
                     params, severity, enabled"
                )));
            }
        }

        // `enabled: false` always wins, whatever else the entry says.
        if refinement.get("enabled").and_then(Yaml::as_bool) == Some(false) {
            rules.remove(def.id);
            continue;
        }

        let rule = rules.get_mut(def.id).expect("membership checked above");
        rule.provenance = format!("{};refined-by:checks", rule.provenance);

        if let Some(severity) = refinement.get("severity") {
            let Some(severity) = severity.as_str().and_then(Severity::parse) else {
                return Err(Error::Policy(format!(
                    "unknown severity in the `checks` entry for `{id}`; airlock accepts blocking, \
                     required, observation"
                )));
            };
            rule.severity = severity;
        }

        if let Some(params) = refinement.get("params") {
            let Some(params) = params.as_map() else {
                return Err(Error::Policy(format!(
                    "`params` in the `checks` entry for `{id}` should be a mapping, found {}",
                    params.kind()
                )));
            };
            for (name, value) in params {
                if !def.params.contains(&name.as_str()) {
                    return Err(Error::Policy(format!(
                        "`{id}` declares no parameter `{name}`; it accepts {}",
                        if def.params.is_empty() {
                            "none".to_owned()
                        } else {
                            def.params.join(", ")
                        }
                    )));
                }
                rule.params.insert(name.clone(), to_json(value));
            }
        }
    }
    Ok(())
}

fn to_json(value: &Yaml) -> serde_json::Value {
    match value {
        Yaml::Null => serde_json::Value::Null,
        Yaml::Bool(value) => serde_json::Value::Bool(*value),
        Yaml::Int(value) => serde_json::Value::from(*value),
        Yaml::Float(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Yaml::String(value) => serde_json::Value::String(value.clone()),
        Yaml::Seq(values) => serde_json::Value::Array(values.iter().map(to_json).collect()),
        Yaml::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect(),
        ),
    }
}

fn read_suppressions(
    document: &Yaml,
    rules: &BTreeMap<&'static str, RuleInstance>,
) -> Result<SuppressionAuthority> {
    let Some(suppressions) = document.get("suppressions") else {
        return Ok(SuppressionAuthority::default());
    };
    let Some(entries) = suppressions.as_map() else {
        return Err(Error::Policy(format!(
            "`suppressions` should be a mapping, found {}",
            suppressions.kind()
        )));
    };
    for (key, _) in entries {
        if !["direct", "allow-repo-requests"].contains(&key.as_str()) {
            return Err(Error::Policy(format!(
                "unknown key `{key}` under `suppressions`; airlock accepts direct, \
                 allow-repo-requests"
            )));
        }
    }

    let mut authority = SuppressionAuthority::default();

    if let Some(direct) = suppressions.get("direct") {
        let Some(items) = direct.as_seq() else {
            return Err(Error::Policy(format!(
                "`suppressions.direct` should be a sequence, found {}",
                direct.kind()
            )));
        };
        for item in items {
            for key in item.keys() {
                if !["rule", "repository", "reason"].contains(&key) {
                    return Err(Error::Policy(format!(
                        "unknown key `{key}` in a direct suppression; airlock accepts rule, \
                         repository, reason"
                    )));
                }
            }
            let rule = item.get("rule").and_then(Yaml::as_str).ok_or_else(|| {
                Error::Policy("every direct suppression must name a `rule`".to_owned())
            })?;
            registry::find(rule).ok_or_else(|| {
                Error::Policy(format!(
                    "a direct suppression names `{rule}`, which is not a rule airlock knows"
                ))
            })?;
            let reason = item
                .get("reason")
                .and_then(Yaml::as_str)
                .unwrap_or_default();
            if reason.trim().is_empty() {
                return Err(Error::Policy(format!(
                    "the direct suppression for `{rule}` must state a reason"
                )));
            }
            authority.direct.push(DirectSuppression {
                rule: rule.to_owned(),
                repository: item
                    .get("repository")
                    .and_then(Yaml::as_str)
                    .map(ToOwned::to_owned),
                reason: reason.to_owned(),
            });
        }
    }

    if let Some(allowed) = suppressions.get("allow-repo-requests") {
        let Some(items) = allowed.as_seq() else {
            return Err(Error::Policy(format!(
                "`suppressions.allow-repo-requests` should be a sequence, found {}",
                allowed.kind()
            )));
        };
        for item in items {
            let rule = item.as_str().ok_or_else(|| {
                Error::Policy(
                    "`suppressions.allow-repo-requests` should list rule ids as strings".to_owned(),
                )
            })?;
            registry::find(rule).ok_or_else(|| {
                Error::Policy(format!(
                    "`suppressions.allow-repo-requests` names `{rule}`, which is not a rule \
                     airlock knows"
                ))
            })?;
            authority.allow_repo_requests.insert(rule.to_owned());
        }
    }

    // A suppression for a rule nothing enables is dead policy, and dead policy
    // hides intent. Say so rather than carrying it silently.
    for suppression in &authority.direct {
        if !rules.contains_key(suppression.rule.as_str()) {
            return Err(Error::Policy(format!(
                "`suppressions.direct` suppresses `{}`, which no enabled capability brings in",
                suppression.rule
            )));
        }
    }

    Ok(authority)
}

fn bundle_digest(sources: &[BundleSource], rules: &[RuleInstance], gate: Gate) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"airlock-policy-bundle-1\x1e");
    hasher.update(gate.code().as_bytes());
    hasher.update(b"\x1e");
    for source in sources {
        hasher.update(source.name.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(source.identity.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(source.content_digest.as_bytes());
        hasher.update(b"\x1e");
    }
    for rule in rules {
        hasher.update(rule.def.id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(rule.severity.code().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(rule.condition.code().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(
            serde_json::to_string(&rule.params)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(b"\x1e");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Parse an audited repository's `.github/airlock.yml` suppression requests.
///
/// # Errors
///
/// Returns a policy error only when the document is unparseable or malformed.
/// A request for a rule the policy did not authorise is not an error here — it
/// is reported as an unauthorised request.
pub fn parse_suppression_requests(text: &str, limits: &Limits) -> Result<Vec<SuppressionRequest>> {
    let document = yaml::parse_mapping(text, limits.yaml)
        .map_err(|error| Error::Policy(format!(".github/airlock.yml: {error}")))?;

    for key in document.keys() {
        if !["version", "suppress"].contains(&key) {
            return Err(Error::Policy(format!(
                "unknown key `{key}` in .github/airlock.yml; airlock accepts version, suppress"
            )));
        }
    }

    match document.get("version").and_then(Yaml::as_i64) {
        Some(1) | None => {}
        Some(other) => {
            return Err(Error::Policy(format!(
                ".github/airlock.yml declares version {other}; airlock understands version 1"
            )))
        }
    }

    let Some(entries) = document.get("suppress") else {
        return Ok(Vec::new());
    };
    let Some(items) = entries.as_seq() else {
        return Err(Error::Policy(format!(
            "`suppress` in .github/airlock.yml should be a sequence, found {}",
            entries.kind()
        )));
    };

    let mut requests = Vec::new();
    for item in items {
        for key in item.keys() {
            if !["rule", "reason"].contains(&key) {
                return Err(Error::Policy(format!(
                    "unknown key `{key}` in a .github/airlock.yml suppression request"
                )));
            }
        }
        let rule = item.get("rule").and_then(Yaml::as_str).ok_or_else(|| {
            Error::Policy(
                "every .github/airlock.yml suppression request must name a `rule`".to_owned(),
            )
        })?;
        requests.push(SuppressionRequest {
            rule: rule.to_owned(),
            reason: item
                .get("reason")
                .and_then(Yaml::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }
    Ok(requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_text(text: &str) -> Result<ResolvedPolicy> {
        let limits = Limits::default();
        let document = yaml::parse_mapping(text, limits.yaml)
            .map_err(|error| Error::Policy(error.to_string()))?;
        compile(
            &PolicySource::Local(PathBuf::from("./policy.yml")),
            &document,
            BTreeMap::new(),
            vec![BundleSource {
                name: "policy".to_owned(),
                identity: "./policy.yml#test".to_owned(),
                content_digest: content_digest(text),
            }],
        )
    }

    const MINIMAL: &str = "\
version: 1
name: test
gate: blocking
capabilities:
  base: [licensing]
";

    #[test]
    fn a_minimal_policy_compiles_to_its_section() {
        let policy = compile_text(MINIMAL).unwrap();
        assert_eq!(policy.name, "test");
        assert_eq!(policy.gate, Gate::Blocking);
        assert_eq!(
            policy.rules.len(),
            registry::in_section(Section::Licensing).len()
        );
        assert_eq!(policy.rules[0].provenance, "capability:base/licensing");
    }

    #[test]
    fn rules_are_ordered_by_id() {
        let policy = compile_text(MINIMAL).unwrap();
        let ids: Vec<&str> = policy.rules.iter().map(|rule| rule.def.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn the_bundle_digest_moves_when_a_severity_is_refined() {
        let base = compile_text(MINIMAL).unwrap();
        let refined = compile_text(&format!(
            "{MINIMAL}checks:\n  REPO-LIC-01:\n    severity: observation\n"
        ))
        .unwrap();
        assert_ne!(base.bundle_digest, refined.bundle_digest);
        assert_eq!(
            refined.rule("REPO-LIC-01").unwrap().severity,
            Severity::Observation
        );
    }

    #[test]
    fn the_bundle_digest_is_stable_for_the_same_inputs() {
        assert_eq!(
            compile_text(MINIMAL).unwrap().bundle_digest,
            compile_text(MINIMAL).unwrap().bundle_digest
        );
    }

    #[test]
    fn an_unknown_top_level_key_is_a_policy_error() {
        let error = compile_text(&format!("{MINIMAL}surprise: true\n")).unwrap_err();
        assert!(error.to_string().contains("unknown policy key `surprise`"));
    }

    #[test]
    fn an_unknown_section_is_a_policy_error() {
        let error = compile_text(
            "version: 1\nname: test\ngate: blocking\ncapabilities:\n  base: [nonsense]\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown section `nonsense`"));
    }

    #[test]
    fn an_unknown_rule_id_is_a_policy_error() {
        let error = compile_text(&format!(
            "{MINIMAL}checks:\n  REPO-NOPE-01:\n    enabled: false\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains("REPO-NOPE-01"));
    }

    #[test]
    fn refining_a_rule_no_capability_enables_is_a_policy_error() {
        let error = compile_text(&format!(
            "{MINIMAL}checks:\n  REPO-CI-02:\n    severity: observation\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains("no enabled capability"));
    }

    #[test]
    fn an_unknown_parameter_is_a_policy_error() {
        let error = compile_text(
            "version: 1\nname: test\ngate: blocking\ncapabilities:\n  base: [identity]\n\
             checks:\n  REPO-META-06:\n    params: { min-topics: 3, surprise: 1 }\n",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("declares no parameter `surprise`"));
    }

    #[test]
    fn a_declared_parameter_is_carried_onto_the_rule() {
        let policy = compile_text(
            "version: 1\nname: test\ngate: blocking\ncapabilities:\n  base: [identity]\n\
             checks:\n  REPO-META-06:\n    params: { min-topics: 2, max-topics: 5 }\n",
        )
        .unwrap();
        let rule = policy.rule("REPO-META-06").unwrap();
        assert_eq!(rule.param_u64("min-topics"), Some(2));
        assert_eq!(rule.param_u64("max-topics"), Some(5));
    }

    #[test]
    fn disabling_a_rule_removes_it_entirely() {
        let policy = compile_text(&format!(
            "{MINIMAL}checks:\n  REPO-LIC-06:\n    enabled: false\n"
        ))
        .unwrap();
        assert!(policy.rule("REPO-LIC-06").is_none());
        assert!(policy.rule("REPO-LIC-01").is_some());
    }

    #[test]
    fn disabling_wins_over_a_severity_in_the_same_entry() {
        let policy = compile_text(&format!(
            "{MINIMAL}checks:\n  REPO-LIC-06:\n    enabled: false\n    severity: blocking\n"
        ))
        .unwrap();
        assert!(policy.rule("REPO-LIC-06").is_none());
    }

    #[test]
    fn the_first_capability_to_name_a_rule_owns_its_provenance() {
        let policy = compile_text(
            "version: 1\nname: test\ngate: blocking\ncapabilities:\n  base: [licensing]\n  \
             extra: [licensing]\n",
        )
        .unwrap();
        assert_eq!(
            policy.rule("REPO-LIC-01").unwrap().provenance,
            "capability:base/licensing"
        );
    }

    #[test]
    fn an_incompatible_registry_requirement_is_a_policy_error() {
        let error = compile_text(&format!("{MINIMAL}requires-registry: \">=9.0\"\n")).unwrap_err();
        assert!(error.to_string().contains("requires-registry"));
    }

    #[test]
    fn a_satisfied_registry_requirement_compiles() {
        assert!(compile_text(&format!("{MINIMAL}requires-registry: \">=0.1\"\n")).is_ok());
    }

    #[test]
    fn a_missing_gate_is_a_policy_error() {
        let error = compile_text("version: 1\nname: test\ncapabilities:\n  base: [licensing]\n")
            .unwrap_err();
        assert!(error.to_string().contains("gate"));
    }

    #[test]
    fn a_condition_is_carried_onto_every_rule_it_governs() {
        let policy = compile_text(
            "version: 1\nname: test\ngate: blocking\ncapabilities:\n  registry: [release]\n\
             apply:\n  registry:\n    when: intentional-config-present\n",
        )
        .unwrap();
        assert_eq!(
            policy.rule("REPO-REL-01").unwrap().condition,
            Condition::IntentionalConfigPresent
        );
    }

    #[test]
    fn applying_an_undeclared_capability_is_a_policy_error() {
        let error = compile_text(&format!("{MINIMAL}apply:\n  registry: always\n")).unwrap_err();
        assert!(error.to_string().contains("does not declare"));
    }

    #[test]
    fn an_unknown_condition_is_a_policy_error() {
        let error =
            compile_text(&format!("{MINIMAL}apply:\n  base:\n    when: some-day\n")).unwrap_err();
        assert!(error.to_string().contains("unknown condition"));
    }

    #[test]
    fn suppression_authority_is_read_from_the_policy() {
        let policy = compile_text(&format!(
            "{MINIMAL}suppressions:\n  direct:\n    - rule: REPO-LIC-06\n      repository: \
             owner/name\n      reason: \"deliberate\"\n  allow-repo-requests: [REPO-LIC-02]\n"
        ))
        .unwrap();
        assert!(policy
            .suppressions
            .direct_for("REPO-LIC-06", "owner/name")
            .is_some());
        assert!(policy
            .suppressions
            .direct_for("REPO-LIC-06", "owner/other")
            .is_none());
        assert!(policy
            .suppressions
            .allow_repo_requests
            .contains("REPO-LIC-02"));
    }

    #[test]
    fn a_direct_suppression_without_a_repository_covers_every_repository() {
        let policy = compile_text(&format!(
            "{MINIMAL}suppressions:\n  direct:\n    - rule: REPO-LIC-06\n      reason: \"why\"\n"
        ))
        .unwrap();
        assert!(policy
            .suppressions
            .direct_for("REPO-LIC-06", "anyone/anything")
            .is_some());
    }

    #[test]
    fn a_direct_suppression_without_a_reason_is_a_policy_error() {
        let error = compile_text(&format!(
            "{MINIMAL}suppressions:\n  direct:\n    - rule: REPO-LIC-06\n      reason: \"  \"\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains("must state a reason"));
    }

    #[test]
    fn suppressing_a_rule_no_capability_enables_is_a_policy_error() {
        let error = compile_text(&format!(
            "{MINIMAL}suppressions:\n  direct:\n    - rule: REPO-CI-02\n      reason: \"why\"\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains("no enabled capability"));
    }

    #[test]
    fn policy_sources_parse() {
        assert_eq!(
            PolicySource::parse("owner/repo:airlock/policy.yml").unwrap(),
            PolicySource::Remote {
                owner: "owner".to_owned(),
                repo: "repo".to_owned(),
                path: "airlock/policy.yml".to_owned(),
                reference: None,
            }
        );
        assert_eq!(
            PolicySource::parse("owner/repo:airlock/policy.yml@v1").unwrap(),
            PolicySource::Remote {
                owner: "owner".to_owned(),
                repo: "repo".to_owned(),
                path: "airlock/policy.yml".to_owned(),
                reference: Some("v1".to_owned()),
            }
        );
        assert_eq!(
            PolicySource::parse("./policy.yml").unwrap(),
            PolicySource::Local(PathBuf::from("./policy.yml"))
        );
        assert!(PolicySource::parse("just-a-word").is_err());
    }

    #[test]
    fn the_default_source_is_the_owners_dot_github_repository() {
        assert_eq!(
            PolicySource::default_for_owner("wyrd-company").label(),
            "wyrd-company/.github:airlock/policy.yml"
        );
    }

    #[test]
    fn a_remote_policy_cannot_reference_a_local_file() {
        let root = PolicySource::Remote {
            owner: "owner".to_owned(),
            repo: ".github".to_owned(),
            path: "airlock/policy.yml".to_owned(),
            reference: None,
        };
        assert!(resolve_reference_source(&root, "./topics.yml").is_err());
    }

    #[test]
    fn a_local_reference_resolves_beside_its_policy() {
        let root = PolicySource::Local(PathBuf::from("/tmp/policies/policy.yml"));
        assert_eq!(
            resolve_reference_source(&root, "./topics.yml").unwrap(),
            PolicySource::Local(PathBuf::from("/tmp/policies/./topics.yml"))
        );
    }

    #[test]
    fn suppression_requests_parse() {
        let requests = parse_suppression_requests(
            "version: 1\nsuppress:\n  - rule: REPO-DOCS-01\n    reason: \"stubs for now\"\n",
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].rule, "REPO-DOCS-01");
    }

    #[test]
    fn a_suppression_request_with_an_unknown_key_is_rejected() {
        let error = parse_suppression_requests(
            "suppress:\n  - rule: REPO-DOCS-01\n    forever: true\n",
            &Limits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown key `forever`"));
    }

    #[test]
    fn a_suppression_request_file_with_duplicate_keys_is_rejected() {
        let error = parse_suppression_requests(
            "version: 1\nversion: 1\nsuppress: []\n",
            &Limits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn the_bundle_budget_is_aggregate_not_per_file() {
        let mut budget = ByteBudget::new(100);
        assert_eq!(budget.cap_for(80), 80);
        budget.spend("first", 80).unwrap();
        // The second file is individually legal at 80 bytes, but the bundle
        // has only 20 left, so that is the cap it faces.
        assert_eq!(budget.cap_for(80), 20);
        let error = budget.spend("second", 80).unwrap_err().to_string();
        assert!(error.contains("policy bundle exceeds its 100 byte budget"));
        assert!(error.contains("second"));
    }

    #[test]
    fn the_bundle_budget_admits_files_that_fit_together() {
        let mut budget = ByteBudget::new(100);
        budget.spend("first", 60).unwrap();
        budget.spend("second", 40).unwrap();
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.cap_for(1_000), 0);
    }

    #[tokio::test]
    async fn a_policy_over_the_aggregate_budget_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.yml");
        std::fs::write(&path, MINIMAL).unwrap();

        let limits = Limits {
            // Smaller than the policy, while the per-blob cap stays large — so
            // only the aggregate budget can catch this.
            max_total_bytes: 8,
            ..Limits::default()
        };
        let error = resolve(&NoNetwork, &PolicySource::Local(path), &limits)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("byte"), "{error}");
    }

    #[tokio::test]
    async fn individually_valid_references_can_still_exhaust_the_bundle_budget() {
        let directory = tempfile::tempdir().unwrap();
        let padding = "x".repeat(400);
        std::fs::write(
            directory.path().join("first.yml"),
            format!("padding: {padding}\n"),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("second.yml"),
            format!("padding: {padding}\n"),
        )
        .unwrap();
        let path = directory.path().join("policy.yml");
        std::fs::write(
            &path,
            format!("{MINIMAL}reference-data:\n  first: ./first.yml\n  second: ./second.yml\n"),
        )
        .unwrap();

        // Each file fits the per-blob cap comfortably. Together with the root
        // policy they do not fit the bundle.
        let generous = Limits {
            max_total_bytes: 16 * 1024,
            ..Limits::default()
        };
        let resolved = resolve(&NoNetwork, &PolicySource::Local(path.clone()), &generous)
            .await
            .expect("all three documents fit the generous budget");
        assert_eq!(resolved.sources.len(), 3);

        let tight = Limits {
            max_blob_bytes: 4096,
            max_total_bytes: 700,
            ..Limits::default()
        };
        let error = resolve(&NoNetwork, &PolicySource::Local(path), &tight)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("byte"), "{error}");
    }

    /// A GitHub that fails every call, proving the local paths never reach it.
    struct NoNetwork;

    impl crate::github::GitHub for NoNetwork {
        async fn repository(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> crate::github::ApiResult<crate::github::Repository> {
            Err(unreachable_call())
        }
        async fn topics(&self, _owner: &str, _repo: &str) -> crate::github::ApiResult<Vec<String>> {
            Err(unreachable_call())
        }
        async fn resolve_commit(
            &self,
            _owner: &str,
            _repo: &str,
            _reference: &str,
        ) -> crate::github::ApiResult<String> {
            Err(unreachable_call())
        }
        async fn tree(
            &self,
            _owner: &str,
            _repo: &str,
            _commit: &str,
        ) -> crate::github::ApiResult<crate::github::Tree> {
            Err(unreachable_call())
        }
        async fn blob(
            &self,
            _owner: &str,
            _repo: &str,
            _sha: &str,
        ) -> crate::github::ApiResult<Vec<u8>> {
            Err(unreachable_call())
        }
        async fn tags(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> crate::github::ApiResult<crate::github::Paged<crate::github::TagRef>> {
            Err(unreachable_call())
        }
        async fn history(
            &self,
            _owner: &str,
            _repo: &str,
            _commit: &str,
            _max_commits: usize,
        ) -> crate::github::ApiResult<crate::github::Paged<crate::github::CommitSummary>> {
            Err(unreachable_call())
        }
        async fn rulesets(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> crate::github::ApiResult<crate::github::Paged<crate::github::Ruleset>> {
            Err(unreachable_call())
        }
        async fn branch_rules(
            &self,
            _owner: &str,
            _repo: &str,
            _branch: &str,
        ) -> crate::github::ApiResult<crate::github::Paged<crate::github::BranchRule>> {
            Err(unreachable_call())
        }
        async fn user_installations(
            &self,
        ) -> crate::github::ApiResult<Vec<crate::github::Installation>> {
            Err(unreachable_call())
        }
        async fn authenticated_user(
            &self,
        ) -> crate::github::ApiResult<crate::github::AuthenticatedUser> {
            Err(unreachable_call())
        }
    }

    fn unreachable_call() -> crate::github::ApiError {
        crate::github::ApiError::local(
            crate::github::ErrorCause::Transport,
            "test",
            "this test must not reach github",
        )
    }
}
