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

mod compilation;
mod digest;
mod fetch;
mod references;
mod source;
mod suppression;

use compilation::*;
use digest::*;
use fetch::*;
use references::*;
use suppression::*;

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
    ///
    /// `Ok(None)` means the policy set no such parameter. An entry that is not
    /// a string is a malformed parameter rather than one fewer value: a policy
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
            return Ok(None);
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
    let loaded = load_source(client, source, limits, &mut budget).await?;
    let text = to_text(&source.label(), loaded.bytes)?;
    bundle.push(BundleSource {
        name: "policy".to_owned(),
        source: source.label(),
        commit: loaded.commit,
        blob_sha: loaded.blob_sha,
        content_digest: content_digest(&text),
    });

    let document = yaml::parse_mapping(&text, limits.yaml)
        .map_err(|error| Error::Policy(format!("{}: {error}", source.label())))?;

    let reference_data =
        resolve_references(client, source, &document, limits, &mut bundle, &mut budget).await?;

    compile(source, &document, reference_data, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audited_repository::parse_suppression_requests;

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
                source: "./policy.yml".to_owned(),
                commit: None,
                blob_sha: None,
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
