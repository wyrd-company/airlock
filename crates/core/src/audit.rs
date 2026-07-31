//! One audit run, end to end.
//!
//! The order matters. The repository and its commit are resolved once, every
//! git-backed fact is gathered at that commit, live settings are gathered
//! separately and stamped with when they were observed, and only then do the
//! checks run against what was gathered. Nothing a check reads can change
//! underneath it.

use crate::audited_repository::parse_suppression_requests;
use crate::auth::VerifiedGrant;
use crate::checks::{self, AuditContext, Workflow};
use crate::findings::{
    AirlockIdentity, AuditedRepository, EffectiveRule, Finding, PolicyIdentity, PolicyObservation,
    PolicyObservationCode, PolicySourceIdentity, RemediationClass, Report, Status, Suppression,
    SuppressionSource,
};
use crate::github::{ApiError, ErrorCause, GitHub};
use crate::limits::Limits;
use crate::policy::ResolvedPolicy;
use crate::registry::{CredentialCapability, Evaluation, Observation};
use crate::snapshot::RepoSnapshot;
use crate::yaml;
use crate::{Error, Result};

/// Paths every audit reads, whatever the policy enabled.
///
/// Reading them together keeps the request count predictable, and a check that
/// wants a path nobody listed gets a conclusive "missing" rather than a
/// surprise fetch part-way through evaluation.
const AUDITED_PATHS: &[&str] = &[
    ".config/lefthook.yml",
    ".editorconfig",
    ".github/airlock.yml",
    ".github/renovate.json",
    ".github/repo-settings.yml",
    ".gitattributes",
    ".gitignore",
    ".intentional/config.yml",
    "AGENTS.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    "CONTRIBUTING.md",
    "Cargo.toml",
    "LICENSE",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "package.json",
    "pubspec.yaml",
    "taskfile.yml",
];

/// How one audit run should behave.
#[derive(Debug, Clone, Default)]
pub struct AuditOptions {
    /// The commit, branch, or tag to audit. Defaults to the default branch.
    /// Only meaningful for API-sourced file observation: a working tree is
    /// audited as it stands.
    pub reference: Option<String>,
    /// The budgets to run under.
    pub limits: Limits,
    /// The airlock version to record.
    pub version: String,
    /// A local working tree to observe file-level rules from, instead of the
    /// API tree. Platform rules stay with the API — or, without a
    /// credential, are reported as not observed.
    pub working_tree: Option<std::path::PathBuf>,
}

/// What the credential a run presented was enumerated to be able to do.
///
/// An absent grant is not a permissive one. Airlock refuses any credential it
/// cannot enumerate before a run starts, so reaching here without one means no
/// credential was presented, and a credential that does not exist holds no
/// write permission.
fn credential_capability(grant: Option<&VerifiedGrant>) -> CredentialCapability {
    grant.map_or(
        CredentialCapability::Unauthenticated,
        VerifiedGrant::capability,
    )
}

/// The source labels one run evaluates under.
struct Sources {
    /// What file-level rules were read from.
    file: &'static str,
    /// What platform rules were read from, when they were observed at all.
    platform: Option<&'static str>,
    /// The stated terms of the working-tree observation, when one happened.
    working_tree: Option<crate::findings::WorkingTreeObservation>,
}

impl Sources {
    fn api() -> Self {
        Self {
            file: "api",
            platform: Some("api"),
            working_tree: None,
        }
    }

    fn record(&self) -> crate::findings::ObservationRecord {
        crate::findings::ObservationRecord {
            file_source: self.file.to_owned(),
            platform_source: self.platform.map(ToOwned::to_owned),
            working_tree: self.working_tree.clone(),
        }
    }
}

/// Run one audit.
///
/// # Errors
///
/// Returns an operational error when the repository itself cannot be read.
/// Anything narrower than that is a finding, not an error: one unreadable
/// endpoint makes one rule inconclusive, never the whole run.
pub async fn run<G: GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    policy: &ResolvedPolicy,
    options: &AuditOptions,
    grant: Option<&VerifiedGrant>,
) -> Result<Report> {
    if let Some(root) = options.working_tree.clone() {
        return run_mixed(client, owner, repo, policy, options, grant, &root).await;
    }

    let mut snapshot = RepoSnapshot::read(
        client,
        owner,
        repo,
        options.reference.as_deref(),
        options.limits,
    )
    .await
    .map_err(|error| repository_error(owner, repo, &error, grant))?;

    let workflow_paths = workflow_paths(&snapshot, options.limits.max_workflow_files);
    let mut paths: Vec<String> = AUDITED_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
    paths.extend(workflow_paths.paths.clone());
    snapshot.load_files(client, owner, repo, &paths).await;

    // Release-unit paths are only known once the config file has been read, so
    // they are a second pass rather than a guess.
    let unit_paths = release_unit_paths(&snapshot, options.limits);
    if !unit_paths.is_empty() {
        snapshot.load_files(client, owner, repo, &unit_paths).await;
    }

    let workflows = parse_workflows(&snapshot, &workflow_paths.paths, options.limits);
    let branch = snapshot.repository.default_branch.clone();
    let commit = snapshot.commit.clone();
    let platform = PlatformData {
        custom_property_values: observe_custom_property_values(client, owner, repo, policy).await,
        tags: client.tags(owner, repo).await,
        history: client
            .history(owner, repo, &commit, options.limits.max_history_commits)
            .await,
        rulesets: client.rulesets(owner, repo).await,
        branch_rules: client.branch_rules(owner, repo, &branch).await,
    };

    let id = Some(snapshot.repository.id);
    complete_run(
        &snapshot,
        workflows,
        workflow_paths.truncated || snapshot.tree.truncated,
        platform,
        policy,
        options,
        Sources::api(),
        credential_capability(grant),
        id,
        SuppressionInput::Snapshot,
    )
}

/// Run a mixed audit: file-level rules from a working tree, platform rules
/// from the API.
async fn run_mixed<G: GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    policy: &ResolvedPolicy,
    options: &AuditOptions,
    grant: Option<&VerifiedGrant>,
    root: &std::path::Path,
) -> Result<Report> {
    refuse_reference_with_working_tree(options)?;
    let facts = crate::worktree::read_facts(root)?;

    let repository = client
        .repository(owner, repo)
        .await
        .map_err(|error| repository_error(owner, repo, &error, grant))?;
    let topics = client.topics(owner, repo).await;
    let branch = repository.default_branch.clone();

    let mut snapshot = RepoSnapshot {
        repository,
        topics,
        commit: facts.head_commit.clone(),
        tree: facts.tree.clone(),
        files: std::collections::BTreeMap::new(),
        bytes_read: 0,
        limits: options.limits,
    };
    let workflow_paths = load_local_files(&mut snapshot, &facts, options.limits);
    let workflows = parse_workflows(&snapshot, &workflow_paths.paths, options.limits);

    let platform = PlatformData {
        custom_property_values: observe_custom_property_values(client, owner, repo, policy).await,
        tags: client.tags(owner, repo).await,
        history: client
            .history(
                owner,
                repo,
                &facts.head_commit,
                options.limits.max_history_commits,
            )
            .await,
        rulesets: client.rulesets(owner, repo).await,
        branch_rules: client.branch_rules(owner, repo, &branch).await,
    };

    let sources = Sources {
        file: "working-tree",
        platform: Some("api"),
        working_tree: Some(working_tree_observation(&facts, &branch, true)),
    };
    let id = Some(snapshot.repository.id);
    complete_run(
        &snapshot,
        workflows,
        workflow_paths.truncated,
        platform,
        policy,
        options,
        sources,
        credential_capability(grant),
        id,
        SuppressionInput::Committed(facts.head_file(".github/airlock.yml")),
    )
}

/// Run a local-only audit: file-level rules from a working tree, no
/// credential, platform rules reported as not observed — never as passing.
///
/// # Errors
///
/// Returns an operational error when the working tree cannot be read.
pub fn run_local(
    policy: &ResolvedPolicy,
    options: &AuditOptions,
    root: &std::path::Path,
) -> Result<Report> {
    refuse_reference_with_working_tree(options)?;
    let facts = crate::worktree::read_facts(root)?;

    let full_name = facts
        .remote_full_name
        .clone()
        .unwrap_or_else(|| "unknown/unknown".to_owned());
    let (owner, name) = full_name.split_once('/').unwrap_or(("unknown", "unknown"));
    let default_branch_observed = facts.observed_default_branch.is_some();
    let branch = facts
        .observed_default_branch
        .clone()
        .unwrap_or_else(|| "main".to_owned());

    // The platform's record was never read. These values exist only so the
    // snapshot has its shape; every rule that would read them is gated to
    // `not_observed` before its check runs.
    let repository = crate::github::Repository {
        full_name: full_name.clone(),
        id: 0,
        owner: owner.to_owned(),
        name: name.to_owned(),
        default_branch: branch.clone(),
        visibility: String::new(),
        description: None,
        license_spdx: None,
        allow_merge_commit: None,
        allow_squash_merge: None,
        allow_rebase_merge: None,
        delete_branch_on_merge: None,
        has_wiki: false,
        has_projects: false,
        has_discussions: false,
        has_issues: false,
        observed_at: None,
    };

    let mut snapshot = RepoSnapshot {
        repository,
        topics: Err(not_observed_error("topics")),
        commit: facts.head_commit.clone(),
        tree: facts.tree.clone(),
        files: std::collections::BTreeMap::new(),
        bytes_read: 0,
        limits: options.limits,
    };
    let workflow_paths = load_local_files(&mut snapshot, &facts, options.limits);
    let workflows = parse_workflows(&snapshot, &workflow_paths.paths, options.limits);

    let platform = PlatformData {
        custom_property_values: Err(not_observed_error("custom property values")),
        tags: Err(not_observed_error("tags")),
        history: Err(not_observed_error("history")),
        rulesets: Err(not_observed_error("rulesets")),
        branch_rules: Err(not_observed_error("branch rules")),
    };

    let sources = Sources {
        file: "working-tree",
        platform: None,
        working_tree: Some(working_tree_observation(
            &facts,
            &branch,
            default_branch_observed,
        )),
    };
    complete_run(
        &snapshot,
        workflows,
        workflow_paths.truncated,
        platform,
        policy,
        options,
        sources,
        // A local run presents no credential, so nothing was enumerated. It
        // observes no platform rule either: they are gated as not observed
        // before any check reads them.
        CredentialCapability::Unauthenticated,
        None,
        SuppressionInput::Committed(facts.head_file(".github/airlock.yml")),
    )
}

fn refuse_reference_with_working_tree(options: &AuditOptions) -> Result<()> {
    if options.reference.is_some() {
        return Err(Error::WorkingTree(
            "a working tree is audited as it stands; `--ref` applies only to API-sourced audits"
                .to_owned(),
        ));
    }
    Ok(())
}

fn working_tree_observation(
    facts: &crate::worktree::WorkingTreeFacts,
    default_branch: &str,
    default_branch_observed: bool,
) -> crate::findings::WorkingTreeObservation {
    crate::findings::WorkingTreeObservation {
        root: facts.root.display().to_string(),
        head_commit: facts.head_commit.clone(),
        dirty: facts.dirty,
        includes_uncommitted: true,
        ignored_files_excluded: true,
        default_branch: default_branch.to_owned(),
        default_branch_observed,
    }
}

/// Load the audited paths from the working tree, mirroring the API path
/// loading: the standard set, workflows, then release-unit paths once the
/// config has been read.
fn load_local_files(
    snapshot: &mut RepoSnapshot,
    facts: &crate::worktree::WorkingTreeFacts,
    limits: Limits,
) -> WorkflowPaths {
    let workflow_paths = workflow_paths(snapshot, limits.max_workflow_files);
    let mut paths: Vec<String> = AUDITED_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
    paths.extend(workflow_paths.paths.clone());
    crate::worktree::load_files(
        facts,
        &paths,
        limits,
        &mut snapshot.files,
        &mut snapshot.bytes_read,
    );

    let unit_paths = release_unit_paths(snapshot, limits);
    if !unit_paths.is_empty() {
        crate::worktree::load_files(
            facts,
            &unit_paths,
            limits,
            &mut snapshot.files,
            &mut snapshot.bytes_read,
        );
    }
    workflow_paths
}

fn not_observed_error(subject: &str) -> ApiError {
    ApiError::local(
        ErrorCause::Unauthenticated,
        format!("local://not-observed/{subject}"),
        format!(
            "{subject} live on the GitHub API and this run had no credential, so they were not \
             observed"
        ),
    )
}

/// The platform-owned inputs of one run, however they were (or were not)
/// gathered.
struct PlatformData {
    custom_property_values: std::result::Result<Vec<crate::github::CustomPropertyValue>, ApiError>,
    tags: std::result::Result<crate::github::Paged<crate::github::TagRef>, ApiError>,
    history: std::result::Result<crate::github::Paged<crate::github::CommitSummary>, ApiError>,
    rulesets: std::result::Result<crate::github::Paged<crate::github::Ruleset>, ApiError>,
    branch_rules: std::result::Result<crate::github::Paged<crate::github::BranchRule>, ApiError>,
}

async fn observe_custom_property_values<G: GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    policy: &ResolvedPolicy,
) -> std::result::Result<Vec<crate::github::CustomPropertyValue>, ApiError> {
    if policy.rules.iter().any(|rule| {
        matches!(
            rule.condition,
            crate::policy::Condition::CustomProperty { .. }
        )
    }) {
        client.custom_property_values(owner, repo).await
    } else {
        Ok(Vec::new())
    }
}

/// Evaluate every enabled rule and assemble the report.
#[allow(clippy::too_many_arguments)]
fn complete_run(
    snapshot: &RepoSnapshot,
    workflows: Vec<Workflow>,
    workflows_truncated: bool,
    platform: PlatformData,
    policy: &ResolvedPolicy,
    options: &AuditOptions,
    sources: Sources,
    credential: CredentialCapability,
    repository_id: Option<u64>,
    suppressions: SuppressionInput,
) -> Result<Report> {
    let branch = snapshot.repository.default_branch.clone();
    let commit = snapshot.commit.clone();
    let context = AuditContext {
        policy,
        limits: options.limits,
        workflows,
        workflows_truncated,
        custom_property_values: platform.custom_property_values,
        tags: platform.tags,
        history: platform.history,
        rulesets: platform.rulesets,
        branch_rules: platform.branch_rules,
        snapshot,
        credential,
    };

    // Suppression is authorization, not observation. An API snapshot only
    // holds committed content; a working tree holds whatever was just
    // written, so working-tree runs read the request file from HEAD instead
    // — an uncommitted suppression request suppresses nothing.
    let request_text = match &suppressions {
        SuppressionInput::Snapshot => context.text(".github/airlock.yml").map(ToOwned::to_owned),
        SuppressionInput::Committed(text) => text.clone(),
    };
    let (requests, mut observations) =
        suppression_requests(request_text.as_deref(), options.limits)?;

    let platform_unobserved = sources.platform.is_none();
    let mut findings = Vec::with_capacity(policy.rules.len());
    let mut effective_policy = Vec::with_capacity(policy.rules.len());

    for rule in &policy.rules {
        effective_policy.push(EffectiveRule {
            rule: rule.def.id.to_owned(),
            severity: rule.severity.code().to_owned(),
            params: rule.params.clone(),
            provenance: rule.provenance.clone(),
        });

        // A platform rule with no API behind it was not observed. It is
        // gated here, before its check could run against synthesized state,
        // and it can never pass.
        let gated = platform_unobserved
            && rule.def.observation() == Observation::Platform
            && rule.def.evaluation == Evaluation::Mechanical;
        let verdict = if gated {
            checks::Verdict::inconclusive(
                "not_observed",
                format!(
                    "{} reads platform state only the GitHub API reports, and this run had no \
                     credential, so it was not observed",
                    rule.def.id
                ),
            )
        } else {
            checks::evaluate(rule, &context)
        };

        // The source that decided the finding. A judgment or unimplemented
        // rule was decided by neither source, and an unobserved platform
        // rule was decided by none at all.
        let source = match rule.def.evaluation {
            Evaluation::Mechanical => match rule.def.observation() {
                Observation::FileTree => Some(sources.file.to_owned()),
                Observation::Platform => sources.platform.map(ToOwned::to_owned),
            },
            Evaluation::Manual | Evaluation::Unimplemented => None,
        };

        let mut finding = Finding {
            rule: rule.def.id.to_owned(),
            statement: rule.def.statement.to_owned(),
            severity: rule.severity.code().to_owned(),
            status: verdict.status,
            evidence: verdict.evidence,
            remediation: verdict.remediation,
            remediation_class: RemediationClass::for_rule(rule.def.id),
            suppression: None,
            source,
            error: verdict.error,
        };

        apply_suppressions(&mut finding, policy, &requests, context.full_name());
        findings.push(finding);
    }

    // A request naming a rule the policy did not authorise never changes a
    // finding, so it is recorded here instead — the attempt stays visible.
    observations.extend(unauthorized_requests(policy, &requests, &findings));

    Ok(Report::assemble(
        AirlockIdentity::current(&options.version),
        AuditedRepository {
            full_name: snapshot.repository.full_name.clone(),
            id: repository_id,
            default_branch: branch,
            audited_commit: commit,
            settings_observed_at: snapshot.repository.observed_at.clone(),
        },
        sources.record(),
        PolicyIdentity {
            name: policy.name.clone(),
            source: policy.source.clone(),
            commit: policy.commit.clone(),
            sources: policy
                .sources
                .iter()
                .map(|source| PolicySourceIdentity {
                    name: source.name.clone(),
                    source: source.source.clone(),
                    commit: source.commit.clone(),
                    blob_sha: source.blob_sha.clone(),
                    content_digest: source.content_digest.clone(),
                })
                .collect(),
            bundle_digest: policy.bundle_digest.clone(),
            gate: policy.gate,
        },
        effective_policy,
        observations,
        findings,
    ))
}

/// The workflow paths in the tree, and whether the budget cut them short.
struct WorkflowPaths {
    paths: Vec<String>,
    truncated: bool,
}

fn workflow_paths(snapshot: &RepoSnapshot, budget: usize) -> WorkflowPaths {
    let mut paths: Vec<String> = snapshot
        .entries_under(".github/workflows")
        .into_iter()
        .filter(|entry| {
            entry.kind.is_file() && (entry.path.ends_with(".yml") || entry.path.ends_with(".yaml"))
        })
        .map(|entry| entry.path.clone())
        .collect();
    paths.sort();
    let truncated = paths.len() > budget;
    paths.truncate(budget);
    WorkflowPaths { paths, truncated }
}

fn release_unit_paths(snapshot: &RepoSnapshot, limits: Limits) -> Vec<String> {
    let Some(text) = snapshot.file(".intentional/config.yml").text() else {
        return Vec::new();
    };
    let Ok(document) = yaml::parse_mapping(text, limits.yaml) else {
        return Vec::new();
    };
    let Some(units) = document
        .get("release-units")
        .and_then(crate::yaml::Yaml::as_map)
    else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    for (_, unit) in units {
        let path = unit
            .get("path")
            .and_then(crate::yaml::Yaml::as_str)
            .unwrap_or(".")
            .trim_end_matches('/');
        if path == "." || path.is_empty() {
            continue;
        }
        paths.push(format!("{path}/taskfile.yml"));
        paths.push(format!("{path}/CHANGELOG.md"));
    }
    paths
}

fn parse_workflows(snapshot: &RepoSnapshot, paths: &[String], limits: Limits) -> Vec<Workflow> {
    paths
        .iter()
        .map(|path| {
            let state = snapshot.file(path);
            let text = state.text().unwrap_or_default().to_owned();
            let parsed = yaml::parse_mapping(&text, limits.yaml);
            Workflow {
                path: path.clone(),
                name: path.rsplit('/').next().unwrap_or(path).to_owned(),
                text,
                document: parsed.as_ref().ok().cloned(),
                parse_error: parsed.err().map(|error| error.to_string()),
            }
        })
        .collect()
}

/// Where the suppression request file is read from.
enum SuppressionInput {
    /// The snapshot's own copy — for API sources, always committed content.
    Snapshot,
    /// The committed copy read from the working tree's HEAD.
    Committed(Option<String>),
}

fn suppression_requests(
    text: Option<&str>,
    limits: Limits,
) -> Result<(
    Vec<crate::policy::SuppressionRequest>,
    Vec<PolicyObservation>,
)> {
    let Some(text) = text else {
        return Ok((Vec::new(), Vec::new()));
    };
    let requests = parse_suppression_requests(text, &limits)?;

    let mut observations = Vec::new();
    let mut valid = Vec::new();
    for request in requests {
        if request.reason.trim().is_empty() {
            observations.push(PolicyObservation {
                code: PolicyObservationCode::InvalidSuppressionRequest,
                rule: Some(request.rule.clone()),
                detail: format!(
                    "the repository asked to suppress {} without stating a reason, so the \
                     request is invalid",
                    request.rule
                ),
            });
            continue;
        }
        valid.push(request);
    }
    Ok((valid, observations))
}

fn apply_suppressions(
    finding: &mut Finding,
    policy: &ResolvedPolicy,
    requests: &[crate::policy::SuppressionRequest],
    full_name: &str,
) {
    // Only a failure can be suppressed. Suppressing a pass would hide that the
    // rule was evaluated, and suppressing an undecided result would let a
    // repository suppress its way out of completeness.
    if finding.status != Status::Fail {
        return;
    }

    if let Some(direct) = policy.suppressions.direct_for(&finding.rule, full_name) {
        finding.status = Status::Suppressed;
        finding.suppression = Some(Suppression {
            source: SuppressionSource::Policy,
            requested_reason: None,
            policy_reason: Some(direct.reason.clone()),
            authorized_by: format!("policy `{}` suppressions.direct", policy.name),
        });
        return;
    }

    if !policy
        .suppressions
        .allow_repo_requests
        .contains(&finding.rule)
    {
        return;
    }
    let Some(request) = requests.iter().find(|request| request.rule == finding.rule) else {
        return;
    };

    finding.status = Status::Suppressed;
    finding.suppression = Some(Suppression {
        source: SuppressionSource::RepositoryRequest,
        requested_reason: Some(request.reason.clone()),
        policy_reason: None,
        authorized_by: format!("policy `{}` suppressions.allow-repo-requests", policy.name),
    });
}

fn unauthorized_requests(
    policy: &ResolvedPolicy,
    requests: &[crate::policy::SuppressionRequest],
    findings: &[Finding],
) -> Vec<PolicyObservation> {
    requests
        .iter()
        .filter(|request| {
            !policy
                .suppressions
                .allow_repo_requests
                .contains(&request.rule)
        })
        .map(|request| {
            let status = findings
                .iter()
                .find(|finding| finding.rule == request.rule)
                .map_or("not enabled by the policy".to_owned(), |finding| {
                    format!("still {}", finding.status.code())
                });
            PolicyObservation {
                code: PolicyObservationCode::UnauthorizedSuppressionRequest,
                rule: Some(request.rule.clone()),
                detail: format!(
                    "the repository asked to suppress {} (\"{}\"), which policy `{}` does not \
                     allow it to suppress; the finding is {status}",
                    request.rule, request.reason, policy.name
                ),
            }
        })
        .collect()
}

/// Turn a failure to read the repository into an operational error a human can
/// act on. A 404 is deliberately ambiguous on GitHub's side, so airlock names
/// both possibilities rather than picking one.
fn repository_error(
    owner: &str,
    repo: &str,
    error: &ApiError,
    grant: Option<&VerifiedGrant>,
) -> Error {
    if error.cause != ErrorCause::NotFound {
        return Error::GitHub {
            api_error: Box::new(error.clone()),
            message: error.to_string(),
        };
    }

    let mut message = format!(
        "{owner}/{repo} could not be read. GitHub answers 404 both for a repository that does \
         not exist and for one this credential cannot see, so airlock cannot tell you which."
    );
    if let Some(grant) = grant {
        let accounts = grant.visible_accounts();
        if accounts.is_empty() {
            message.push_str(
                " The credential reaches no accounts at all, which would explain the second case.",
            );
        } else {
            message.push_str(&format!(
                " The credential reaches {}. If {owner} is not among them, install Airlock Safe \
                 on {owner}.",
                accounts.join(", ")
            ));
        }
    }
    Error::GitHub {
        api_error: Box::new(error.clone()),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Gate;
    use crate::policy::{DirectSuppression, SuppressionRequest};
    use crate::registry::Severity;
    use std::collections::BTreeMap;

    fn policy_with(direct: Vec<DirectSuppression>, allowed: &[&str]) -> ResolvedPolicy {
        let mut policy = ResolvedPolicy {
            name: "test".to_owned(),
            source: "./policy.yml".to_owned(),
            commit: None,
            bundle_digest: "sha256:0".to_owned(),
            sources: Vec::new(),
            gate: Gate::Blocking,
            rules: Vec::new(),
            suppressions: Default::default(),
            reference_data: BTreeMap::new(),
            capabilities: Vec::new(),
        };
        policy.suppressions.direct = direct;
        policy.suppressions.allow_repo_requests =
            allowed.iter().map(|rule| (*rule).to_owned()).collect();
        policy
    }

    fn failing(rule: &str) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: "statement".to_owned(),
            severity: Severity::Blocking.code().to_owned(),
            status: Status::Fail,
            evidence: None,
            remediation: None,
            remediation_class: RemediationClass::for_rule(rule),
            suppression: None,
            source: None,
            error: None,
        }
    }

    #[test]
    fn a_policy_suppression_records_both_the_reason_and_the_authority() {
        let policy = policy_with(
            vec![DirectSuppression {
                rule: "REPO-FILE-10".to_owned(),
                repository: Some("owner/name".to_owned()),
                reason: "the devcontainer lives in the umbrella workspace".to_owned(),
            }],
            &[],
        );
        let mut finding = failing("REPO-FILE-10");
        apply_suppressions(&mut finding, &policy, &[], "owner/name");
        assert_eq!(finding.status, Status::Suppressed);
        let suppression = finding.suppression.unwrap();
        assert_eq!(suppression.source.code(), "policy");
        assert!(suppression.policy_reason.is_some());
    }

    #[test]
    fn a_policy_suppression_scoped_to_another_repository_does_not_apply() {
        let policy = policy_with(
            vec![DirectSuppression {
                rule: "REPO-FILE-10".to_owned(),
                repository: Some("owner/other".to_owned()),
                reason: "elsewhere".to_owned(),
            }],
            &[],
        );
        let mut finding = failing("REPO-FILE-10");
        apply_suppressions(&mut finding, &policy, &[], "owner/name");
        assert_eq!(finding.status, Status::Fail);
    }

    #[test]
    fn an_authorised_request_is_honoured_with_both_provenances() {
        let policy = policy_with(Vec::new(), &["REPO-DOCS-01"]);
        let requests = vec![SuppressionRequest {
            rule: "REPO-DOCS-01".to_owned(),
            reason: "docs are stubs until the first release".to_owned(),
        }];
        let mut finding = failing("REPO-DOCS-01");
        apply_suppressions(&mut finding, &policy, &requests, "owner/name");
        assert_eq!(finding.status, Status::Suppressed);
        let suppression = finding.suppression.unwrap();
        assert_eq!(suppression.source.code(), "repository_request");
        assert_eq!(
            suppression.requested_reason.as_deref(),
            Some("docs are stubs until the first release")
        );
        assert!(suppression.authorized_by.contains("allow-repo-requests"));
    }

    #[test]
    fn an_unauthorised_request_changes_nothing_and_is_recorded() {
        let policy = policy_with(Vec::new(), &[]);
        let requests = vec![SuppressionRequest {
            rule: "REPO-CI-02".to_owned(),
            reason: "inconvenient".to_owned(),
        }];
        let mut finding = failing("REPO-CI-02");
        apply_suppressions(&mut finding, &policy, &requests, "owner/name");
        assert_eq!(finding.status, Status::Fail);

        let observations = unauthorized_requests(&policy, &requests, &[finding]);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].code.code(),
            "unauthorized_suppression_request"
        );
        assert!(observations[0].detail.contains("still fail"));
    }

    #[test]
    fn only_failures_are_suppressible() {
        let policy = policy_with(
            vec![DirectSuppression {
                rule: "REPO-CI-02".to_owned(),
                repository: None,
                reason: "why".to_owned(),
            }],
            &[],
        );
        for status in [
            Status::Unimplemented,
            Status::Error,
            Status::Inconclusive,
            Status::Pass,
        ] {
            let mut finding = failing("REPO-CI-02");
            finding.status = status;
            apply_suppressions(&mut finding, &policy, &[], "owner/name");
            assert_eq!(
                finding.status, status,
                "{status:?} must not be suppressible"
            );
        }
    }

    #[test]
    fn a_repository_404_names_both_possibilities() {
        let error = ApiError {
            cause: ErrorCause::NotFound,
            endpoint: "GET /repos/owner/name".to_owned(),
            status: Some(404),
            message: Some("Not Found".to_owned()),
            documentation_url: None,
            accepted_permissions: None,
            request_id: None,
        };
        let grant = VerifiedGrant {
            kind: crate::auth::TokenKind::AppUser,
            issuer: Some("airlock-safe".to_owned()),
            login: None,
            scopes: Vec::new(),
            installations: vec![crate::auth::InstallationGrant {
                id: 1,
                account: Some("other-owner".to_owned()),
                permissions: vec!["metadata=read".to_owned()],
            }],
        };
        let message = repository_error("owner", "name", &error, Some(&grant)).to_string();
        assert!(message.contains("does not exist"));
        assert!(message.contains("cannot see"));
        assert!(message.contains("other-owner"));
    }
}
