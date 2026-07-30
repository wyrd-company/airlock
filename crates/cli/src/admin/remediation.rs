//! Settings-level remediation, behind the interactive-session type fence.
//!
//! This module is the only mutating GitHub surface in the binary. It is not
//! exported by `airlock-core`, and no command handler can construct it: the
//! only constructor consumes the interactive session credential.
//!
//! An operation never accepts an observation. It accepts repository
//! coordinates and a rule id, observes immediately before deciding whether to
//! write, and observes again after a successful request. The result is derived
//! from that last observation, not from the status of the write request.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use airlock_core::audit::{self, AuditOptions};
use airlock_core::auth::{InstallationGrant, TokenKind, VerifiedGrant};
use airlock_core::findings::Report;
use airlock_core::github::{GitHub as _, Repository, RestClient, RestClientConfig};
use airlock_core::limits::Limits;
use airlock_core::policy::{self, PolicySource};
use reqwest::StatusCode;
use serde::Serialize;
use zeroize::Zeroize as _;

use super::flow;
use super::identity;
use super::session::SessionCredential;
use super::text::{self, CAUSE_LIMIT, NAME_LIMIT};

/// A rule whose change can be derived without asking the operator for data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Rename the current default branch to `main`.
    DefaultBranchMain,
    /// Disable merge commits.
    DisableMergeCommits,
    /// Enable squash merges.
    EnableSquashMerge,
    /// Enable automatic deletion of merged head branches.
    EnableHeadBranchAutoDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkKind {
    RepositorySettings,
    DefaultBranchRef,
}

impl Action {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DefaultBranchMain => "set-default-branch-main",
            Self::DisableMergeCommits => "disable-merge-commits",
            Self::EnableSquashMerge => "enable-squash-merge",
            Self::EnableHeadBranchAutoDelete => "enable-head-branch-auto-delete",
        }
    }

    #[must_use]
    pub const fn bulk_kind(self) -> BulkKind {
        match self {
            Self::DefaultBranchMain => BulkKind::DefaultBranchRef,
            Self::DisableMergeCommits
            | Self::EnableSquashMerge
            | Self::EnableHeadBranchAutoDelete => BulkKind::RepositorySettings,
        }
    }
    /// Resolve the compiled remediation code to an executable action.
    ///
    /// The other operator-setting remediations need explicit operator input:
    /// a destination owner, a new name, a ruleset, or a credential value. They
    /// are deliberately not guessed from prose in a finding.
    #[must_use]
    pub const fn for_code(code: &str) -> Option<Self> {
        match code.as_bytes() {
            b"set-default-branch-main" => Some(Self::DefaultBranchMain),
            b"disable-merge-commits" => Some(Self::DisableMergeCommits),
            b"enable-squash-merge" => Some(Self::EnableSquashMerge),
            b"enable-head-branch-auto-delete" => Some(Self::EnableHeadBranchAutoDelete),
            _ => None,
        }
    }

    /// What the confirmation says will change.
    #[must_use]
    pub const fn change(self) -> &'static str {
        match self {
            Self::DefaultBranchMain => "rename the current default branch to `main`",
            Self::DisableMergeCommits => "disable merge commits",
            Self::EnableSquashMerge => "enable squash merges",
            Self::EnableHeadBranchAutoDelete => "enable automatic deletion of merged head branches",
        }
    }

    /// Whether the observed repository already satisfies the rule.
    fn satisfied_by(self, repository: &Repository) -> Option<bool> {
        match self {
            Self::DefaultBranchMain => Some(repository.default_branch == "main"),
            Self::DisableMergeCommits => repository.allow_merge_commit.map(|value| !value),
            Self::EnableSquashMerge => repository.allow_squash_merge,
            Self::EnableHeadBranchAutoDelete => repository.delete_branch_on_merge,
        }
    }
}

/// One line in the operator-visible transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What happened, sanitized before crossing the worker boundary.
    pub detail: String,
    /// Time since this operation began.
    pub elapsed: Duration,
    /// Whether this step completed.
    pub succeeded: bool,
}

/// What the final re-observation established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedStatus {
    /// The rule now passes.
    Pass,
    /// The rule still fails.
    Fail,
    /// Airlock could not establish the rule's status.
    Inconclusive,
}

/// The complete result of one attempted remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// The rule this operation re-observed.
    pub rule: String,
    /// The compiled remediation code.
    pub remediation: String,
    /// What was proposed before the operation.
    pub proposed_change: String,
    /// Every step, ending in re-observation.
    pub steps: Vec<Step>,
    /// Derived only from the final re-observation.
    pub observed: ObservedStatus,
    /// A credential-free inverse request, present only when Airlock can
    /// reconstruct the previous value without guessing.
    pub undo: Option<UndoHandle>,
}

/// Opaque reference to an inverse held only by the credential-owning worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UndoHandle(u64);

#[cfg(test)]
impl UndoHandle {
    pub(crate) const fn fixture(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UndoOperation {
    RenameBranch {
        owner: String,
        repo: String,
        from: String,
        to: String,
    },
    PatchRepository {
        owner: String,
        repo: String,
        field: String,
        value: bool,
    },
    RenameRepository {
        owner: String,
        from: String,
        to: String,
    },
    RenameVariable {
        owner: String,
        repo: String,
        from: String,
        to: String,
    },
}

/// Repository coordinates, kept out of the rendering layer's credential fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub owner: String,
    pub repo: String,
}

/// Freshly observed values that the rendering layer may offer as choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedInput {
    Rulesets(Vec<String>),
    Variables(Vec<String>),
}

/// Work the terminal loop asks the credential-owning worker to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Observe a repository in full under its owner's default policy.
    Observe(Target),
    /// Read the choices for an input-bearing remediation immediately before it
    /// is shown. These values are never cached as an executable plan.
    Prepare { target: Target, remediation: String },
    /// Apply one freshly re-observed rule.
    Apply {
        target: Target,
        rule: String,
        remediation: String,
        argument: Option<String>,
    },
    /// Apply a confirmed same-lane group, re-observing per rule.
    ApplyGroup {
        target: Target,
        requests: Vec<(String, Action)>,
    },
    /// Apply an inverse captured from the immediately preceding fresh
    /// observation.
    Undo {
        target: Target,
        rule: String,
        remediation: String,
        undo: UndoHandle,
        expected: ObservedStatus,
    },
}

/// Credential-free output from the worker.
#[derive(Debug)]
pub enum Response {
    /// A complete fresh observation.
    Observed { target: Target, report: Box<Report> },
    /// Sanitized choices from a fresh settings observation.
    Prepared {
        remediation: String,
        input: PreparedInput,
    },
    /// One remediation transcript.
    Applied {
        target: Target,
        transcript: Transcript,
    },
    /// One transcript per rule in a bulk confirmation.
    GroupApplied {
        target: Target,
        transcripts: Vec<Transcript>,
    },
    /// An operational failure, sanitized before crossing the boundary.
    Failed(String),
}

/// A client with mutating methods, constructible only from a session grant.
///
/// It is a different type from the read-only [`RestClient`]. The core GitHub
/// trait has no mutating method, so neither audits nor command handlers can
/// reach anything below.
struct WriteClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl WriteClient {
    fn from_session(credential: &SessionCredential) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            token: credential.expose_for_authorization_header().to_owned(),
            base_url: flow::api_base().trim_end_matches('/').to_owned(),
        })
    }

    async fn patch_repository(
        &self,
        owner: &str,
        repo: &str,
        body: &RepositoryPatch,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .patch(format!(
                "{}/repos/{}/{}",
                self.base_url,
                segment(owner),
                segment(repo)
            ))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
            .send()
            .await?;
        accepted(response.status(), "PATCH /repos/{owner}/{repo}")
    }

    async fn rename_branch(&self, owner: &str, repo: &str, branch: &str) -> anyhow::Result<()> {
        self.rename_branch_to(owner, repo, branch, "main").await
    }

    async fn rename_branch_to(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        new_name: &str,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!(
                "{}/repos/{}/{}/branches/{}/rename",
                self.base_url,
                segment(owner),
                segment(repo),
                segment(branch)
            ))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&serde_json::json!({ "new_name": new_name }))
            .send()
            .await?;
        accepted(
            response.status(),
            "POST /repos/{owner}/{repo}/branches/{branch}/rename",
        )
    }

    async fn rename_repository(&self, owner: &str, repo: &str, name: &str) -> anyhow::Result<()> {
        self.patch_repository(
            owner,
            repo,
            &RepositoryPatch {
                name: Some(name.to_owned()),
                ..RepositoryPatch::default()
            },
        )
        .await
    }

    async fn transfer_repository(
        &self,
        owner: &str,
        repo: &str,
        destination: &str,
    ) -> anyhow::Result<()> {
        self.send_json(
            reqwest::Method::POST,
            &format!("/repos/{}/{}/transfer", segment(owner), segment(repo)),
            &serde_json::json!({"new_owner": destination}),
            "POST /repos/{owner}/{repo}/transfer",
        )
        .await
    }

    async fn attach_ruleset(&self, owner: &str, repo: &str, id: &str) -> anyhow::Result<()> {
        let body = ruleset_body(Some(repo));
        if id == "create" {
            self.send_json(
                reqwest::Method::POST,
                &format!("/orgs/{}/rulesets", segment(owner)),
                &body,
                "POST /orgs/{org}/rulesets",
            )
            .await
        } else {
            let existing = self
                .get_json(&format!(
                    "/orgs/{}/rulesets/{}",
                    segment(owner),
                    segment(id)
                ))
                .await?;
            let body = ruleset_attach_body(existing, repo)?;
            self.send_json(
                reqwest::Method::PUT,
                &format!("/orgs/{}/rulesets/{}", segment(owner), segment(id)),
                &body,
                "PUT /orgs/{org}/rulesets/{id}",
            )
            .await
        }
    }

    async fn tighten_ruleset(&self, owner: &str, id: &str) -> anyhow::Result<()> {
        let existing = self
            .get_json(&format!(
                "/orgs/{}/rulesets/{}",
                segment(owner),
                segment(id)
            ))
            .await?;
        self.send_json(
            reqwest::Method::PUT,
            &format!("/orgs/{}/rulesets/{}", segment(owner), segment(id)),
            &ruleset_tighten_body(existing)?,
            "PUT /orgs/{org}/rulesets/{id}",
        )
        .await
    }

    async fn rename_variable(&self, owner: &str, repo: &str, input: &str) -> anyhow::Result<()> {
        let mut lines = input.lines();
        let old = lines.next().unwrap_or_default();
        let new = lines.next().unwrap_or_default();
        anyhow::ensure!(
            !old.is_empty() && !new.is_empty(),
            "variable rename needs old and new names"
        );
        let response = self
            .http
            .get(format!(
                "{}/repos/{}/{}/actions/variables/{}",
                self.base_url,
                segment(owner),
                segment(repo),
                segment(old)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "the variable value could not be read"
        );
        let value: serde_json::Value = response.json().await?;
        let value = value
            .get("value")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("the variable response carried no value"))?;
        self.send_json(
            reqwest::Method::POST,
            &format!(
                "/repos/{}/{}/actions/variables",
                segment(owner),
                segment(repo)
            ),
            &serde_json::json!({"name": new, "value": value}),
            "POST /repos/{owner}/{repo}/actions/variables",
        )
        .await?;
        let response = self
            .http
            .delete(format!(
                "{}/repos/{}/{}/actions/variables/{}",
                self.base_url,
                segment(owner),
                segment(repo),
                segment(old)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        accepted(
            response.status(),
            "DELETE /repos/{owner}/{repo}/actions/variables/{name}",
        )
    }

    async fn rulesets(&self, owner: &str) -> anyhow::Result<Vec<String>> {
        let value = self
            .get_json(&format!("/orgs/{}/rulesets?per_page=100", segment(owner)))
            .await?;
        let rows = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("the ruleset response was not a list"))?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                let id = row.get("id")?.as_u64()?;
                let name = row.get("name")?.as_str()?;
                Some(format!("{id} — {}", text::sanitize(name, NAME_LIMIT)))
            })
            .collect())
    }

    async fn variables(&self, owner: &str, repo: &str) -> anyhow::Result<Vec<String>> {
        let value = self
            .get_json(&format!(
                "/repos/{}/{}/actions/variables?per_page=100",
                segment(owner),
                segment(repo)
            ))
            .await?;
        let rows = value
            .get("variables")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("the variable response carried no list"))?;
        Ok(rows
            .iter()
            .filter_map(|row| row.get("name").and_then(serde_json::Value::as_str))
            .map(|name| text::sanitize(name, NAME_LIMIT))
            .collect())
    }

    async fn get_json(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "the settings observation returned HTTP {}",
            response.status().as_u16()
        );
        response.json().await.map_err(Into::into)
    }

    async fn send_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &serde_json::Value,
        endpoint: &str,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
            .send()
            .await?;
        accepted(response.status(), endpoint)
    }
}

fn ruleset_update_base(
    existing: &serde_json::Value,
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    let mut body = serde_json::Map::new();
    for field in [
        "name",
        "target",
        "enforcement",
        "bypass_actors",
        "conditions",
    ] {
        if let Some(value) = existing.get(field) {
            body.insert(field.to_owned(), value.clone());
        }
    }
    anyhow::ensure!(
        body.contains_key("name")
            && body.contains_key("target")
            && body.contains_key("enforcement")
            && body.contains_key("conditions"),
        "the observed ruleset omitted a required field"
    );
    Ok(body)
}

fn observed_rules(existing: &serde_json::Value) -> anyhow::Result<Vec<serde_json::Value>> {
    existing
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the observed ruleset omitted its rules"))
}

fn ruleset_attach_body(
    existing: serde_json::Value,
    repository: &str,
) -> anyhow::Result<serde_json::Value> {
    let mut body = ruleset_update_base(&existing)?;
    let include = body
        .get_mut("conditions")
        .and_then(|value| value.get_mut("repository_name"))
        .and_then(|value| value.get_mut("include"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("the observed ruleset has no repository-name choice"))?;
    if !include
        .iter()
        .any(|value| value.as_str() == Some(repository))
    {
        include.push(serde_json::Value::String(repository.to_owned()));
    }
    body.insert(
        "rules".to_owned(),
        serde_json::Value::Array(observed_rules(&existing)?),
    );
    Ok(serde_json::Value::Object(body))
}

fn ruleset_tighten_body(existing: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let mut body = ruleset_update_base(&existing)?;
    let mut rules = observed_rules(&existing)?;
    if let Some(pull_request) = rules
        .iter_mut()
        .find(|rule| rule.get("type").and_then(serde_json::Value::as_str) == Some("pull_request"))
    {
        let parameters = pull_request
            .get_mut("parameters")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("the observed pull-request rule omitted parameters"))?;
        parameters.insert(
            "allowed_merge_methods".to_owned(),
            serde_json::json!(["squash", "rebase"]),
        );
    } else {
        rules.push(ruleset_body(None)["rules"][0].clone());
    }
    if !rules.iter().any(|rule| {
        rule.get("type").and_then(serde_json::Value::as_str) == Some("required_linear_history")
    }) {
        rules.push(serde_json::json!({"type": "required_linear_history"}));
    }
    body.insert("rules".to_owned(), serde_json::Value::Array(rules));
    Ok(serde_json::Value::Object(body))
}

impl Drop for WriteClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Debug, Default, Serialize)]
struct RepositoryPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_merge_commit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_squash_merge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_branch_on_merge: Option<bool>,
}

pub(crate) fn ruleset_body(repository: Option<&str>) -> serde_json::Value {
    let conditions = repository.map_or_else(
        || serde_json::json!({}),
        |name| {
            serde_json::json!({
                "repository_name": {"include": [name], "exclude": [], "protected": false}
            })
        },
    );
    serde_json::json!({
        "name": "Airlock default branch",
        "target": "branch",
        "enforcement": "active",
        "conditions": conditions,
        "rules": [
            {"type": "pull_request", "parameters": {
                "allowed_merge_methods": ["squash", "rebase"],
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": false,
                "require_code_owner_review": false,
                "require_last_push_approval": false,
                "required_review_thread_resolution": false
            }},
            {"type": "required_linear_history"}
        ]
    })
}

/// The credential-owning remediation session.
///
/// This value belongs to the terminal run loop, never to rendering state.
pub struct Session {
    token: String,
    config: RestClientConfig,
    writer: WriteClient,
    version: String,
    undo_operations: HashMap<UndoHandle, UndoOperation>,
    next_undo: u64,
}

impl Session {
    /// Construct the read/write pair from the interactive credential.
    ///
    /// Both clients refuse redirects. A redirect is the server selecting the
    /// destination to which the write-capable credential will be sent.
    pub fn start(
        credential: &SessionCredential,
        version: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let config = RestClientConfig {
            base_url: flow::api_base(),
            ..RestClientConfig::default().refusing_redirects()
        };
        Ok(Self {
            token: credential.expose_for_authorization_header().to_owned(),
            config,
            writer: WriteClient::from_session(credential)?,
            version: version.into(),
            undo_operations: HashMap::new(),
            next_undo: 1,
        })
    }

    fn reader(&self) -> anyhow::Result<RestClient> {
        RestClient::new(&self.token, self.config.clone())
            .map_err(|error| anyhow::anyhow!("cannot build observation client: {error}"))
    }

    /// Observe the repository in full with the write-capable session grant.
    pub async fn observe(&self, target: &Target) -> anyhow::Result<Report> {
        let reader = self.reader()?;
        let limits = Limits::default();
        let source = PolicySource::default_for_owner(&target.owner);
        let policy = policy::resolve(&reader, &source, &limits).await?;
        let grant = write_grant();
        audit::run(
            &reader,
            &target.owner,
            &target.repo,
            &policy,
            &AuditOptions {
                version: self.version.clone(),
                limits,
                ..AuditOptions::default()
            },
            Some(&grant),
        )
        .await
        .map_err(Into::into)
    }

    async fn prepare(&self, target: &Target, remediation: &str) -> anyhow::Result<PreparedInput> {
        match remediation {
            "attach-org-rulesets" => {
                let mut choices = self.writer.rulesets(&target.owner).await?;
                choices.push("create — Airlock default branch".to_owned());
                Ok(PreparedInput::Rulesets(choices))
            }
            "tighten-org-rulesets" => self
                .writer
                .rulesets(&target.owner)
                .await
                .map(PreparedInput::Rulesets),
            "rename-app-credentials" | "rename-task-named-credentials" => self
                .writer
                .variables(&target.owner, &target.repo)
                .await
                .map(PreparedInput::Variables),
            _ => anyhow::bail!("this remediation has no observed choice input"),
        }
    }

    /// Apply one rule under the re-observation contract.
    pub async fn apply(
        &mut self,
        owner: &str,
        repo: &str,
        rule: &str,
        remediation: &str,
        argument: Option<&str>,
    ) -> Transcript {
        let started = Instant::now();
        let action = Action::for_code(remediation);
        let proposed_change = action.map_or_else(
            || "requires explicit operator input; airlock will not guess it".to_owned(),
            |action| action.change().to_owned(),
        );
        let mut transcript = Transcript {
            rule: text::sanitize(rule, NAME_LIMIT),
            remediation: text::sanitize(remediation, NAME_LIMIT),
            proposed_change,
            steps: Vec::new(),
            observed: ObservedStatus::Inconclusive,
            undo: None,
        };
        if action.is_none() && argument.is_none() {
            transcript.steps.push(step(
                started,
                false,
                "no request was made because this remediation needs explicit operator input",
            ));
            transcript.steps.push(step(
                started,
                false,
                "re-observation did not run because no executable change was selected",
            ));
            return transcript;
        }

        if action.is_none() {
            let before = match self
                .observe(&Target {
                    owner: owner.to_owned(),
                    repo: repo.to_owned(),
                })
                .await
            {
                Ok(report) => report,
                Err(error) => {
                    transcript.steps.push(step(
                        started,
                        false,
                        &format!("pre-change re-observation failed: {error:#}"),
                    ));
                    transcript
                        .steps
                        .push(step(started, false, "no write was attempted"));
                    return transcript;
                }
            };
            let before_status = before
                .findings
                .iter()
                .find(|finding| finding.rule == rule)
                .map(|finding| finding.status);
            transcript.steps.push(step(
                started,
                before_status.is_some(),
                "re-observed the rule immediately before acting",
            ));
            if before_status != Some(airlock_core::findings::Status::Fail) {
                transcript.steps.push(step(
                    started,
                    before_status == Some(airlock_core::findings::Status::Pass),
                    "the fresh observation does not report a gap; no write was made",
                ));
            } else {
                let changed = self
                    .change_with_input(owner, repo, remediation, argument.unwrap_or_default())
                    .await;
                let accepted = changed.is_ok();
                if accepted {
                    if let Some(undo) = input_undo(owner, repo, remediation, argument) {
                        transcript.undo = Some(self.remember_undo(undo));
                    }
                }
                transcript.steps.push(step(
                    started,
                    accepted,
                    &changed.map_or_else(
                        |error| format!("the change request failed: {error:#}"),
                        |()| "github accepted the change request".to_owned(),
                    ),
                ));
            }

            let (observed_owner, observed_repo) =
                observed_target(owner, repo, remediation, argument);
            match self
                .observe(&Target {
                    owner: observed_owner,
                    repo: observed_repo,
                })
                .await
            {
                Ok(report) => {
                    let finding = report.findings.iter().find(|finding| finding.rule == rule);
                    transcript.observed = match finding.map(|finding| finding.status) {
                        Some(airlock_core::findings::Status::Pass) => ObservedStatus::Pass,
                        Some(airlock_core::findings::Status::Fail) => ObservedStatus::Fail,
                        _ => ObservedStatus::Inconclusive,
                    };
                    transcript.steps.push(step(
                        started,
                        transcript.observed == ObservedStatus::Pass,
                        match transcript.observed {
                            ObservedStatus::Pass => "re-observation reports pass",
                            ObservedStatus::Fail => {
                                "re-observation reports fail; the gap remains open"
                            }
                            ObservedStatus::Inconclusive => {
                                "re-observation could not establish the rule"
                            }
                        },
                    ));
                }
                Err(error) => transcript.steps.push(step(
                    started,
                    false,
                    &format!("post-change re-observation failed: {error:#}"),
                )),
            }
            return transcript;
        }

        let reader = match self.reader() {
            Ok(reader) => reader,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("pre-change re-observation could not start: {error:#}"),
                ));
                return transcript;
            }
        };
        let before = match reader.repository(owner, repo).await {
            Ok(repository) => repository,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("pre-change re-observation failed: {error}"),
                ));
                transcript
                    .steps
                    .push(step(started, false, "no write was attempted"));
                return transcript;
            }
        };
        transcript.steps.push(step(
            started,
            true,
            "re-observed the rule immediately before acting",
        ));

        let satisfied = action.map_or(Some(false), |action| action.satisfied_by(&before));
        match satisfied {
            Some(true) => {
                transcript.steps.push(step(
                    started,
                    true,
                    "the fresh observation already passes; no write was made",
                ));
            }
            None => {
                transcript.steps.push(step(
                    started,
                    false,
                    "the fresh observation withheld the setting; no write was made",
                ));
            }
            Some(false) => {
                let changed = if let Some(action) = action {
                    self.change(owner, repo, action, &before).await
                } else {
                    self.change_with_input(owner, repo, remediation, argument.unwrap_or_default())
                        .await
                };
                let accepted = changed.is_ok();
                transcript.steps.push(step(
                    started,
                    accepted,
                    &changed.map_or_else(
                        |error| format!("the change request failed: {error:#}"),
                        |()| "github accepted the change request".to_owned(),
                    ),
                ));
                if accepted {
                    if let Some(undo) =
                        action.and_then(|action| action_undo(owner, repo, action, &before))
                    {
                        transcript.undo = Some(self.remember_undo(undo));
                    }
                }
            }
        }

        let reader = match self.reader() {
            Ok(reader) => reader,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("post-change re-observation could not start: {error:#}"),
                ));
                return transcript;
            }
        };
        match reader.repository(owner, repo).await {
            Ok(repository) => match action.and_then(|action| action.satisfied_by(&repository)) {
                Some(true) => {
                    transcript.observed = ObservedStatus::Pass;
                    transcript
                        .steps
                        .push(step(started, true, "re-observation reports pass"));
                }
                Some(false) => {
                    transcript.observed = ObservedStatus::Fail;
                    transcript.steps.push(step(
                        started,
                        false,
                        "re-observation reports fail; the gap remains open",
                    ));
                }
                None => transcript.steps.push(step(
                    started,
                    false,
                    "re-observation could not establish the setting",
                )),
            },
            Err(error) => transcript.steps.push(step(
                started,
                false,
                &format!("post-change re-observation failed: {error}"),
            )),
        }
        transcript
    }

    /// Apply a same-kind group, preserving the single-rule contract per rule.
    pub async fn apply_group<'a>(
        &mut self,
        owner: &str,
        repo: &str,
        requests: impl IntoIterator<Item = (&'a str, Action)>,
    ) -> Vec<Transcript> {
        let mut transcripts = Vec::new();
        for (rule, action) in requests {
            transcripts.push(self.apply(owner, repo, rule, action.code(), None).await);
        }
        transcripts
    }

    async fn change(
        &self,
        owner: &str,
        repo: &str,
        action: Action,
        before: &Repository,
    ) -> anyhow::Result<()> {
        match action {
            Action::DefaultBranchMain => {
                self.writer
                    .rename_branch(owner, repo, &before.default_branch)
                    .await
            }
            Action::DisableMergeCommits => {
                self.writer
                    .patch_repository(
                        owner,
                        repo,
                        &RepositoryPatch {
                            allow_merge_commit: Some(false),
                            ..RepositoryPatch::default()
                        },
                    )
                    .await
            }
            Action::EnableSquashMerge => {
                self.writer
                    .patch_repository(
                        owner,
                        repo,
                        &RepositoryPatch {
                            allow_squash_merge: Some(true),
                            ..RepositoryPatch::default()
                        },
                    )
                    .await
            }
            Action::EnableHeadBranchAutoDelete => {
                self.writer
                    .patch_repository(
                        owner,
                        repo,
                        &RepositoryPatch {
                            delete_branch_on_merge: Some(true),
                            ..RepositoryPatch::default()
                        },
                    )
                    .await
            }
        }
    }

    async fn change_with_input(
        &self,
        owner: &str,
        repo: &str,
        remediation: &str,
        argument: &str,
    ) -> anyhow::Result<()> {
        match remediation {
            "transfer-repository" => {
                let destination = argument.lines().next().unwrap_or_default();
                self.writer
                    .transfer_repository(owner, repo, destination)
                    .await
            }
            "rename-repository-kebab"
            | "rename-repository-undotted"
            | "rename-repository-family-prefix" => {
                self.writer.rename_repository(owner, repo, argument).await
            }
            "attach-org-rulesets" => {
                let id = argument.split_whitespace().next().unwrap_or_default();
                self.writer.attach_ruleset(owner, repo, id).await
            }
            "tighten-org-rulesets" => {
                let id = argument.split_whitespace().next().unwrap_or_default();
                self.writer.tighten_ruleset(owner, id).await
            }
            "rename-app-credentials" | "rename-task-named-credentials" => {
                self.writer.rename_variable(owner, repo, argument).await
            }
            _ => anyhow::bail!("the remediation has no executable input contract"),
        }
    }

    fn remember_undo(&mut self, undo: UndoOperation) -> UndoHandle {
        let handle = UndoHandle(self.next_undo);
        self.next_undo = self.next_undo.saturating_add(1);
        self.undo_operations.insert(handle, undo);
        handle
    }

    async fn undo(&self, undo: &UndoOperation) -> anyhow::Result<()> {
        match undo {
            UndoOperation::RenameBranch {
                owner,
                repo,
                from,
                to,
            } => self.writer.rename_branch_to(owner, repo, from, to).await,
            UndoOperation::PatchRepository {
                owner,
                repo,
                field,
                value,
            } => {
                let mut patch = RepositoryPatch::default();
                match field.as_str() {
                    "allow_merge_commit" => patch.allow_merge_commit = Some(*value),
                    "allow_squash_merge" => patch.allow_squash_merge = Some(*value),
                    "delete_branch_on_merge" => patch.delete_branch_on_merge = Some(*value),
                    _ => anyhow::bail!("the undo field is not supported"),
                }
                self.writer.patch_repository(owner, repo, &patch).await
            }
            UndoOperation::RenameRepository { owner, from, to } => {
                self.writer.rename_repository(owner, from, to).await
            }
            UndoOperation::RenameVariable {
                owner,
                repo,
                from,
                to,
            } => {
                self.writer
                    .rename_variable(owner, repo, &format!("{from}\n{to}"))
                    .await
            }
        }
    }

    async fn apply_undo(
        &mut self,
        target: &Target,
        rule: &str,
        remediation: &str,
        undo: UndoHandle,
        expected: ObservedStatus,
    ) -> Transcript {
        let started = Instant::now();
        let mut transcript = Transcript {
            rule: text::sanitize(rule, NAME_LIMIT),
            remediation: text::sanitize(remediation, NAME_LIMIT),
            proposed_change: "restore the freshly observed previous value".to_owned(),
            steps: Vec::new(),
            observed: ObservedStatus::Inconclusive,
            undo: None,
        };
        let Some(operation) = self.undo_operations.get(&undo).cloned() else {
            transcript.steps.push(step(
                started,
                false,
                "the undo is no longer available; no write was made",
            ));
            return transcript;
        };
        let observation_target = undo_observation_target(&operation, target);
        let before = match self.observe(&observation_target).await {
            Ok(report) => report,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("pre-undo re-observation failed: {error:#}"),
                ));
                transcript
                    .steps
                    .push(step(started, false, "no undo write was attempted"));
                return transcript;
            }
        };
        let observed = before
            .findings
            .iter()
            .find(|finding| finding.rule == rule)
            .map(|finding| finding.status);
        let expected = match expected {
            ObservedStatus::Pass => Some(airlock_core::findings::Status::Pass),
            ObservedStatus::Fail => Some(airlock_core::findings::Status::Fail),
            ObservedStatus::Inconclusive => None,
        };
        transcript.steps.push(step(
            started,
            observed.is_some(),
            "re-observed the rule immediately before undo",
        ));
        if expected.is_none() || observed != expected {
            transcript.steps.push(step(
                started,
                false,
                "the current observation no longer matches the undo point; no write was made",
            ));
            return transcript;
        }
        self.undo_operations.remove(&undo);
        let changed = self.undo(&operation).await;
        transcript.steps.push(step(
            started,
            changed.is_ok(),
            &changed.map_or_else(
                |error| format!("the undo request failed: {error:#}"),
                |()| "github accepted the undo request".to_owned(),
            ),
        ));
        match self.observe(target).await {
            Ok(report) => {
                transcript.observed = match report
                    .findings
                    .iter()
                    .find(|finding| finding.rule == rule)
                    .map(|finding| finding.status)
                {
                    Some(airlock_core::findings::Status::Fail) => ObservedStatus::Fail,
                    Some(airlock_core::findings::Status::Pass) => ObservedStatus::Pass,
                    _ => ObservedStatus::Inconclusive,
                };
                transcript.steps.push(step(
                    started,
                    true,
                    "re-observed the rule after undo; status follows that observation",
                ));
            }
            Err(error) => transcript.steps.push(step(
                started,
                false,
                &format!("post-undo re-observation failed: {error:#}"),
            )),
        }
        transcript
    }
}

fn undo_observation_target(operation: &UndoOperation, fallback: &Target) -> Target {
    match operation {
        UndoOperation::RenameRepository { owner, from, .. } => Target {
            owner: owner.clone(),
            repo: from.clone(),
        },
        _ => fallback.clone(),
    }
}

fn action_undo(
    owner: &str,
    repo: &str,
    action: Action,
    before: &Repository,
) -> Option<UndoOperation> {
    match action {
        Action::DefaultBranchMain => Some(UndoOperation::RenameBranch {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            from: "main".to_owned(),
            to: before.default_branch.clone(),
        }),
        Action::DisableMergeCommits => {
            before
                .allow_merge_commit
                .map(|value| UndoOperation::PatchRepository {
                    owner: owner.to_owned(),
                    repo: repo.to_owned(),
                    field: "allow_merge_commit".to_owned(),
                    value,
                })
        }
        Action::EnableSquashMerge => {
            before
                .allow_squash_merge
                .map(|value| UndoOperation::PatchRepository {
                    owner: owner.to_owned(),
                    repo: repo.to_owned(),
                    field: "allow_squash_merge".to_owned(),
                    value,
                })
        }
        Action::EnableHeadBranchAutoDelete => {
            before
                .delete_branch_on_merge
                .map(|value| UndoOperation::PatchRepository {
                    owner: owner.to_owned(),
                    repo: repo.to_owned(),
                    field: "delete_branch_on_merge".to_owned(),
                    value,
                })
        }
    }
}

fn input_undo(
    owner: &str,
    repo: &str,
    remediation: &str,
    argument: Option<&str>,
) -> Option<UndoOperation> {
    let argument = argument?;
    match remediation {
        "rename-repository-kebab"
        | "rename-repository-undotted"
        | "rename-repository-family-prefix" => Some(UndoOperation::RenameRepository {
            owner: owner.to_owned(),
            from: argument.to_owned(),
            to: repo.to_owned(),
        }),
        "rename-app-credentials" | "rename-task-named-credentials" => {
            let mut names = argument.lines();
            Some(UndoOperation::RenameVariable {
                owner: owner.to_owned(),
                repo: repo.to_owned(),
                from: names.nth(1)?.to_owned(),
                to: argument.lines().next()?.to_owned(),
            })
        }
        _ => None,
    }
}

fn observed_target(
    owner: &str,
    repo: &str,
    remediation: &str,
    argument: Option<&str>,
) -> (String, String) {
    match remediation {
        "transfer-repository" => (
            argument
                .and_then(|value| value.lines().next())
                .unwrap_or(owner)
                .to_owned(),
            repo.to_owned(),
        ),
        "rename-repository-kebab"
        | "rename-repository-undotted"
        | "rename-repository-family-prefix" => {
            (owner.to_owned(), argument.unwrap_or(repo).to_owned())
        }
        _ => (owner.to_owned(), repo.to_owned()),
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// The terminal loop's handle to the credential-owning worker.
pub struct Working {
    requests: Sender<Request>,
    responses: Receiver<Response>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Working {
    /// Start the one worker that owns every client built from the session grant.
    pub fn start(
        credential: &SessionCredential,
        version: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let session = Session::start(credential, version)?;
        let (requests, incoming) = std::sync::mpsc::channel();
        let (outgoing, responses) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("airlock-remediation".to_owned())
            .spawn(move || run(session, incoming, &outgoing))?;
        Ok(Self {
            requests,
            responses,
            worker: Some(worker),
        })
    }

    /// Queue one operation. A disconnected worker is an operational failure.
    pub fn request(&self, request: Request) -> anyhow::Result<()> {
        self.requests
            .send(request)
            .map_err(|_| anyhow::anyhow!("the remediation worker has stopped"))
    }

    /// Take one completed operation without blocking the terminal.
    pub fn next_response(&self) -> Option<Response> {
        self.responses.try_recv().ok()
    }
}

impl Drop for Working {
    fn drop(&mut self) {
        // Closing the request side is the worker's cancellation signal.
        let (replacement, _) = std::sync::mpsc::channel();
        self.requests = replacement;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(mut session: Session, requests: Receiver<Request>, responses: &Sender<Response>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = responses.send(Response::Failed(text::sanitize(
                &format!("the remediation worker could not start: {error}"),
                CAUSE_LIMIT,
            )));
            return;
        }
    };
    while let Ok(request) = requests.recv() {
        let response = match request {
            Request::Observe(target) => match runtime.block_on(session.observe(&target)) {
                Ok(report) => Response::Observed {
                    target,
                    report: Box::new(report),
                },
                Err(error) => Response::Failed(text::sanitize(
                    &format!("the repository observation failed: {error:#}"),
                    CAUSE_LIMIT,
                )),
            },
            Request::Prepare {
                target,
                remediation,
            } => match runtime.block_on(session.prepare(&target, &remediation)) {
                Ok(input) => Response::Prepared { remediation, input },
                Err(error) => Response::Failed(text::sanitize(
                    &format!("the remediation choices could not be observed: {error:#}"),
                    CAUSE_LIMIT,
                )),
            },
            Request::Apply {
                mut target,
                rule,
                remediation,
                argument,
            } => {
                let transcript = runtime.block_on(session.apply(
                    &target.owner,
                    &target.repo,
                    &rule,
                    &remediation,
                    argument.as_deref(),
                ));
                (target.owner, target.repo) = observed_target(
                    &target.owner,
                    &target.repo,
                    &remediation,
                    argument.as_deref(),
                );
                Response::Applied { target, transcript }
            }
            Request::ApplyGroup { target, requests } => {
                let borrowed = requests
                    .iter()
                    .map(|(rule, action)| (rule.as_str(), *action));
                let transcripts =
                    runtime.block_on(session.apply_group(&target.owner, &target.repo, borrowed));
                Response::GroupApplied {
                    target,
                    transcripts,
                }
            }
            Request::Undo {
                target,
                rule,
                remediation,
                undo,
                expected,
            } => {
                let transcript = runtime.block_on(session.apply_undo(
                    &target,
                    &rule,
                    &remediation,
                    undo,
                    expected,
                ));
                Response::Applied { target, transcript }
            }
        };
        if responses.send(response).is_err() {
            return;
        }
    }
}

fn write_grant() -> VerifiedGrant {
    let bound = identity::bound();
    VerifiedGrant {
        kind: TokenKind::AppUser,
        issuer: Some(bound.slug.to_owned()),
        login: None,
        scopes: Vec::new(),
        installations: vec![InstallationGrant {
            id: 1,
            account: None,
            permissions: bound
                .grant
                .iter()
                .map(|permission| format!("{}={}", permission.name, permission.level))
                .collect(),
        }],
    }
}

fn step(started: Instant, succeeded: bool, detail: &str) -> Step {
    Step {
        detail: text::sanitize(detail, CAUSE_LIMIT),
        elapsed: started.elapsed(),
        succeeded,
    }
}

fn accepted(status: StatusCode, endpoint: &str) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        anyhow::bail!("{endpoint} returned HTTP {}", status.as_u16())
    }
}

fn segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn only_changes_derivable_without_operator_data_are_executable() {
        assert_eq!(
            Action::for_code("disable-merge-commits"),
            Some(Action::DisableMergeCommits)
        );
        for code in [
            "transfer-repository",
            "rename-repository-kebab",
            "align-live-settings",
            "attach-org-rulesets",
            "tighten-org-rulesets",
            "rename-app-credentials",
            "rename-task-named-credentials",
        ] {
            assert_eq!(Action::for_code(code), None, "{code}");
        }
    }

    #[test]
    fn repository_patch_writes_only_the_selected_setting() {
        assert_eq!(
            serde_json::to_value(RepositoryPatch {
                allow_squash_merge: Some(true),
                ..RepositoryPatch::default()
            })
            .unwrap(),
            serde_json::json!({"allow_squash_merge": true})
        );
    }

    #[test]
    fn path_segments_are_encoded_not_interpolated() {
        assert_eq!(segment("name/other"), "name%2Fother");
        assert_eq!(segment("space here"), "space+here");
    }

    fn repository(allow_merge_commit: bool) -> serde_json::Value {
        serde_json::json!({
            "id": 41,
            "full_name": "generic-owner/sample-repository",
            "owner": {"login": "generic-owner"},
            "name": "sample-repository",
            "default_branch": "main",
            "visibility": "private",
            "allow_merge_commit": allow_merge_commit,
            "allow_squash_merge": true,
            "allow_rebase_merge": true,
            "delete_branch_on_merge": true,
            "has_wiki": false,
            "has_projects": false,
            "has_discussions": false,
            "has_issues": true
        })
    }

    async fn session(server: &MockServer) -> Session {
        let config = RestClientConfig {
            base_url: server.uri(),
            ..RestClientConfig::default().refusing_redirects()
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Session {
            token: "ghu_test_only".to_owned(),
            config,
            writer: WriteClient {
                http,
                token: "ghu_test_only".to_owned(),
                base_url: server.uri(),
            },
            version: "0.0.0".to_owned(),
            undo_operations: HashMap::new(),
            next_undo: 1,
        }
    }

    fn writer(server: &MockServer) -> WriteClient {
        WriteClient {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            token: "ghu_test_only".to_owned(),
            base_url: server.uri(),
        }
    }

    #[tokio::test]
    async fn input_mutations_have_fixture_shaped_requests() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/repos/generic-owner/sample-repository"))
            .and(body_json(serde_json::json!({"name": "renamed-repository"})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-owner/sample-repository/transfer"))
            .and(body_json(
                serde_json::json!({"new_owner": "destination-owner"}),
            ))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let writer = writer(&server);
        writer
            .rename_repository("generic-owner", "sample-repository", "renamed-repository")
            .await
            .unwrap();
        writer
            .transfer_repository("generic-owner", "sample-repository", "destination-owner")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ruleset_choices_are_fresh_and_creation_is_policy_shaped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 41, "name": "protected branches"}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/orgs/generic-owner/rulesets"))
            .and(body_json(ruleset_body(Some("sample-repository"))))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        let writer = writer(&server);
        assert_eq!(
            writer.rulesets("generic-owner").await.unwrap(),
            vec!["41 — protected branches"]
        );
        writer
            .attach_ruleset("generic-owner", "sample-repository", "create")
            .await
            .unwrap();
    }

    fn protected_ruleset() -> serde_json::Value {
        serde_json::json!({
            "id": 41,
            "name": "protected branches",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [{"actor_id": 7, "actor_type": "Team", "bypass_mode": "pull_request"}],
            "conditions": {
                "repository_name": {
                    "include": ["existing-repository"],
                    "exclude": ["excluded-repository"],
                    "protected": true
                }
            },
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["merge"],
                        "required_approving_review_count": 2,
                        "dismiss_stale_reviews_on_push": true,
                        "require_code_owner_review": true,
                        "require_last_push_approval": true,
                        "required_review_thread_resolution": true
                    }
                },
                {
                    "type": "required_status_checks",
                    "parameters": {"strict_required_status_checks_policy": true}
                }
            ]
        })
    }

    #[tokio::test]
    async fn attaching_an_existing_ruleset_changes_only_its_repository_condition() {
        let server = MockServer::start().await;
        let existing = protected_ruleset();
        let expected = ruleset_attach_body(existing.clone(), "sample-repository").unwrap();
        assert_eq!(expected["rules"], existing["rules"]);
        assert_eq!(expected["bypass_actors"], existing["bypass_actors"]);
        assert_eq!(
            expected["conditions"]["repository_name"]["include"],
            serde_json::json!(["existing-repository", "sample-repository"])
        );
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets/41"))
            .respond_with(ResponseTemplate::new(200).set_body_json(existing))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/orgs/generic-owner/rulesets/41"))
            .and(body_json(expected))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        writer(&server)
            .attach_ruleset("generic-owner", "sample-repository", "41")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn tightening_preserves_every_unasserted_rule_and_parameter() {
        let server = MockServer::start().await;
        let existing = protected_ruleset();
        let expected = ruleset_tighten_body(existing.clone()).unwrap();
        let mut preserved_parameters = existing["rules"][0]["parameters"].clone();
        preserved_parameters["allowed_merge_methods"] = serde_json::json!(["squash", "rebase"]);
        assert_eq!(expected["rules"][0]["parameters"], preserved_parameters);
        assert_eq!(
            expected["rules"][0]["parameters"]["required_approving_review_count"],
            2
        );
        assert_eq!(
            expected["rules"][0]["parameters"]["require_code_owner_review"],
            true
        );
        assert_eq!(
            expected["rules"][0]["parameters"]["allowed_merge_methods"],
            serde_json::json!(["squash", "rebase"])
        );
        assert_eq!(expected["rules"][1], existing["rules"][1]);
        assert_eq!(expected["conditions"], existing["conditions"]);
        assert_eq!(expected["bypass_actors"], existing["bypass_actors"]);
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets/41"))
            .respond_with(ResponseTemplate::new(200).set_body_json(existing))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/orgs/generic-owner/rulesets/41"))
            .and(body_json(expected))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        writer(&server)
            .tighten_ruleset("generic-owner", "41")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn variable_rename_preserves_the_worker_only_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/variables/OLD_NAME",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"name":"OLD_NAME","value":"opaque-value"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/variables",
            ))
            .and(body_json(
                serde_json::json!({"name":"NEW_NAME","value":"opaque-value"}),
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/variables/OLD_NAME",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        writer(&server)
            .rename_variable("generic-owner", "sample-repository", "OLD_NAME\nNEW_NAME")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_accepted_write_that_does_not_close_the_gap_reports_fail() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/generic-owner/sample-repository"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repository(true)))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/generic-owner/sample-repository"))
            .and(body_json(serde_json::json!({"allow_merge_commit": false})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let transcript = session(&server)
            .await
            .apply(
                "generic-owner",
                "sample-repository",
                "REPO-GIT-04",
                "disable-merge-commits",
                None,
            )
            .await;

        assert_eq!(transcript.observed, ObservedStatus::Fail);
        assert!(transcript
            .steps
            .iter()
            .any(|step| step.detail.contains("accepted")));
        assert!(transcript
            .steps
            .last()
            .is_some_and(|step| step.detail.contains("gap remains open")));
    }

    #[tokio::test]
    async fn a_fresh_pass_makes_no_write_and_still_reobserves() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/generic-owner/sample-repository"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repository(false)))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/generic-owner/sample-repository"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let transcript = session(&server)
            .await
            .apply(
                "generic-owner",
                "sample-repository",
                "REPO-GIT-04",
                "disable-merge-commits",
                None,
            )
            .await;

        assert_eq!(transcript.observed, ObservedStatus::Pass);
        assert!(transcript
            .steps
            .iter()
            .any(|step| step.detail.contains("no write was made")));
    }
}
