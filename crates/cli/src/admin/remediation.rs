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
use serde::Serialize;
use zeroize::Zeroize as _;

use super::bootstrap;
use super::flow;
use super::identity;
use super::session::SessionCredential;
use super::text::{self, CAUSE_LIMIT, NAME_LIMIT};

/// Where a repository declares what it releases.
const INTENTIONAL_CONFIG: &str = ".intentional/config.yml";

/// What the repository declares it publishes, read from one snapshot.
///
/// The release units come from the declaration and the manifests come from the
/// tree, so both halves are facts about the audited commit rather than
/// something the operator told the interface.
fn declaration_of(
    snapshot: &airlock_core::snapshot::RepoSnapshot,
    limits: Limits,
) -> bootstrap::Declaration {
    use airlock_core::snapshot::FileState;
    let mut declaration = bootstrap::Declaration {
        units: Vec::new(),
        files: snapshot
            .tree
            .entries
            .iter()
            .filter(|entry: &&airlock_core::github::TreeEntry| {
                matches!(
                    entry.kind,
                    airlock_core::github::EntryKind::Blob
                        | airlock_core::github::EntryKind::ExecutableBlob
                )
            })
            .map(|entry| entry.path.clone())
            .collect(),
    };
    let state = snapshot.file(INTENTIONAL_CONFIG);
    if !matches!(state, FileState::Content { .. }) {
        return declaration;
    }
    let Ok(document) =
        airlock_core::yaml::parse_mapping(state.text().unwrap_or_default(), limits.yaml)
    else {
        return declaration;
    };
    let Some(units) = document
        .get("release-units")
        .and_then(airlock_core::yaml::Yaml::as_map)
    else {
        return declaration;
    };
    declaration.units = units
        .iter()
        .map(|(id, unit)| {
            let path = unit
                .get("path")
                .and_then(airlock_core::yaml::Yaml::as_str)
                .unwrap_or(".")
                .trim_end_matches('/')
                .to_owned();
            (id.clone(), path)
        })
        .collect();
    declaration
}

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

/// One capability the resolved owner policy lets a new repository declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldCapability {
    pub name: String,
    /// Terminal-safe reading of `name`; never used in an API request.
    pub display_name: String,
    pub property: String,
    pub value: String,
}

/// Fresh policy-derived choices for repository creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldPlan {
    pub owner: String,
    pub capabilities: Vec<ScaffoldCapability>,
    pub files: Vec<String>,
}

/// The confirmed, credential-free repository creation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldRequest {
    pub owner: String,
    pub owner_is_organization: bool,
    pub name: String,
    pub visibility: String,
    pub capabilities: Vec<ScaffoldCapability>,
}

/// Freshly observed values that the rendering layer may offer as choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedInput {
    Rulesets(Vec<String>),
    Credentials {
        variables: Vec<String>,
        secrets: Vec<String>,
    },
}

/// A secret supplied by the operator.
///
/// This type deliberately implements none of `Clone`, `Debug`, `Display`, or
/// `Serialize`. Drawable state cannot contain it, and the only way to create
/// one is to consume a [`SecretEntry`].
pub struct SecretValue(String);

impl SecretValue {
    fn expose(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn test_bytes(&self) -> &[u8] {
        self.expose()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The shared value- and length-hidden entry buffer owned by the terminal
/// driver, outside every drawable application model.
pub struct SecretEntry {
    value: String,
}

const INITIAL_SECRET_CAPACITY: usize = 256;

impl Default for SecretEntry {
    fn default() -> Self {
        Self {
            value: String::with_capacity(INITIAL_SECRET_CAPACITY),
        }
    }
}

/// What the shared terminal input controller asks its host to do.
pub enum SecretInputAction {
    Changed { holding_input: bool },
    RefusedEmpty,
    Submit(SecretValue),
    Cancel,
    Exit,
    Ignored,
}

/// Value-free description of a write that consumes freshly supplied input.
/// New consumers extend this boundary without changing terminal input routing.
pub enum SecretOperation {
    RenameCredentials {
        variable: Option<(String, String)>,
        secret: (String, String),
    },
    /// Set one named repository secret to the value just supplied.
    ///
    /// The publishing bootstrap's second step. The write is decided by the
    /// named secret alone, and its completion is the re-observed presence of
    /// that name: GitHub does not read a secret's value back, so nothing here
    /// can claim the value works.
    SetRepositorySecret { name: String },
}

impl SecretEntry {
    /// Explicitly erase input held across a terminal-driver boundary.
    pub fn clear(&mut self) {
        self.value.zeroize();
    }

    fn reserve_without_plaintext_reallocation(&mut self, additional: usize) {
        let required = self.value.len().saturating_add(additional);
        if required <= self.value.capacity() {
            return;
        }
        let capacity = required
            .checked_next_power_of_two()
            .unwrap_or(required)
            .max(INITIAL_SECRET_CAPACITY);
        let mut replacement = String::with_capacity(capacity);
        replacement.push_str(&self.value);
        self.value.zeroize();
        self.value = replacement;
    }

    pub fn push(&mut self, character: char) {
        self.reserve_without_plaintext_reallocation(character.len_utf8());
        self.value.push(character);
    }

    pub fn paste(&mut self, value: &mut String) {
        self.reserve_without_plaintext_reallocation(value.len());
        self.value.push_str(value);
        // This clears the event allocation airlock receives. Crossterm's
        // parser has already copied its internal read buffer into this String;
        // that dependency-owned buffer is outside airlock's reach.
        value.zeroize();
    }

    pub fn backspace(&mut self) {
        self.value.pop();
    }

    pub fn take(&mut self) -> Option<SecretValue> {
        (!self.value.is_empty()).then(|| SecretValue(std::mem::take(&mut self.value)))
    }

    /// Handle the complete focused terminal-input contract in one reusable
    /// driver-owned component. Consumers provide only drawable state changes.
    pub fn handle_terminal_event(&mut self, event: crossterm::event::Event) -> SecretInputAction {
        use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
        match event {
            Event::Paste(mut value) => {
                self.paste(&mut value);
                SecretInputAction::Changed {
                    holding_input: !self.value.is_empty(),
                }
            }
            Event::Key(key) if key.kind == KeyEventKind::Release => SecretInputAction::Ignored,
            Event::Key(key)
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c') =>
            {
                SecretInputAction::Exit
            }
            Event::Key(key) => match key.code {
                KeyCode::Esc => {
                    self.clear();
                    SecretInputAction::Cancel
                }
                KeyCode::Enter => self
                    .take()
                    .map_or(SecretInputAction::RefusedEmpty, SecretInputAction::Submit),
                KeyCode::Backspace => {
                    self.backspace();
                    SecretInputAction::Changed {
                        holding_input: !self.value.is_empty(),
                    }
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.push(character);
                    SecretInputAction::Changed {
                        holding_input: true,
                    }
                }
                _ => SecretInputAction::Ignored,
            },
            _ => SecretInputAction::Ignored,
        }
    }
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Work the terminal loop asks the credential-owning worker to do.
pub enum Request {
    /// Observe a repository in full under its owner's default policy.
    Observe(Target),
    /// Observe the publishing bootstrap's facts: the bootstrap secret, the
    /// package, and any public publisher signal. Asked for afresh every time,
    /// because the flow persists no position of its own.
    ObserveBootstrap(Target),
    /// Resolve the owner's policy immediately before offering scaffold choices.
    PrepareScaffold { owner: String },
    /// Re-observe a repository whose creation was in flight when the grant
    /// lapsed, then either audit it or freshly resolve the scaffold plan.
    RecoverScaffold(Target),
    /// Create an empty repository, its capability declarations, and its sole
    /// direct branch-creating commit, then run the ordinary audit.
    Scaffold(ScaffoldRequest),
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
    /// Apply a secret-bearing operation. The value cannot enter drawable state.
    ApplyWithSecret {
        target: Target,
        rule: String,
        remediation: String,
        operation: SecretOperation,
        value: SecretValue,
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
    /// The publishing bootstrap's freshly observed facts, one per target.
    BootstrapObserved {
        target: Target,
        observations: Vec<bootstrap::Observation>,
    },
    /// Policy-derived scaffold choices.
    ScaffoldPrepared(ScaffoldPlan),
    /// The ordinary audit observed immediately after repository creation.
    Scaffolded {
        target: Target,
        report: Box<Report>,
        warnings: Vec<String>,
    },
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
/// reach anything below. Writes are never retried: a transport failure is
/// ambiguous because the mutation may have landed, and observe-write-observe
/// resolves that ambiguity without risking a double application.
struct WriteClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl WriteClient {
    fn from_session(credential: &SessionCredential) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
            .pool_idle_timeout(Duration::from_secs(5))
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
        accepted(response, "PATCH /repos/{owner}/{repo}")
            .await
            .map(|_| ())
    }

    async fn repository_absent(&self, owner: &str, repo: &str) -> anyhow::Result<bool> {
        let endpoint = "GET /repos/{owner}/{repo}";
        let response = self
            .http
            .get(format!(
                "{}/repos/{}/{}",
                self.base_url,
                segment(owner),
                segment(repo)
            ))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(true);
        }
        accepted(response, endpoint).await.map(|_| false)
    }

    async fn create_repository(&self, request: &ScaffoldRequest) -> anyhow::Result<()> {
        let (path, endpoint) = if request.owner_is_organization {
            (
                format!("/orgs/{}/repos", segment(&request.owner)),
                "POST /orgs/{org}/repos",
            )
        } else {
            ("/user/repos".to_owned(), "POST /user/repos")
        };
        self.send_json(
            reqwest::Method::POST,
            &path,
            &serde_json::json!({
                "name": request.name,
                "visibility": request.visibility,
                "auto_init": false
            }),
            endpoint,
        )
        .await
    }

    async fn create_initial_commit(
        &self,
        owner: &str,
        repo: &str,
        files: &[airlock_core::alignment::ScaffoldFile],
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            !files.is_empty(),
            "the policy produced no deterministic base files"
        );
        let mut tree = Vec::with_capacity(files.len());
        for file in files {
            use base64::Engine as _;
            let value = self
                .send_json_value(
                    reqwest::Method::POST,
                    &format!("/repos/{}/{}/git/blobs", segment(owner), segment(repo)),
                    &serde_json::json!({
                        "content": base64::engine::general_purpose::STANDARD.encode(&file.contents),
                        "encoding": "base64"
                    }),
                    "POST /repos/{owner}/{repo}/git/blobs",
                )
                .await?;
            let sha = json_sha(&value, "POST /repos/{owner}/{repo}/git/blobs")?;
            tree.push(serde_json::json!({
                "path": file.path,
                "mode": "100644",
                "type": "blob",
                "sha": sha
            }));
        }
        let value = self
            .send_json_value(
                reqwest::Method::POST,
                &format!("/repos/{}/{}/git/trees", segment(owner), segment(repo)),
                &serde_json::json!({"tree": tree}),
                "POST /repos/{owner}/{repo}/git/trees",
            )
            .await?;
        let tree_sha = json_sha(&value, "POST /repos/{owner}/{repo}/git/trees")?;
        let value = self
            .send_json_value(
                reqwest::Method::POST,
                &format!("/repos/{}/{}/git/commits", segment(owner), segment(repo)),
                &serde_json::json!({
                    "message": "chore: scaffold repository",
                    "tree": tree_sha,
                    "parents": []
                }),
                "POST /repos/{owner}/{repo}/git/commits",
            )
            .await?;
        let commit_sha = json_sha(&value, "POST /repos/{owner}/{repo}/git/commits")?;
        self.send_json(
            reqwest::Method::POST,
            &format!("/repos/{}/{}/git/refs", segment(owner), segment(repo)),
            &serde_json::json!({"ref": "refs/heads/main", "sha": commit_sha}),
            "POST /repos/{owner}/{repo}/git/refs",
        )
        .await?;
        Ok(commit_sha.to_owned())
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
            response,
            "POST /repos/{owner}/{repo}/branches/{branch}/rename",
        )
        .await
        .map(|_| ())
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
                .get_json(
                    &format!("/orgs/{}/rulesets/{}", segment(owner), segment(id)),
                    "GET /orgs/{org}/rulesets/{id}",
                )
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
            .get_json(
                &format!("/orgs/{}/rulesets/{}", segment(owner), segment(id)),
                "GET /orgs/{org}/rulesets/{id}",
            )
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
        anyhow::ensure!(old != new, "variable rename needs two different names");
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
        let response = accepted(
            response,
            "GET /repos/{owner}/{repo}/actions/variables/{name}",
        )
        .await?;
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
            response,
            "DELETE /repos/{owner}/{repo}/actions/variables/{name}",
        )
        .await
        .map(|_| ())
    }

    async fn rulesets(&self, owner: &str) -> anyhow::Result<Vec<String>> {
        let value = self
            .get_json(
                &format!("/orgs/{}/rulesets?per_page=100", segment(owner)),
                "GET /orgs/{org}/rulesets",
            )
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
            .get_json(
                &format!(
                    "/repos/{}/{}/actions/variables?per_page=100",
                    segment(owner),
                    segment(repo)
                ),
                "GET /repos/{owner}/{repo}/actions/variables",
            )
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

    async fn set_custom_property(
        &self,
        organization: &str,
        repository: &str,
        property: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.send_json(
            reqwest::Method::PATCH,
            &format!("/orgs/{}/properties/values", segment(organization)),
            &serde_json::json!({
                "repository_names": [repository],
                "properties": [{"property_name": property, "value": value}]
            }),
            "PATCH /orgs/{org}/properties/values",
        )
        .await
    }

    async fn secrets(&self, owner: &str, repo: &str) -> anyhow::Result<Vec<String>> {
        let value = self
            .get_json(
                &format!(
                    "/repos/{}/{}/actions/secrets?per_page=100",
                    segment(owner),
                    segment(repo)
                ),
                "GET /repos/{owner}/{repo}/actions/secrets",
            )
            .await?;
        let rows = value
            .get("secrets")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("the secret response carried no list"))?;
        Ok(rows
            .iter()
            .filter_map(|row| row.get("name").and_then(serde_json::Value::as_str))
            .map(|name| text::sanitize(name, NAME_LIMIT))
            .collect())
    }

    /// The repository's Actions secrets, by name and creation time.
    ///
    /// GitHub reports when a secret was created and never what it holds, which
    /// is exactly what the outstanding-credential block is allowed to show.
    async fn secret_records(
        &self,
        owner: &str,
        repo: &str,
    ) -> anyhow::Result<Vec<bootstrap::Credential>> {
        let value = self
            .get_json(
                &format!(
                    "/repos/{}/{}/actions/secrets?per_page=100",
                    segment(owner),
                    segment(repo)
                ),
                "GET /repos/{owner}/{repo}/actions/secrets",
            )
            .await?;
        let rows = value
            .get("secrets")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("the secret response carried no list"))?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                let name = row.get("name").and_then(serde_json::Value::as_str)?;
                Some(bootstrap::Credential {
                    name: text::sanitize(name, NAME_LIMIT),
                    scope: format!("{owner}/{repo} \u{b7} Actions repository secret"),
                    created: row
                        .get("created_at")
                        .and_then(serde_json::Value::as_str)
                        .map_or_else(
                            || "not stated by GitHub".to_owned(),
                            |at| text::sanitize(at, NAME_LIMIT),
                        ),
                })
            })
            .collect())
    }

    /// Read one container package by name.
    ///
    /// By name rather than by enumeration: the container list endpoint rejects
    /// the credential shape airlock holds, and the package name is derived from
    /// the repository's declared release units anyway.
    async fn container_package(
        &self,
        owner: &str,
        package: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let path = |scope: &str| {
            format!(
                "/{scope}/{}/packages/container/{}",
                segment(owner),
                segment(package)
            )
        };
        match self
            .optional_json(&path("orgs"), "GET /orgs/{org}/packages/container/{name}")
            .await
        {
            Ok(Some(value)) => Ok(Some(value)),
            // An account that is not an organization answers the user-scoped
            // path instead, and the two are not distinguishable from here
            // without asking. A package absent under both is absent.
            Ok(None) | Err(_) => {
                self.optional_json(
                    &path("users"),
                    "GET /users/{username}/packages/container/{name}",
                )
                .await
            }
        }
    }

    /// A read whose 404 is an answer rather than a failure.
    async fn optional_json(
        &self,
        path: &str,
        endpoint: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = accepted(response, endpoint).await?;
        response.json().await.map(Some).map_err(Into::into)
    }

    /// Write one named repository secret.
    ///
    /// The value is sealed to the repository's own public key before it leaves
    /// this process, and it exists here only as the borrowed [`SecretValue`]
    /// the caller owns.
    async fn put_secret(
        &self,
        owner: &str,
        repo: &str,
        name: &str,
        value: &SecretValue,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!name.is_empty(), "a repository secret write needs a name");
        let (key_id, encrypted_value) = self.seal_for_repository(owner, repo, value).await?;
        self.send_json(
            reqwest::Method::PUT,
            &format!(
                "/repos/{}/{}/actions/secrets/{}",
                segment(owner),
                segment(repo),
                segment(name)
            ),
            &serde_json::json!({"encrypted_value": encrypted_value, "key_id": key_id}),
            "PUT /repos/{owner}/{repo}/actions/secrets/{name}",
        )
        .await
    }

    /// Seal a value to the repository's Actions public key.
    async fn seal_for_repository(
        &self,
        owner: &str,
        repo: &str,
        value: &SecretValue,
    ) -> anyhow::Result<(String, String)> {
        let key = self
            .get_json(
                &format!(
                    "/repos/{}/{}/actions/secrets/public-key",
                    segment(owner),
                    segment(repo)
                ),
                "GET /repos/{owner}/{repo}/actions/secrets/public-key",
            )
            .await?;
        let key_id = key
            .get("key_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!("the repository secret public-key response carried no key id")
            })?;
        let encoded_key = key
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!("the repository secret public-key response carried no key")
            })?;
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_key)
            .map_err(|_| {
                anyhow::anyhow!("the repository secret public key was not valid base64")
            })?;
        let public_key = crypto_box::PublicKey::from_slice(&decoded)
            .map_err(|_| anyhow::anyhow!("the repository secret public key was not 32 bytes"))?;
        let encrypted = public_key
            .seal(&mut crypto_box::aead::OsRng, value.expose())
            .map_err(|_| anyhow::anyhow!("the repository secret value could not be encrypted"))?;
        Ok((
            key_id.to_owned(),
            base64::engine::general_purpose::STANDARD.encode(encrypted),
        ))
    }

    async fn rename_secret(
        &self,
        owner: &str,
        repo: &str,
        old: &str,
        new: &str,
        value: &SecretValue,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !old.is_empty() && !new.is_empty(),
            "secret rename needs old and new names"
        );
        anyhow::ensure!(old != new, "secret rename needs two different names");
        let (key_id, encrypted_value) = self.seal_for_repository(owner, repo, value).await?;
        self.send_json(
            reqwest::Method::PUT,
            &format!(
                "/repos/{}/{}/actions/secrets/{}",
                segment(owner),
                segment(repo),
                segment(new)
            ),
            &serde_json::json!({"encrypted_value": encrypted_value, "key_id": key_id}),
            "PUT /repos/{owner}/{repo}/actions/secrets/{name}",
        )
        .await?;
        let response = self
            .http
            .delete(format!(
                "{}/repos/{}/{}/actions/secrets/{}",
                self.base_url,
                segment(owner),
                segment(repo),
                segment(old)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        accepted(
            response,
            "DELETE /repos/{owner}/{repo}/actions/secrets/{name}",
        )
        .await
        .map(|_| ())
    }

    async fn get_json(&self, path: &str, endpoint: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        let response = accepted(response, endpoint)
            .await
            .map_err(|error| anyhow::anyhow!("the settings observation {error}"))?;
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
        accepted(response, endpoint).await.map(|_| ())
    }

    async fn send_json_value(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &serde_json::Value,
        endpoint: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
            .send()
            .await?;
        accepted(response, endpoint)
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}

fn json_sha<'a>(value: &'a serde_json::Value, endpoint: &str) -> anyhow::Result<&'a str> {
    value
        .get("sha")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{endpoint} returned no object sha"))
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
struct CapabilitySettlement {
    changed: anyhow::Result<()>,
    observed: anyhow::Result<(ObservedStatus, String)>,
}

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

    /// Observe everything the publishing bootstrap places the operator by.
    ///
    /// Three reads and no memory: what the repository declares it publishes,
    /// which bootstrap secrets it holds, and whether each package exists on its
    /// registry. A read that fails is an operational failure rather than an
    /// absence — reporting an unread secret as "no credential" would call a
    /// ceremony finished that is not.
    pub async fn observe_bootstrap(
        &self,
        target: &Target,
    ) -> anyhow::Result<Vec<bootstrap::Observation>> {
        let reader = self.reader()?;
        let limits = Limits::default();
        let mut snapshot = airlock_core::snapshot::RepoSnapshot::read(
            &reader,
            &target.owner,
            &target.repo,
            None,
            limits,
        )
        .await
        .map_err(|error| anyhow::anyhow!("the repository could not be read: {error}"))?;
        snapshot
            .load_files(
                &reader,
                &target.owner,
                &target.repo,
                &[INTENTIONAL_CONFIG.to_owned()],
            )
            .await;
        let declaration = declaration_of(&snapshot, limits);
        let units = bootstrap::units(&declaration);
        let credentials = self
            .writer
            .secret_records(&target.owner, &target.repo)
            .await?;
        let probe = reqwest::Client::builder()
            .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        let mut observations = Vec::new();
        for unit in units {
            let credential = unit.registry.bootstrap_secret().and_then(|name| {
                credentials
                    .iter()
                    .find(|credential| credential.name == name)
                    .cloned()
            });
            let container = if unit.registry == bootstrap::Registry::Ghcr {
                Some(
                    match self
                        .writer
                        .container_package(&target.owner, &unit.package)
                        .await
                    {
                        Ok(Some(document)) => bootstrap::container_of(&document),
                        Ok(None) => bootstrap::Container::Absent,
                        Err(error) => bootstrap::Container::Undecided {
                            reason: text::sanitize(&format!("{error:#}"), CAUSE_LIMIT),
                        },
                    },
                )
            } else {
                None
            };
            let (publication, publisher) = bootstrap::read_package(&probe, &unit).await;
            observations.push(bootstrap::Observation {
                unit,
                credential,
                publication,
                publisher,
                container,
            });
        }
        Ok(observations)
    }

    async fn scaffold_plan(
        &self,
        owner: &str,
    ) -> anyhow::Result<(ScaffoldPlan, Vec<airlock_core::alignment::ScaffoldFile>)> {
        let reader = self.reader()?;
        let policy = policy::resolve(
            &reader,
            &PolicySource::default_for_owner(owner),
            &Limits::default(),
        )
        .await?;
        let files = airlock_core::alignment::scaffold_files(&policy);
        let capabilities = policy
            .capabilities
            .iter()
            .filter_map(|capability| match &capability.condition {
                airlock_core::policy::Condition::CustomProperty { name, value } => {
                    Some(ScaffoldCapability {
                        name: capability.name.clone(),
                        display_name: text::drawable(&capability.name),
                        property: name.clone(),
                        value: value.clone(),
                    })
                }
                airlock_core::policy::Condition::Always
                | airlock_core::policy::Condition::IntentionalConfigPresent => None,
            })
            .collect();
        Ok((
            ScaffoldPlan {
                owner: owner.to_owned(),
                capabilities,
                files: files.iter().map(|file| file.path.clone()).collect(),
            },
            files,
        ))
    }

    async fn scaffold(&self, request: &ScaffoldRequest) -> anyhow::Result<(Report, Vec<String>)> {
        anyhow::ensure!(
            valid_repository_name(&request.name),
            "the repository name is not accepted by Airlock's GitHub name gate"
        );
        anyhow::ensure!(
            matches!(
                request.visibility.as_str(),
                "public" | "private" | "internal"
            ),
            "the repository visibility is not recognized"
        );
        anyhow::ensure!(
            self.writer
                .repository_absent(&request.owner, &request.name)
                .await?,
            "no request was made because {}/{} already exists",
            request.owner,
            request.name
        );
        let (fresh, files) = self.scaffold_plan(&request.owner).await?;
        anyhow::ensure!(
            !files.is_empty(),
            "the resolved owner policy requires no fixed deterministic file for the initial commit"
        );
        for selected in &request.capabilities {
            anyhow::ensure!(
                fresh.capabilities.contains(selected),
                "the selected capability `{}` is not present in the freshly resolved owner policy",
                selected.name
            );
        }

        self.writer.create_repository(request).await?;
        anyhow::ensure!(
            !self.writer.repository_absent(&request.owner, &request.name).await?,
            "GitHub accepted repository creation but immediate re-observation still reports it absent"
        );

        let reader = self.reader()?;
        // Establish the branch before optional settings writes. A failure to
        // assign a custom property must not strand the repository in the one
        // state that has no ordinary remediation path.
        let empty = reader.repository(&request.owner, &request.name).await?;
        anyhow::ensure!(
            empty.default_branch.is_empty(),
            "repository-creation re-observation expected no default branch before the first commit but observed `{}`",
            empty.default_branch
        );
        self.writer
            .create_initial_commit(&request.owner, &request.name, &files)
            .await?;
        let repository = reader.repository(&request.owner, &request.name).await?;
        anyhow::ensure!(
            repository.default_branch == "main",
            "initial-commit re-observation expected default branch `main` but observed `{}`",
            repository.default_branch
        );

        let mut warnings = Vec::new();
        for capability in &request.capabilities {
            let settlement = self
                .settle_capability_decision(
                    &request.owner,
                    &request.name,
                    &capability.property,
                    &capability.value,
                )
                .await;
            if let Err(error) = settlement.changed {
                warnings.push(format!(
                    "capability `{}` change request failed: {error:#}",
                    capability.name
                ));
            }
            match settlement.observed {
                Ok((ObservedStatus::Pass, _)) => {}
                Ok((_, detail)) => warnings.push(detail),
                Err(error) => warnings.push(format!(
                    "capability `{}` post-change property re-observation failed: {error:#}",
                    capability.name
                )),
            }
        }
        let report = self
            .observe(&Target {
                owner: request.owner.clone(),
                repo: request.name.clone(),
            })
            .await?;
        Ok((report, warnings))
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
            "rename-app-credentials" | "rename-task-named-credentials" => {
                let variables = self.writer.variables(&target.owner, &target.repo).await?;
                let secrets = self.writer.secrets(&target.owner, &target.repo).await?;
                Ok(PreparedInput::Credentials { variables, secrets })
            }
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
            || {
                if remediation == "declare-capability-property" {
                    let mut parts = argument.unwrap_or_default().lines();
                    format!(
                        "set organization custom property `{}` to `{}` for `{owner}/{repo}`",
                        parts.next().unwrap_or_default(),
                        parts.next().unwrap_or_default()
                    )
                } else {
                    "requires explicit operator input; airlock will not guess it".to_owned()
                }
            },
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
            let mut capability_settlement = None;
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
            let before_finding = before.findings.iter().find(|finding| finding.rule == rule);
            let before_status = before_finding.map(|finding| finding.status);
            let capability_decision = remediation == "declare-capability-property"
                && before_finding
                    .and_then(|finding| finding.evidence.as_ref())
                    .is_some_and(|evidence| evidence.code == "capability_undeclared");
            transcript.steps.push(step(
                started,
                before_status.is_some(),
                "re-observed the rule immediately before acting",
            ));
            if before_status != Some(airlock_core::findings::Status::Fail) && !capability_decision {
                transcript.steps.push(step(
                    started,
                    before_status == Some(airlock_core::findings::Status::Pass),
                    "the fresh observation does not report a gap; no write was made",
                ));
            } else {
                let changed = if capability_decision {
                    let mut parts = argument.unwrap_or_default().lines();
                    let property = parts.next().unwrap_or_default();
                    let expected = parts.next().unwrap_or_default();
                    let settlement = self
                        .settle_capability_decision(owner, repo, property, expected)
                        .await;
                    let changed = match &settlement.changed {
                        Ok(()) => Ok(()),
                        Err(error) => Err(anyhow::anyhow!("{error:#}")),
                    };
                    capability_settlement = Some(settlement);
                    changed
                } else {
                    self.change_with_input(owner, repo, remediation, argument.unwrap_or_default())
                        .await
                };
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

            if remediation == "declare-capability-property" {
                let mut parts = argument.unwrap_or_default().lines();
                let property = parts.next().unwrap_or_default();
                let expected = parts.next().unwrap_or_default();
                let observation = match capability_settlement {
                    Some(settlement) => settlement.observed,
                    None => {
                        self.reobserve_capability_decision(owner, repo, property, expected)
                            .await
                    }
                };
                match observation {
                    Ok((observed, detail)) => {
                        transcript.observed = observed;
                        transcript.steps.push(step(
                            started,
                            transcript.observed == ObservedStatus::Pass,
                            &detail,
                        ));
                    }
                    Err(error) => transcript.steps.push(step(
                        started,
                        false,
                        &format!("post-change property re-observation failed: {error:#}"),
                    )),
                }
                return transcript;
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
                let changed = self
                    .change(
                        owner,
                        repo,
                        action.expect("input-bearing remediations returned above"),
                        &before,
                    )
                    .await;
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

    pub async fn apply_with_secret(
        &mut self,
        owner: &str,
        repo: &str,
        rule: &str,
        remediation: &str,
        operation: &SecretOperation,
        value: &SecretValue,
    ) -> Transcript {
        match operation {
            SecretOperation::SetRepositorySecret { name } => {
                self.set_repository_secret(owner, repo, rule, remediation, name, value)
                    .await
            }
            SecretOperation::RenameCredentials { .. } => {
                self.rename_credentials(owner, repo, rule, remediation, operation, value)
                    .await
            }
        }
    }

    /// Set one named repository secret, and report what was then observed.
    ///
    /// The same observe-write-observe shape as every other write, with the one
    /// honest difference this write carries: GitHub does not read a secret's
    /// value back, so the closing observation establishes that the name exists
    /// and nothing more. Nothing here says the value works, and the first
    /// release is what will answer that.
    async fn set_repository_secret(
        &self,
        owner: &str,
        repo: &str,
        rule: &str,
        remediation: &str,
        name: &str,
        value: &SecretValue,
    ) -> Transcript {
        let started = Instant::now();
        let mut transcript = Transcript {
            rule: text::sanitize(rule, NAME_LIMIT),
            remediation: text::sanitize(remediation, NAME_LIMIT),
            proposed_change: format!(
                "set the repository secret `{}` to the value just supplied by the operator",
                text::sanitize(name, NAME_LIMIT)
            ),
            steps: Vec::new(),
            observed: ObservedStatus::Inconclusive,
            undo: None,
        };
        let held = match self.writer.secret_records(owner, repo).await {
            Ok(records) => records,
            Err(error) => {
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("pre-write observation of the repository's secrets failed: {error:#}"),
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
            &if held.iter().any(|record| record.name == name) {
                "re-observed the secret immediately before acting; it exists and \
                 will be replaced"
                    .to_owned()
            } else {
                "re-observed the repository's secrets immediately before acting; \
                 this name is not among them"
                    .to_owned()
            },
        ));
        let existed = held.iter().any(|record| record.name == name);
        let rejected = self
            .writer
            .put_secret(owner, repo, name, value)
            .await
            .err()
            .map(|error| format!("{error:#}"));
        transcript.steps.push(step(
            started,
            rejected.is_none(),
            &rejected.as_ref().map_or_else(
                || "github accepted the sealed repository secret".to_owned(),
                |error| format!("the repository secret write failed: {error}"),
            ),
        ));
        match self.writer.secret_records(owner, repo).await {
            Ok(records) => {
                let present = records.iter().any(|record| record.name == name);
                // Presence answers the question only where the write was
                // accepted. On a replacement the name was already there, so a
                // rejected write leaves a listing that looks exactly like a
                // successful one — and the credential it still names is the
                // dead token the operator came here to replace. The write's own
                // rejection is the decisive fact, and it decides.
                transcript.observed = match (&rejected, present) {
                    (Some(_), _) => ObservedStatus::Fail,
                    (None, true) => ObservedStatus::Pass,
                    (None, false) => ObservedStatus::Fail,
                };
                transcript.steps.push(step(
                    started,
                    transcript.observed == ObservedStatus::Pass,
                    &match (&rejected, present, existed) {
                        (Some(error), true, true) => format!(
                            "re-observation reports the name present, but this write \
                             was rejected: {error}. The name is the one that was \
                             already there, so the value behind it is still the old \
                             one; presence cannot tell a landed replacement from the \
                             value it was meant to replace."
                        ),
                        (Some(error), true, false) => format!(
                            "re-observation reports the name present, but this write \
                             was rejected: {error}. Something other than this write \
                             put it there, so nothing here establishes what it holds."
                        ),
                        (Some(error), false, _) => format!(
                            "the write was rejected and the name is not there: \
                             {error}. The gap remains open."
                        ),
                        (None, true, _) => "re-observation reports the secret present. \
                             Its value is not readable back from GitHub, so airlock \
                             does not claim the value works; the first release is \
                             what answers that."
                            .to_owned(),
                        (None, false, _) => "re-observation does not report the secret; the gap \
                             remains open"
                            .to_owned(),
                    },
                ));
            }
            Err(error) => {
                // A re-observation that did not complete establishes nothing,
                // so the outcome stays inconclusive — unless the write was
                // already known to be rejected, which is a fact this failure
                // does not undo.
                if rejected.is_some() {
                    transcript.observed = ObservedStatus::Fail;
                }
                transcript.steps.push(step(
                    started,
                    false,
                    &format!("post-write re-observation failed: {error:#}"),
                ));
            }
        }
        transcript
    }

    async fn rename_credentials(
        &mut self,
        owner: &str,
        repo: &str,
        rule: &str,
        remediation: &str,
        operation: &SecretOperation,
        value: &SecretValue,
    ) -> Transcript {
        let started = Instant::now();
        let mut transcript = Transcript {
            rule: text::sanitize(rule, NAME_LIMIT),
            remediation: text::sanitize(remediation, NAME_LIMIT),
            proposed_change:
                "rename the selected credential names using the value just supplied by the operator"
                    .to_owned(),
            steps: Vec::new(),
            observed: ObservedStatus::Inconclusive,
            undo: None,
        };
        let target = Target {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        };
        let before = match self.observe(&target).await {
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
            return transcript;
        }
        let SecretOperation::RenameCredentials { variable, secret } = operation else {
            transcript.steps.push(step(
                started,
                false,
                "this operation is not a credential rename; no write was made",
            ));
            return transcript;
        };
        let changed = async {
            if let Some((old_variable, new_variable)) = variable {
                self.writer
                    .rename_variable(owner, repo, &format!("{old_variable}\n{new_variable}"))
                    .await?;
            }
            self.writer
                .rename_secret(owner, repo, &secret.0, &secret.1, value)
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        transcript.steps.push(step(
            started,
            changed.is_ok(),
            &changed.map_or_else(
                |error| format!("the credential rename request failed: {error:#}"),
                |()| "github accepted the credential rename requests".to_owned(),
            ),
        ));
        match self.observe(&target).await {
            Ok(report) => {
                transcript.observed = match report
                    .findings
                    .iter()
                    .find(|finding| finding.rule == rule)
                    .map(|finding| finding.status)
                {
                    Some(airlock_core::findings::Status::Pass) => ObservedStatus::Pass,
                    Some(airlock_core::findings::Status::Fail) => ObservedStatus::Fail,
                    _ => ObservedStatus::Inconclusive,
                };
                transcript.steps.push(step(
                    started,
                    transcript.observed == ObservedStatus::Pass,
                    match transcript.observed {
                        ObservedStatus::Pass => "re-observation reports pass",
                        ObservedStatus::Fail => "re-observation reports fail; the gap remains open",
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
            "declare-capability-property" => {
                let mut parts = argument.lines();
                let property = parts.next().unwrap_or_default();
                let value = parts.next().unwrap_or_default();
                anyhow::ensure!(
                    !property.is_empty() && !value.is_empty() && parts.next().is_none(),
                    "the capability declaration must contain exactly one property and value"
                );
                self.set_capability_property(owner, repo, property, value)
                    .await
            }
            _ => anyhow::bail!("the remediation has no executable input contract"),
        }
    }

    async fn set_capability_property(
        &self,
        owner: &str,
        repo: &str,
        property: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !property.is_empty() && !value.is_empty(),
            "the capability declaration must contain one property and value"
        );
        self.writer
            .set_custom_property(owner, repo, property, value)
            .await
    }

    async fn reobserve_capability_decision(
        &self,
        owner: &str,
        repo: &str,
        property: &str,
        expected: &str,
    ) -> anyhow::Result<(ObservedStatus, String)> {
        let values = self.reader()?.custom_property_values(owner, repo).await?;
        Ok(capability_reobservation(property, expected, &values))
    }

    async fn settle_capability_decision(
        &self,
        owner: &str,
        repo: &str,
        property: &str,
        expected: &str,
    ) -> CapabilitySettlement {
        let changed = self
            .set_capability_property(owner, repo, property, expected)
            .await;
        let observed = self
            .reobserve_capability_decision(owner, repo, property, expected)
            .await;
        CapabilitySettlement { changed, observed }
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

pub(crate) fn valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn capability_reobservation(
    property: &str,
    expected: &str,
    values: &[airlock_core::github::CustomPropertyValue],
) -> (ObservedStatus, String) {
    let observed = values.iter().find(|value| value.property_name == property);
    match observed {
        Some(value) if value.value.as_str() == Some(expected) => (
            ObservedStatus::Pass,
            format!("re-observation reports `{property}` = `{expected}`"),
        ),
        Some(value) => (
            ObservedStatus::Fail,
            format!(
                "re-observation expected `{property}` = `{expected}` but observed {}; the gap remains open",
                value.value.reading()
            ),
        ),
        None => (
            ObservedStatus::Fail,
            format!(
                "re-observation expected `{property}` = `{expected}` but observed absent; the gap remains open"
            ),
        ),
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
            Request::ObserveBootstrap(target) => {
                match runtime.block_on(session.observe_bootstrap(&target)) {
                    Ok(observations) => Response::BootstrapObserved {
                        target,
                        observations,
                    },
                    Err(error) => Response::Failed(text::sanitize(
                        &format!("the publishing bootstrap observation failed: {error:#}"),
                        CAUSE_LIMIT,
                    )),
                }
            }
            Request::PrepareScaffold { owner } => {
                match runtime.block_on(session.scaffold_plan(&owner)) {
                    Ok((plan, _)) => Response::ScaffoldPrepared(plan),
                    Err(error) => Response::Failed(text::sanitize(
                        &format!("the repository scaffold could not be prepared: {error:#}"),
                        CAUSE_LIMIT,
                    )),
                }
            }
            Request::RecoverScaffold(target) => {
                match runtime.block_on(session.writer.repository_absent(&target.owner, &target.repo))
                {
                    Ok(true) => match runtime.block_on(session.scaffold_plan(&target.owner)) {
                        Ok((plan, _)) => Response::ScaffoldPrepared(plan),
                        Err(error) => Response::Failed(text::sanitize(
                            &format!("the repository scaffold could not be recovered: {error:#}"),
                            CAUSE_LIMIT,
                        )),
                    },
                    Ok(false) => match runtime.block_on(session.observe(&target)) {
                        Ok(report) => Response::Scaffolded {
                            target,
                            report: Box::new(report),
                            warnings: vec![
                                "the grant lapsed during creation; re-observation established that the repository exists"
                                    .to_owned(),
                            ],
                        },
                        Err(error) => Response::Failed(text::sanitize(
                            &format!("the created repository could not be re-observed: {error:#}"),
                            CAUSE_LIMIT,
                        )),
                    },
                    Err(error) => Response::Failed(text::sanitize(
                        &format!("repository-creation recovery could not observe the target: {error:#}"),
                        CAUSE_LIMIT,
                    )),
                }
            }
            Request::Scaffold(request) => {
                let target = Target {
                    owner: request.owner.clone(),
                    repo: request.name.clone(),
                };
                match runtime.block_on(session.scaffold(&request)) {
                    Ok((report, warnings)) => Response::Scaffolded {
                        target,
                        report: Box::new(report),
                        warnings: warnings
                            .into_iter()
                            .map(|warning| text::sanitize(&warning, CAUSE_LIMIT))
                            .collect(),
                    },
                    Err(error) => Response::Failed(text::sanitize(
                        &format!("the repository scaffold failed: {error:#}"),
                        CAUSE_LIMIT,
                    )),
                }
            }
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
            Request::ApplyWithSecret {
                target,
                rule,
                remediation,
                operation,
                value,
            } => {
                let transcript = runtime.block_on(session.apply_with_secret(
                    &target.owner,
                    &target.repo,
                    &rule,
                    &remediation,
                    &operation,
                    &value,
                ));
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

async fn accepted(
    response: reqwest::Response,
    endpoint: &str,
) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        let status = response.status().as_u16();
        let permissions = response
            .headers()
            .get_all("x-accepted-github-permissions")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(text::drawable)
            .collect::<Vec<_>>()
            .join(" | ");
        let permission_hint = if permissions.is_empty() {
            String::new()
        } else {
            format!(" [endpoint accepts: {permissions}]")
        };
        let message = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| body.get("message")?.as_str().map(ToOwned::to_owned))
            .map(|message| format!(": {}", text::drawable(&message)))
            .unwrap_or_default();
        anyhow::bail!("{endpoint} returned HTTP {status}{permission_hint}{message}")
    }
}

fn segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_post_write_property_reports_the_observed_discrepancy() {
        let (status, detail) = capability_reobservation("release", "true", &[]);
        assert_eq!(status, ObservedStatus::Fail);
        assert_eq!(
            detail,
            "re-observation expected `release` = `true` but observed absent; the gap remains open"
        );
    }

    #[test]
    fn a_different_post_write_property_reports_both_values() {
        let values = vec![airlock_core::github::CustomPropertyValue {
            property_name: "release".to_owned(),
            value: airlock_core::github::CustomPropertyValueKind::String("false".to_owned()),
        }];
        let (status, detail) = capability_reobservation("release", "true", &values);
        assert_eq!(status, ObservedStatus::Fail);
        assert_eq!(
            detail,
            "re-observation expected `release` = `true` but observed `false`; the gap remains open"
        );
    }
    use tokio::net::TcpListener;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn initial_commit_uses_blobs_one_tree_one_parentless_commit_and_one_ref() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-account/sample-repository/git/blobs"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"sha": "blob"})),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-account/sample-repository/git/trees"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"sha": "tree"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-account/sample-repository/git/commits"))
            .and(body_json(serde_json::json!({
                "message": "chore: scaffold repository",
                "tree": "tree",
                "parents": []
            })))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"sha": "commit"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-account/sample-repository/git/refs"))
            .and(body_json(
                serde_json::json!({"ref": "refs/heads/main", "sha": "commit"}),
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        let client = WriteClient {
            http: reqwest::Client::new(),
            token: "fixture-token".to_owned(),
            base_url: server.uri(),
        };
        let sha = client
            .create_initial_commit(
                "generic-account",
                "sample-repository",
                &[
                    airlock_core::alignment::ScaffoldFile {
                        path: "LICENSE".to_owned(),
                        contents: b"license".to_vec(),
                    },
                    airlock_core::alignment::ScaffoldFile {
                        path: ".editorconfig".to_owned(),
                        contents: b"root = true\n".to_vec(),
                    },
                ],
            )
            .await
            .expect("initial commit");
        assert_eq!(sha, "commit");
    }

    #[test]
    fn secret_entry_treats_paste_as_value_input_and_consumes_once() {
        let mut entry = SecretEntry::default();
        entry.push('t');
        let mut pasted = "opaque-input-7391".to_owned();
        entry.paste(&mut pasted);
        assert!(
            pasted.is_empty(),
            "the paste event allocation was not cleared"
        );
        entry.push('x');
        entry.backspace();
        let value = entry.take().expect("non-empty entry is consumed");
        assert_eq!(value.expose(), b"topaque-input-7391");
        assert!(entry.take().is_none(), "the buffer was not consumed");
    }

    #[test]
    fn secret_entry_growth_preserves_single_use_input() {
        let mut entry = SecretEntry::default();
        let plaintext = "x".repeat(INITIAL_SECRET_CAPACITY * 3);
        let mut pasted = plaintext.clone();

        entry.paste(&mut pasted);

        assert!(pasted.is_empty());
        let value = entry.take().expect("the grown entry is consumed");
        assert_eq!(value.expose(), plaintext.as_bytes());
    }

    #[test]
    fn shared_secret_controller_reports_holding_and_empty_refusal_without_length() {
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
        let mut entry = SecretEntry::default();
        assert!(matches!(
            entry.handle_terminal_event(Event::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE
            ))),
            SecretInputAction::RefusedEmpty
        ));
        assert!(matches!(
            entry.handle_terminal_event(Event::Key(KeyEvent::new(
                KeyCode::Char('x'),
                KeyModifiers::NONE
            ))),
            SecretInputAction::Changed {
                holding_input: true
            }
        ));
    }

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

    /// The bootstrap's step 2, end to end against a stood-up GitHub.
    ///
    /// Observe, write, observe: the completion the transcript reports is the
    /// re-observed presence of the name, and the plaintext appears in no
    /// request body.
    #[tokio::test]
    async fn the_bootstrap_secret_write_is_observed_before_and_after_and_carries_no_plaintext() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let recipient = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        let mut listings = vec![
            serde_json::json!({"secrets": []}),
            serde_json::json!({"secrets": [
                {"name": "CARGO_REGISTRY_TOKEN", "created_at": "2026-01-02T03:04:05Z"}
            ]}),
        ]
        .into_iter();
        for body in listings.by_ref() {
            Mock::given(method("GET"))
                .and(path(
                    "/repos/generic-owner/sample-repository/actions/secrets",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/public-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "fixture-key",
                "key": encoded_key
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/CARGO_REGISTRY_TOKEN",
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let plaintext = "opaque-registry-token-7391";
        let session = session(&server).await;
        let transcript = session
            .set_repository_secret(
                "generic-owner",
                "sample-repository",
                "publishing-bootstrap",
                "set-publishing-bootstrap-secret",
                "CARGO_REGISTRY_TOKEN",
                &SecretValue(plaintext.to_owned()),
            )
            .await;

        assert_eq!(transcript.observed, ObservedStatus::Pass);
        assert_eq!(transcript.steps.len(), 3);
        assert!(transcript.steps[0]
            .detail
            .contains("immediately before acting"));
        assert!(transcript.steps[2].detail.contains("not readable back"));
        assert!(
            !transcript
                .steps
                .iter()
                .any(|step| step.detail.contains(plaintext)),
            "the transcript carries the value"
        );
        assert!(!transcript.proposed_change.contains(plaintext));
        let requests = server.received_requests().await.unwrap();
        assert!(requests
            .iter()
            .all(|request| !String::from_utf8_lossy(&request.body).contains(plaintext)));
    }

    /// A rejected re-mint never passes on the presence it did not create.
    ///
    /// The dangerous shape: the secret already exists, the operator supplies a
    /// freshly minted token because the old one died, GitHub rejects the write,
    /// and the listing afterwards looks exactly as it did before — the name is
    /// there. Presence cannot answer the question that was actually asked,
    /// which is whether the replacement landed, so the rejection answers it.
    #[tokio::test]
    async fn a_rejected_re_mint_does_not_pass_on_the_name_that_was_already_there() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let recipient = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        // The same listing before and after: the name was there and stays there.
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": [
                    {"name": "CARGO_REGISTRY_TOKEN", "created_at": "2026-01-02T03:04:05Z"}
                ]})),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/public-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "fixture-key",
                "key": encoded_key
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/CARGO_REGISTRY_TOKEN",
            ))
            .respond_with(ResponseTemplate::new(403).set_body_json(
                serde_json::json!({"message": "Resource not accessible by integration"}),
            ))
            .mount(&server)
            .await;

        let session = session(&server).await;
        let transcript = session
            .set_repository_secret(
                "generic-owner",
                "sample-repository",
                "publishing-bootstrap",
                "set-publishing-bootstrap-secret",
                "CARGO_REGISTRY_TOKEN",
                &SecretValue("freshly-minted-opaque-input".to_owned()),
            )
            .await;

        assert_eq!(
            transcript.observed,
            ObservedStatus::Fail,
            "a rejected replacement must not read as success"
        );
        let closing = transcript.steps.last().expect("a closing observation");
        assert!(!closing.succeeded);
        assert!(closing.detail.contains("403"), "{}", closing.detail);
        assert!(
            closing.detail.contains("still the old one"),
            "the operator must be told the dead token is still there: {}",
            closing.detail
        );
    }

    /// A write GitHub accepted whose name is not there afterwards is reported
    /// as still open, because status follows observation and never the request.
    #[tokio::test]
    async fn an_accepted_write_the_re_observation_does_not_see_is_reported_as_failing() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let recipient = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": []})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/public-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "fixture-key",
                "key": encoded_key
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/NPM_TOKEN",
            ))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let session = session(&server).await;
        let transcript = session
            .set_repository_secret(
                "generic-owner",
                "sample-repository",
                "publishing-bootstrap",
                "set-publishing-bootstrap-secret",
                "NPM_TOKEN",
                &SecretValue("opaque-input".to_owned()),
            )
            .await;
        assert_eq!(transcript.observed, ObservedStatus::Fail);
        assert!(transcript
            .steps
            .last()
            .is_some_and(|step| step.detail.contains("remains open")));
    }

    /// A secrets read that fails is not an absence: no write is attempted, and
    /// nothing calls the credential gone.
    #[tokio::test]
    async fn an_unreadable_secret_listing_stops_the_write_rather_than_reading_as_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets",
            ))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let session = session(&server).await;
        let transcript = session
            .set_repository_secret(
                "generic-owner",
                "sample-repository",
                "publishing-bootstrap",
                "set-publishing-bootstrap-secret",
                "NPM_TOKEN",
                &SecretValue("opaque-input".to_owned()),
            )
            .await;
        assert_eq!(transcript.observed, ObservedStatus::Inconclusive);
        assert!(transcript
            .steps
            .last()
            .is_some_and(|step| step.detail.contains("no write was attempted")));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == wiremock::http::Method::GET));
    }

    /// A secret listing is read for names and creation times, and there is no
    /// field on the way back a value could travel in.
    #[tokio::test]
    async fn a_secret_listing_carries_names_and_creation_times_only() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": [
                    {"name": "NPM_TOKEN", "created_at": "2026-01-02T03:04:05Z"},
                    {"name": "UNRELATED"}
                ]})),
            )
            .mount(&server)
            .await;
        let records = writer(&server)
            .secret_records("generic-owner", "sample-repository")
            .await
            .unwrap();
        assert_eq!(records[0].name, "NPM_TOKEN");
        assert_eq!(records[0].created, "2026-01-02T03:04:05Z");
        assert!(records[0].scope.contains("generic-owner/sample-repository"));
        assert_eq!(records[1].created, "not stated by GitHub");
    }

    /// A container package absent under both scopes is absent, and a 404 is an
    /// answer rather than a failure.
    #[tokio::test]
    async fn an_absent_container_package_is_absent_rather_than_undecided() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        assert!(writer(&server)
            .container_package("generic-owner", "sample-package")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_transport_error_on_a_write_is_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        });
        let writer = WriteClient {
            http: reqwest::Client::builder().build().unwrap(),
            token: "ghu_test_only".to_owned(),
            base_url: format!("http://{address}"),
        };

        writer
            .patch_repository(
                "generic-owner",
                "sample-repository",
                &RepositoryPatch {
                    allow_squash_merge: Some(true),
                    ..RepositoryPatch::default()
                },
            )
            .await
            .expect_err("an ambiguous write transport failure must surface");
        assert!(
            server.await.unwrap(),
            "the write was attempted more than once"
        );
    }

    #[tokio::test]
    async fn a_settings_observation_403_names_the_endpoint_and_accepted_permissions() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header(
                        "x-accepted-github-permissions",
                        "organization_administration=write",
                    )
                    .set_body_json(serde_json::json!({
                        "message": "Upgrade to GitHub Team to enable this feature."
                    })),
            )
            .mount(&server)
            .await;

        let error = writer(&server)
            .rulesets("generic-owner")
            .await
            .expect_err("a 403 must surface");
        let error = error.to_string();
        assert!(error.contains("GET /orgs/{org}/rulesets"));
        assert!(
            error.contains("Upgrade to GitHub Team to enable this feature."),
            "the error omitted GitHub's message: {error}"
        );
        assert!(
            error.contains("[endpoint accepts: organization_administration=write]"),
            "the error omitted GitHub's permission hint: {error}"
        );
    }

    #[tokio::test]
    async fn a_settings_observation_403_without_a_hint_still_names_the_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(ResponseTemplate::new(403).set_body_string("access denied"))
            .mount(&server)
            .await;

        let error = writer(&server)
            .rulesets("generic-owner")
            .await
            .expect_err("a 403 must surface")
            .to_string();
        assert!(error.contains("GET /orgs/{org}/rulesets"));
        assert!(!error.contains("endpoint accepts"));
        assert!(!error.contains("access denied"));
    }

    #[tokio::test]
    async fn a_json_error_without_a_message_keeps_the_endpoint_and_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "documentation_url": "https://docs.github.com/rest"
            })))
            .mount(&server)
            .await;

        let error = writer(&server)
            .rulesets("generic-owner")
            .await
            .expect_err("a 403 must surface")
            .to_string();
        assert!(error.contains("GET /orgs/{org}/rulesets returned HTTP 403"));
        assert!(!error.contains("documentation_url"));
    }

    #[tokio::test]
    async fn repeated_permission_headers_are_all_reported_and_made_drawable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(
                ResponseTemplate::new(403)
                    .append_header(
                        "x-accepted-github-permissions",
                        "organization_administration=read",
                    )
                    .append_header(
                        "x-accepted-github-permissions",
                        "organization_administration=\twrite",
                    ),
            )
            .mount(&server)
            .await;

        let error = writer(&server)
            .rulesets("generic-owner")
            .await
            .expect_err("a 403 must surface")
            .to_string();
        assert!(error.contains(
            "[endpoint accepts: organization_administration=read | organization_administration=�write]"
        ));
        assert!(!error.contains('\t'));
    }

    #[tokio::test]
    async fn a_long_github_message_cannot_hide_the_permission_hint_at_the_cause_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/orgs/generic-owner/rulesets"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header(
                        "x-accepted-github-permissions",
                        "organization_administration=write",
                    )
                    .set_body_json(serde_json::json!({
                        "message": "This organization has an IP allow list that restricts access to protected resources. Contact an organization owner to request access before trying this operation again. Additional diagnostic context follows."
                    })),
            )
            .mount(&server)
            .await;

        let error = writer(&server)
            .rulesets("generic-owner")
            .await
            .expect_err("a 403 must surface");
        let consumed = text::sanitize(
            &format!("the repository observation failed: {error:#}"),
            CAUSE_LIMIT,
        );
        assert!(
            consumed.contains("[endpoint accepts: organization_administration=write]"),
            "the cause gate omitted GitHub's permission hint: {consumed}"
        );
        assert!(
            consumed.ends_with('…'),
            "the fixture did not reach the gate"
        );
    }

    #[tokio::test]
    async fn a_settings_write_403_names_the_endpoint_and_accepted_permissions() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/generic-owner/sample-repository/transfer"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-accepted-github-permissions", "administration=write")
                    .set_body_json(serde_json::json!({
                        "message": "Repository transfers are disabled."
                    })),
            )
            .mount(&server)
            .await;

        let error = writer(&server)
            .transfer_repository("generic-owner", "sample-repository", "destination-owner")
            .await
            .expect_err("a 403 must surface")
            .to_string();
        assert!(error.contains("POST /repos/{owner}/{repo}/transfer"));
        assert!(error.contains("Repository transfers are disabled."));
        assert!(error.contains("[endpoint accepts: administration=write]"));
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
    async fn a_capability_decision_targets_one_repository_through_the_org_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/orgs/generic-owner/properties/values"))
            .and(body_json(serde_json::json!({
                "repository_names": ["sample-repository"],
                "properties": [{"property_name": "release", "value": "true"}]
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        writer(&server)
            .set_custom_property("generic-owner", "sample-repository", "release", "true")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_capability_write_error_names_endpoint_message_and_permission_hint() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/orgs/generic-owner/properties/values"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header(
                        "x-accepted-github-permissions",
                        "organization_custom_properties=admin",
                    )
                    .set_body_json(
                        serde_json::json!({"message": "Resource not accessible by integration"}),
                    ),
            )
            .mount(&server)
            .await;

        let error = writer(&server)
            .set_custom_property("generic-owner", "sample-repository", "release", "true")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("PATCH /orgs/{org}/properties/values"));
        assert!(error.contains("Resource not accessible by integration"));
        assert!(error.contains("[endpoint accepts: organization_custom_properties=admin]"));
    }

    #[tokio::test]
    async fn a_repository_secret_rename_uses_the_public_key_flow_without_plaintext() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let recipient = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/public-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "fixture-key",
                "key": encoded_key
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/CURRENT_SECRET",
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/LEGACY_SECRET",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let plaintext = "opaque-input-7391";
        writer(&server)
            .rename_secret(
                "generic-owner",
                "sample-repository",
                "LEGACY_SECRET",
                "CURRENT_SECRET",
                &SecretValue(plaintext.to_owned()),
            )
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let put = requests
            .iter()
            .find(|request| request.method == wiremock::http::Method::PUT)
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(body["key_id"], "fixture-key");
        let encrypted = body["encrypted_value"].as_str().unwrap();
        assert!(!encrypted.contains(plaintext));
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encrypted)
            .unwrap();
        assert_eq!(recipient.unseal(&ciphertext).unwrap(), plaintext.as_bytes());
        assert!(requests
            .iter()
            .all(|request| { !String::from_utf8_lossy(&request.body).contains(plaintext) }));
    }

    #[tokio::test]
    async fn a_secret_public_key_403_names_the_endpoint_and_permission_without_the_value() {
        use base64::Engine as _;
        let server = MockServer::start().await;
        let recipient = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        Mock::given(method("GET"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/public-key",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "fixture-key",
                "key": encoded_key
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/repos/generic-owner/sample-repository/actions/secrets/CURRENT_SECRET",
            ))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-accepted-github-permissions", "secrets=write")
                    .set_body_json(serde_json::json!({"message": "Secret writes are disabled."})),
            )
            .mount(&server)
            .await;
        let plaintext = "opaque-input-7391";
        let error = writer(&server)
            .rename_secret(
                "generic-owner",
                "sample-repository",
                "LEGACY_SECRET",
                "CURRENT_SECRET",
                &SecretValue(plaintext.to_owned()),
            )
            .await
            .expect_err("the permission failure must surface")
            .to_string();
        assert!(error.contains("PUT /repos/{owner}/{repo}/actions/secrets/{name}"));
        assert!(error.contains("[endpoint accepts: secrets=write]"));
        assert!(!error.contains(plaintext));
        let requests = server.received_requests().await.unwrap();
        assert!(requests
            .iter()
            .all(|request| request.method != wiremock::http::Method::DELETE));
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
    async fn same_name_credential_renames_are_refused_before_any_write() {
        let server = MockServer::start().await;
        let writer = writer(&server);

        let variable = writer
            .rename_variable("generic-owner", "sample-repository", "SAME_NAME\nSAME_NAME")
            .await
            .unwrap_err();
        assert!(variable.to_string().contains("two different names"));

        let mut entry = SecretEntry::default();
        entry.push('x');
        let value = entry.take().expect("a supplied value");
        let secret = writer
            .rename_secret(
                "generic-owner",
                "sample-repository",
                "SAME_NAME",
                "SAME_NAME",
                &value,
            )
            .await
            .unwrap_err();
        assert!(secret.to_string().contains("two different names"));
        assert!(server.received_requests().await.unwrap().is_empty());
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
    async fn a_long_remediation_code_reaches_action_lookup_intact() {
        let server = MockServer::start().await;
        let mut before = repository(true);
        before["delete_branch_on_merge"] = serde_json::json!(false);
        Mock::given(method("GET"))
            .and(path("/repos/generic-owner/sample-repository"))
            .respond_with(ResponseTemplate::new(200).set_body_json(before))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/generic-owner/sample-repository"))
            .and(body_json(
                serde_json::json!({"delete_branch_on_merge": true}),
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let transcript = session(&server)
            .await
            .apply(
                "generic-owner",
                "sample-repository",
                "REPO-GIT-06",
                "enable-head-branch-auto-delete",
                None,
            )
            .await;

        assert_eq!(transcript.remediation, "enable-head-branch-auto-delete");
        assert!(transcript
            .steps
            .iter()
            .any(|step| step.detail.contains("accepted")));
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
