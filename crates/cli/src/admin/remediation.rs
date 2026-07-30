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

impl Action {
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
}

/// Repository coordinates, kept out of the rendering layer's credential fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub owner: String,
    pub repo: String,
}

/// Work the terminal loop asks the credential-owning worker to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Observe a repository in full under its owner's default policy.
    Observe(Target),
    /// Apply one freshly re-observed rule.
    Apply {
        target: Target,
        rule: String,
        remediation: String,
    },
    /// Apply a confirmed same-lane group, re-observing per rule.
    ApplyGroup {
        target: Target,
        requests: Vec<(String, String)>,
    },
}

/// Credential-free output from the worker.
#[derive(Debug)]
pub enum Response {
    /// A complete fresh observation.
    Observed { target: Target, report: Box<Report> },
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
            .json(&serde_json::json!({ "new_name": "main" }))
            .send()
            .await?;
        accepted(
            response.status(),
            "POST /repos/{owner}/{repo}/branches/{branch}/rename",
        )
    }
}

impl Drop for WriteClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Debug, Default, Serialize)]
struct RepositoryPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_merge_commit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_squash_merge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_branch_on_merge: Option<bool>,
}

/// The credential-owning remediation session.
///
/// This value belongs to the terminal run loop, never to rendering state.
pub struct Session {
    token: String,
    config: RestClientConfig,
    writer: WriteClient,
    version: String,
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

    /// Apply one rule under the re-observation contract.
    pub async fn apply(
        &self,
        owner: &str,
        repo: &str,
        rule: &str,
        remediation: &str,
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
        };
        let Some(action) = action else {
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
        };

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

        match action.satisfied_by(&before) {
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
                let changed = self.change(owner, repo, action, &before).await;
                transcript.steps.push(step(
                    started,
                    changed.is_ok(),
                    &changed.map_or_else(
                        |error| format!("the change request failed: {error:#}"),
                        |()| "github accepted the change request".to_owned(),
                    ),
                ));
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
            Ok(repository) => match action.satisfied_by(&repository) {
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
        &self,
        owner: &str,
        repo: &str,
        requests: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<Transcript> {
        let mut transcripts = Vec::new();
        for (rule, remediation) in requests {
            transcripts.push(self.apply(owner, repo, rule, remediation).await);
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

fn run(session: Session, requests: Receiver<Request>, responses: &Sender<Response>) {
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
            Request::Apply {
                target,
                rule,
                remediation,
            } => {
                let transcript = runtime.block_on(session.apply(
                    &target.owner,
                    &target.repo,
                    &rule,
                    &remediation,
                ));
                Response::Applied { target, transcript }
            }
            Request::ApplyGroup { target, requests } => {
                let borrowed = requests
                    .iter()
                    .map(|(rule, remediation)| (rule.as_str(), remediation.as_str()));
                let transcripts =
                    runtime.block_on(session.apply_group(&target.owner, &target.repo, borrowed));
                Response::GroupApplied {
                    target,
                    transcripts,
                }
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
        }
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

        let transcript = session(&server)
            .await
            .apply(
                "generic-owner",
                "sample-repository",
                "REPO-GIT-04",
                "disable-merge-commits",
            )
            .await;

        assert_eq!(transcript.observed, ObservedStatus::Pass);
        assert!(transcript
            .steps
            .iter()
            .any(|step| step.detail.contains("no write was made")));
    }
}
