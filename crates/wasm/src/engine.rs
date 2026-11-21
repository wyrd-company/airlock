//! The module's entry points, independent of the target.
//!
//! Each takes the transport it runs on. The WebAssembly exports in
//! [`crate::js`] call them with the host's transport; the native parity run
//! calls them with reqwest's. Both builds therefore run exactly this code,
//! and a difference between their findings is a difference in the engine.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use airlock_core::audit::{self, AuditOptions};
use airlock_core::auth::{self, Admission};
use airlock_core::central::{
    self, AzureCredential, CentralConfig, CentralError, CentralInputs, Endpoints,
};
use airlock_core::central_audit;
use airlock_core::github::{RestClient, RestClientConfig};
use airlock_core::limits::Limits;
use airlock_core::policy::{self, PolicySource};
use airlock_core::render;
use airlock_core::transport::Transport;
use airlock_core::workflow_token::ActionsRun;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

/// The Airlock version the module reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why an entry point stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    /// `inputs`, `refused`, `policy`, `audit`, `central` or `render`.
    pub kind: &'static str,
    /// What a person should know. It carries no credential.
    pub message: String,
    /// For `central`: the step central sign-in stopped at.
    pub step: Option<&'static str>,
    /// For `central`: the HTTP status, when a service answered.
    pub status: Option<u16>,
    /// For `central`: the service's vetted error code.
    pub code: Option<String>,
}

impl EngineError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            step: None,
            status: None,
            code: None,
        }
    }

    fn central(error: &CentralError) -> Self {
        Self {
            kind: "central",
            message: error.to_string(),
            step: Some(error.step.code()),
            status: error.status,
            code: error.code.clone(),
        }
    }
}

/// The shortest value the module accepts as a credential, so that redacting
/// one never rewrites ordinary text.
const MIN_SECRET_LENGTH: usize = 8;

/// What `application/x-www-form-urlencoded` leaves unescaped, beside letters
/// and digits, as central sign-in encodes its form.
const FORM_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'*');

/// The boundary every string leaving the module passes.
///
/// An entry point holds the credentials it was given or minted, and every
/// report, error message and error code it returns is redacted against them.
/// A server, proxy or host that echoes a credential (in a message, a header,
/// a body or a rejection) therefore cannot carry it out, whichever call site
/// let the text through. Each credential is matched as sent, form-encoded and
/// JSON-escaped.
#[derive(Default)]
pub struct Redactor {
    forms: Vec<Zeroizing<String>>,
}

impl Redactor {
    /// A redactor for `secrets`.
    #[must_use]
    pub fn of<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Self {
        let mut redactor = Self::default();
        for secret in secrets {
            redactor.add(secret);
        }
        redactor
    }

    /// Redact `secret` too.
    pub fn add(&mut self, secret: &str) {
        let secret = secret.trim();
        if secret.len() < MIN_SECRET_LENGTH {
            return;
        }
        let encoded = percent_encoding::utf8_percent_encode(secret, FORM_VALUE).to_string();
        let escaped = serde_json::to_string(secret).unwrap_or_default();
        let escaped = escaped.trim_matches('"').to_owned();
        for form in [secret.to_owned(), encoded, escaped] {
            if !self.forms.iter().any(|known| known.as_str() == form) {
                self.forms.push(Zeroizing::new(form));
            }
        }
        // The longest first, so a secret containing another is replaced whole.
        self.forms.sort_by_key(|form| std::cmp::Reverse(form.len()));
    }

    /// `text`, with every known credential replaced by `[redacted]`.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for form in &self.forms {
            if text.contains(form.as_str()) {
                text = text.replace(form.as_str(), "[redacted]");
            }
        }
        text
    }

    /// An entry point's result, redacted.
    fn result<T: Redactable>(&self, result: Result<T, EngineError>) -> Result<T, EngineError> {
        match result {
            Ok(value) => Ok(value.redacted(self)),
            Err(error) => Err(error.redacted(self)),
        }
    }
}

/// What an entry point returns, as the redactor sees it.
trait Redactable {
    fn redacted(self, redactor: &Redactor) -> Self;
}

impl Redactable for String {
    fn redacted(self, redactor: &Redactor) -> Self {
        redactor.redact(&self)
    }
}

impl Redactable for () {
    fn redacted(self, _: &Redactor) -> Self {}
}

impl Redactable for EngineError {
    fn redacted(self, redactor: &Redactor) -> Self {
        Self {
            message: redactor.redact(&self.message),
            code: self.code.map(|code| redactor.redact(&code)),
            ..self
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EngineError {}

/// What [`audit`] audits, with what.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRequest {
    /// The credential, verified before any other request.
    pub token: String,
    /// The repository's owner.
    pub owner: String,
    /// The repository's name.
    pub repo: String,
    /// The policy, as `owner/repo:path[@ref]`. Absent: the owner's default.
    #[serde(default)]
    pub policy: Option<String>,
    /// The GitHub REST API root. Absent: `https://api.github.com`.
    #[serde(default)]
    pub github_api: Option<String>,
}

impl Drop for AuditRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl AuditRequest {
    /// Refuse, before it is sent anywhere, a token that is not shaped like a
    /// GitHub token. Only such a token is redacted wherever it is echoed:
    /// one holding `"`, `\` or `%` has escaped forms the redactor would not
    /// match.
    fn check_token(&self) -> Result<(), EngineError> {
        if auth::has_token_shape(&self.token) {
            Ok(())
        } else {
            Err(EngineError::new(
                "inputs",
                "the token is not a GitHub token: it must be 8 to 4096 letters, digits and `_`",
            ))
        }
    }

    /// Parse a request from its JSON text.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error that does not repeat the text.
    pub fn parse(json: &str) -> Result<Self, EngineError> {
        serde_json::from_str(json).map_err(|error| {
            // serde's message can quote a value, and the value may be the
            // token, so only the position is kept.
            EngineError::new(
                "inputs",
                format!(
                    "the audit request is not valid (line {}, column {})",
                    error.line(),
                    error.column()
                ),
            )
        })
    }
}

fn client_config(limits: Limits, github_api: Option<&str>) -> RestClientConfig {
    let mut config = RestClientConfig::from_limits(limits);
    if let Some(base) = github_api {
        base.trim_end_matches('/').clone_into(&mut config.base_url);
    }
    config
}

fn policy_source(policy: Option<&str>, owner: &str) -> Result<PolicySource, EngineError> {
    match policy {
        Some(value) => match PolicySource::parse(value) {
            // The module reads no file system: a policy is read through the
            // API or not at all.
            Ok(PolicySource::Local(_)) => Err(EngineError::new(
                "inputs",
                "the module reads the policy through the GitHub API, so it must be named as \
                 `owner/repo:path[@ref]`, not as a local path",
            )),
            Ok(source) => Ok(source),
            Err(error) => Err(EngineError::new(
                "inputs",
                format!("cannot read the policy: {error}"),
            )),
        },
        None => Ok(PolicySource::default_for_owner(owner)),
    }
}

fn options(limits: Limits) -> AuditOptions {
    AuditOptions {
        reference: None,
        limits,
        version: VERSION.to_owned(),
        working_tree: None,
    }
}

/// Audit one repository and return its findings document, as
/// `airlock audit --format json` prints it.
///
/// The token is verified first, as on every surface: a token whose grant
/// cannot be enumerated, or that can write, is refused before the audit
/// reads anything.
///
/// # Errors
///
/// Returns an [`EngineError`] when the token is refused, the policy cannot be
/// resolved, or the repository cannot be read.
pub async fn audit(
    transport: Arc<dyn Transport>,
    request: &AuditRequest,
) -> Result<String, EngineError> {
    let redactor = Redactor::of([request.token.as_str()]);
    redactor.result(audit_unredacted(transport, request).await)
}

async fn audit_unredacted(
    transport: Arc<dyn Transport>,
    request: &AuditRequest,
) -> Result<String, EngineError> {
    request.check_token()?;
    let limits = Limits::default();
    let client = RestClient::with_transport(
        request.token.as_str(),
        client_config(limits, request.github_api.as_deref()),
        transport,
    );
    let grant = auth::verify_for(&request.token, &client, Admission::Standard)
        .await
        .map_err(|refusal| {
            EngineError::new("refused", format!("the credential was refused: {refusal}"))
        })?;
    let source = policy_source(request.policy.as_deref(), &request.owner)?;
    let policy = policy::resolve(&client, &source, &limits)
        .await
        .map_err(|error| {
            EngineError::new(
                "policy",
                format!("cannot resolve the policy at {}: {error}", source.label()),
            )
        })?;
    let report = audit::run(
        &client,
        &request.owner,
        &request.repo,
        &policy,
        &options(limits),
        Some(&grant),
    )
    .await
    .map_err(|error| {
        EngineError::new(
            "audit",
            format!("cannot audit {}/{}: {error}", request.owner, request.repo),
        )
    })?;
    serde_json::to_string_pretty(&report)
        .map_err(|error| EngineError::new("render", error.to_string()))
}

/// What [`repository_audit`] audits: repository mode, as the JavaScript
/// action runs it inside GitHub Actions.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryRequest {
    /// The credential: the run's own `GITHUB_TOKEN`, or another token
    /// Airlock can verify as read-only.
    pub token: String,
    /// The run's own token, as `github.token` gives it. Never sent: an
    /// installation token is admitted only when it is this one.
    #[serde(default)]
    pub run_token: Option<String>,
    /// `owner/repo` to audit; repository mode audits the run's own only.
    pub repository: String,
    /// The commit, branch or tag to audit. Absent: the default branch.
    #[serde(default)]
    pub reference: Option<String>,
    /// The policy, as `owner/repo:path[@ref]`. Absent: the owner's default.
    #[serde(default)]
    pub policy: Option<String>,
    /// `json`, the default, or `text`.
    #[serde(default)]
    pub format: Option<String>,
    /// The variables that describe the run (see
    /// [`airlock_core::workflow_token::ACTIONS_VARIABLES`]), as the runner
    /// set them. Others are ignored.
    #[serde(default)]
    pub actions: BTreeMap<String, String>,
    /// The GitHub REST API root. Absent: `https://api.github.com`.
    #[serde(default)]
    pub github_api: Option<String>,
}

impl Drop for RepositoryRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        if let Some(run_token) = &mut self.run_token {
            run_token.zeroize();
        }
    }
}

impl RepositoryRequest {
    /// Parse a request from its JSON text.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error that does not repeat the text.
    pub fn parse(json: &str) -> Result<Self, EngineError> {
        serde_json::from_str(json).map_err(|error| {
            EngineError::new(
                "inputs",
                format!(
                    "the repository audit request is not valid (line {}, column {})",
                    error.line(),
                    error.column()
                ),
            )
        })
    }
}

/// A repository-mode audit's result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryAudit {
    /// `conformant`, `nonconformant` or `incomplete`, as the report states.
    pub outcome: &'static str,
    /// Whether the audit completed without a run error.
    pub complete: bool,
    /// The findings document, in the requested format.
    pub document: String,
}

impl Redactable for RepositoryAudit {
    fn redacted(self, redactor: &Redactor) -> Self {
        Self {
            document: redactor.redact(&self.document),
            ..self
        }
    }
}

/// Audit the run's own repository in repository mode, as the JavaScript
/// action does, and return the outcome with the findings document.
///
/// Repository mode is settled first: outside GitHub Actions, or for a run
/// the variables do not describe, nothing is read. The token is then
/// admitted as the command line's repository mode admits it. The run's
/// `GITHUB_TOKEN` is accepted only when it is the run's own token, for the
/// run's own repository, and every permission the job declares in the
/// workflow file at `GITHUB_WORKFLOW_SHA` is `read`.
///
/// # Errors
///
/// Returns an [`EngineError`] when the run or the token is refused, the
/// policy cannot be resolved, or the repository cannot be read.
pub async fn repository_audit(
    transport: Arc<dyn Transport>,
    request: &RepositoryRequest,
) -> Result<RepositoryAudit, EngineError> {
    let mut redactor = Redactor::of([request.token.as_str()]);
    if let Some(run_token) = &request.run_token {
        redactor.add(run_token);
    }
    redactor.result(repository_audit_unredacted(transport, request).await)
}

async fn repository_audit_unredacted(
    transport: Arc<dyn Transport>,
    request: &RepositoryRequest,
) -> Result<RepositoryAudit, EngineError> {
    let run =
        ActionsRun::from_lookup(|name| request.actions.get(name).cloned()).map_err(|refusal| {
            EngineError::new("refused", format!("repository mode was refused: {refusal}"))
        })?;
    let text = match request.format.as_deref() {
        None | Some("json") => false,
        Some("text") => true,
        Some(_) => {
            return Err(EngineError::new(
                "inputs",
                "format must be `json` or `text`",
            ))
        }
    };
    if !auth::has_token_shape(&request.token) {
        return Err(EngineError::new(
            "inputs",
            "the token is not a GitHub token: it must be 8 to 4096 letters, digits and `_`",
        ));
    }
    let Some((owner, repo)) = request
        .repository
        .split_once('/')
        .filter(|(owner, repo)| !owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
    else {
        return Err(EngineError::new(
            "inputs",
            "the repository must be named as `owner/repo`",
        ));
    };
    let limits = Limits::default();
    let client = RestClient::with_transport(
        request.token.as_str(),
        client_config(limits, request.github_api.as_deref()),
        transport,
    );
    let admission = Admission::Repository {
        run: &run,
        owner,
        repo,
        run_token: request.run_token.as_deref(),
    };
    let grant = auth::verify_for(&request.token, &client, admission)
        .await
        .map_err(|refusal| {
            EngineError::new("refused", format!("the credential was refused: {refusal}"))
        })?;
    let source = policy_source(request.policy.as_deref(), owner)?;
    let policy = policy::resolve(&client, &source, &limits)
        .await
        .map_err(|error| {
            EngineError::new(
                "policy",
                format!("cannot resolve the policy at {}: {error}", source.label()),
            )
        })?;
    let options = AuditOptions {
        reference: request.reference.clone(),
        ..options(limits)
    };
    let report = audit::run(&client, owner, repo, &policy, &options, Some(&grant))
        .await
        .map_err(|error| {
            EngineError::new("audit", format!("cannot audit {owner}/{repo}: {error}"))
        })?;
    let document = if text {
        render::report_text(&report)
    } else {
        serde_json::to_string_pretty(&report)
            .map_err(|error| EngineError::new("render", error.to_string()))?
    };
    Ok(RepositoryAudit {
        outcome: report.outcome.code(),
        complete: report.complete,
        document,
    })
}

/// How [`sign_in`] signs in as Airlock Safe.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CentralRequest {
    /// The account whose installation Safe signs in to.
    pub owner: String,
    /// `AIRLOCK_SAFE_APP_ID`.
    pub app_id: String,
    /// The Key Vault key holding Safe's private key.
    pub key_name: String,
    /// `installation-repositories`: `<owner>/*`.
    pub installation_repositories: String,
    /// The vault's `https://` origin.
    pub vault_url: String,
    /// The Entra ID tenant.
    pub azure_tenant_id: String,
    /// The host's Entra application.
    pub azure_client_id: String,
    /// The host's Entra credential.
    pub credential: CredentialRequest,
    /// The GitHub REST API root. Absent: `https://api.github.com`.
    #[serde(default)]
    pub github_api: Option<String>,
    /// Entra ID's sign-in host. Absent: `https://login.microsoftonline.com`.
    #[serde(default)]
    pub azure_login: Option<String>,
}

/// The host's Entra credential, as it reaches the module.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRequest {
    /// `client-secret`, the only kind the module takes
    /// (wyrd-company/.github#26).
    pub kind: String,
    /// The secret.
    pub value: String,
}

impl Drop for CredentialRequest {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl CentralRequest {
    /// Parse a request from its JSON text.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error that does not repeat the text.
    pub fn parse(json: &str) -> Result<Self, EngineError> {
        serde_json::from_str(json).map_err(|error| {
            EngineError::new(
                "inputs",
                format!(
                    "the central request is not valid (line {}, column {})",
                    error.line(),
                    error.column()
                ),
            )
        })
    }
}

/// A signed-in central run.
///
/// Holds Safe's installation token in memory only, and overwrites it when
/// dropped. Every output passes through the session's redaction.
pub struct Session {
    inner: central::CentralSession,
    /// Safe's installation token, as every output is redacted against it.
    redactor: Redactor,
    owner: String,
    client_config: RestClientConfig,
}

/// What the session's credential is, as verified. No token is in it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionGrant {
    /// The App's slug.
    pub app_slug: &'static str,
    /// The App's id.
    pub app_id: u64,
    /// The owner's installation.
    pub installation_id: u64,
    /// The minted token's permissions, each `name=read`.
    pub permissions: Vec<String>,
    /// When the token expires, as GitHub stated it.
    pub expires_at: Option<String>,
}

/// Sign in as Airlock Safe through Key Vault, with the host's Entra
/// credential, and mint a read-only installation token.
///
/// # Errors
///
/// Returns a `central` [`EngineError`] naming the step that refused, or an
/// `inputs` one for a credential kind the module does not take.
pub async fn sign_in(
    transport: Arc<dyn Transport>,
    request: &CentralRequest,
) -> Result<Session, EngineError> {
    let redactor = Redactor::of([request.credential.value.as_str()]);
    match sign_in_unredacted(transport, request).await {
        Ok(session) => Ok(session),
        Err(error) => Err(error.redacted(&redactor)),
    }
}

async fn sign_in_unredacted(
    transport: Arc<dyn Transport>,
    request: &CentralRequest,
) -> Result<Session, EngineError> {
    if request.credential.value.trim().len() < MIN_SECRET_LENGTH {
        return Err(EngineError::new(
            "inputs",
            "the Entra ID credential is too short to be one",
        ));
    }
    let config = CentralConfig::parse(
        &request.owner,
        &CentralInputs {
            app_id: request.app_id.clone(),
            key_name: request.key_name.clone(),
            installation_repositories: request.installation_repositories.clone(),
            vault_url: request.vault_url.clone(),
            azure_tenant_id: request.azure_tenant_id.clone(),
            azure_client_id: request.azure_client_id.clone(),
        },
    )
    .map_err(|error| EngineError::central(&error))?;
    // The module has no GitHub Actions job to ask for an OpenID Connect
    // token; a host proves itself with its own credential.
    if request.credential.kind != "client-secret" {
        return Err(EngineError::new(
            "inputs",
            "the credential kind must be `client-secret`",
        ));
    }
    let credential = AzureCredential::client_secret(request.credential.value.as_str())
        .map_err(|error| EngineError::central(&error))?;

    let defaults = Endpoints::default();
    let endpoints = Endpoints {
        github_api: request
            .github_api
            .as_deref()
            .map_or(defaults.github_api, |base| {
                base.trim_end_matches('/').to_owned()
            }),
        azure_login: request
            .azure_login
            .as_deref()
            .map_or(defaults.azure_login, |base| {
                base.trim_end_matches('/').to_owned()
            }),
    };
    let limits = Limits::default();
    let inner = central::sign_in(&config, &credential, &endpoints, limits, transport)
        .await
        .map_err(|error| EngineError::central(&error))?;
    let redactor = Redactor::of([inner.token()]);
    Ok(Session {
        inner,
        redactor,
        owner: config.owner,
        client_config: client_config(limits, Some(&endpoints.github_api)),
    })
}

impl Session {
    /// What the session's credential is.
    #[must_use]
    pub fn grant(&self) -> SessionGrant {
        SessionGrant {
            app_slug: auth::AIRLOCK_SAFE_APP_SLUG,
            app_id: auth::AIRLOCK_SAFE_APP_ID,
            installation_id: self.inner.installation_id,
            permissions: self
                .inner
                .grant
                .installations
                .first()
                .map(|installation| installation.permissions.clone())
                .unwrap_or_default(),
            expires_at: self.inner.expires_at.clone(),
        }
    }

    fn redacted<T: Redactable>(&self, result: Result<T, EngineError>) -> Result<T, EngineError> {
        // The module's boundary is the one guard here: it holds the same
        // token the core's own session redacts.
        self.redactor.result(result)
    }

    /// Audit one repository the installation reaches, with Safe's grant.
    ///
    /// # Errors
    ///
    /// Returns a `policy` or `audit` [`EngineError`].
    pub async fn audit_repository(
        &self,
        repo: &str,
        policy: Option<&str>,
    ) -> Result<String, EngineError> {
        let result = async {
            let limits = Limits::default();
            let client = RestClient::with_transport(
                self.inner.token(),
                self.client_config.clone().withholding_response_text(),
                self.inner.transport(),
            );
            let source = policy_source(policy, &self.owner)?;
            let policy = policy::resolve(&client, &source, &limits)
                .await
                .map_err(|error| {
                    EngineError::new(
                        "policy",
                        format!("cannot resolve the policy at {}: {error}", source.label()),
                    )
                })?;
            let report = audit::run(
                &client,
                &self.owner,
                repo,
                &policy,
                &options(limits),
                Some(&self.inner.grant),
            )
            .await
            .map_err(|error| {
                EngineError::new(
                    "audit",
                    format!("cannot audit {}/{repo}: {error}", self.owner),
                )
            })?;
            serde_json::to_string_pretty(&report)
                .map_err(|error| EngineError::new("render", error.to_string()))
        }
        .await;
        self.redacted(result)
    }

    /// Audit every repository the installation reaches, as one central
    /// report.
    ///
    /// # Errors
    ///
    /// Returns an `inputs`, `policy` or `audit` [`EngineError`].
    pub async fn audit_installation(&self, policy: Option<&str>) -> Result<String, EngineError> {
        let result = async {
            let source = match policy {
                Some(value) => Some(policy_source(Some(value), &self.owner)?),
                None => None,
            };
            let report = central_audit::run(
                &self.inner,
                &self.owner,
                &self.client_config,
                source,
                &options(Limits::default()),
            )
            .await
            .map_err(|error| {
                EngineError::new(
                    "audit",
                    format!("cannot audit the repositories of {}: {error}", self.owner),
                )
            })?;
            serde_json::to_string_pretty(&report)
                .map_err(|error| EngineError::new("render", error.to_string()))
        }
        .await;
        self.redacted(result)
    }

    /// Revoke the installation token.
    ///
    /// # Errors
    ///
    /// Returns a `central` [`EngineError`] when GitHub does not confirm it.
    pub async fn revoke(&self) -> Result<(), EngineError> {
        let result = self
            .inner
            .revoke()
            .await
            .map_err(|error| EngineError::central(&error));
        self.redacted(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_is_redacted_as_sent_form_encoded_and_json_escaped() {
        let secret = "s3cr~et.value\"with/quote";
        let redactor = Redactor::of([secret]);
        let encoded = percent_encoding::utf8_percent_encode(secret, FORM_VALUE).to_string();
        let escaped = serde_json::to_string(secret).unwrap();
        let text = format!("raw {secret} form {encoded} json {escaped}");
        let redacted = redactor.redact(&text);
        assert!(!redacted.contains(secret), "{redacted}");
        assert!(!redacted.contains(&encoded), "{redacted}");
        assert!(!redacted.contains(escaped.trim_matches('"')), "{redacted}");
        assert_eq!(redacted.matches("[redacted]").count(), 3, "{redacted}");
    }

    #[test]
    fn a_value_too_short_to_be_a_credential_rewrites_nothing() {
        let redactor = Redactor::of(["abc", "", "       "]);
        assert_eq!(redactor.redact("abc abc"), "abc abc");
    }

    #[test]
    fn an_error_is_redacted_in_its_message_and_its_code() {
        let token = "ghu_SYNTHETICtoken0123456789abcdef";
        let mut error = EngineError::new("audit", format!("echoed {token}"));
        error.code = Some(token.to_owned());
        let error = error.redacted(&Redactor::of([token]));
        assert!(!error.message.contains(token));
        assert_eq!(error.code.as_deref(), Some("[redacted]"));
    }

    #[test]
    fn a_token_too_short_to_redact_is_refused_before_any_request() {
        for token in [
            "ghu_x",
            "ghu_has space",
            "",
            "ghu_SYN\"THE\\TICtoken0123456789",
            "ghu_per%2fcent0123456789",
            "ghu_dash-token0123456789",
        ] {
            let request = AuditRequest::parse(
                &serde_json::json!({ "token": token, "owner": "o", "repo": "r" }).to_string(),
            )
            .unwrap();
            assert_eq!(request.check_token().unwrap_err().kind, "inputs", "{token}");
        }
        let request = AuditRequest::parse(
            &serde_json::json!({ "token": "ghu_SYNTHETICtoken0123456789", "owner": "o", "repo": "r" })
                .to_string(),
        )
        .unwrap();
        assert!(request.check_token().is_ok());
    }
}
