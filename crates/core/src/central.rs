//! Central mode: signing in as Airlock Safe through Azure Key Vault.
//!
//! The organization's audit repository runs Airlock with no stored token.
//! Its job holds only `id-token: write`. Airlock exchanges the job's OpenID
//! Connect token at Microsoft Entra ID for a Key Vault access token. Key Vault
//! signs Airlock Safe's JSON Web Token with a key that never leaves the vault,
//! in the sequence `release-authority-token` describes. Airlock then checks
//! the App and its installation before it mints its own installation token.
//!
//! Every check is a refusal, made before the next step:
//!
//! - `GET /app` must name the App Airlock is built with, by id and slug, with
//!   every permission `read`;
//! - the owner's installation must reach every repository
//!   (`repository_selection` `all`) and pass the `installation-repositories`
//!   rule with the configured value, which is `<owner>/*`;
//! - the minting response must list only `read` permissions.
//!
//! Nothing here writes to a repository or an organization. The one request
//! that is not a read mints the token, and the one other request revokes it
//! when the run ends.
//!
//! No message carries a token, an assertion, a signature or a request body.
//! Errors keep the step, the HTTP status and the service's error code.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::auth::{InstallationGrant, TokenKind, VerifiedGrant};
use crate::auth::{AIRLOCK_SAFE_APP_ID, AIRLOCK_SAFE_APP_SLUG};
use crate::limits::Limits;
use crate::transport::{self, FailureKind, Method, Transport};

/// Microsoft Entra ID's sign-in host.
pub const AZURE_LOGIN_BASE: &str = "https://login.microsoftonline.com";

/// The audience Entra ID accepts a GitHub OpenID Connect token for.
const AZURE_AUDIENCE: &str = "api://AzureADTokenExchange";

/// The scope of a Key Vault data-plane access token.
const KEY_VAULT_SCOPE: &str = "https://vault.azure.net/.default";

/// The Key Vault REST API version the sign operation is called with.
const KEY_VAULT_API_VERSION: &str = "7.4";

/// What `application/x-www-form-urlencoded` leaves unescaped, beside letters
/// and digits.
const FORM_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'*');

/// The step a central sign-in stopped at.
///
/// Named as the token action names its steps where the step is the same, so
/// one failure reads the same in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The Action's inputs, before any request.
    Inputs,
    /// The job's OpenID Connect token and its exchange at Entra ID.
    AzureSignIn,
    /// Key Vault's signature over the App's JSON Web Token.
    KeyVaultSign,
    /// `GET /app` and the App it names.
    AppIdentity,
    /// The owner's installation of the App.
    InstallationLookup,
    /// The installation's repository selection and reach.
    InstallationScope,
    /// Minting the installation token, and the permissions it lists.
    TokenRequest,
    /// Revoking the installation token at the end of the run.
    TokenRevoke,
}

impl Step {
    /// The step's stable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Inputs => "inputs",
            Self::AzureSignIn => "azure-sign-in",
            Self::KeyVaultSign => "key-vault-sign",
            Self::AppIdentity => "app-identity",
            Self::InstallationLookup => "installation-lookup",
            Self::InstallationScope => "installation-scope",
            Self::TokenRequest => "token-request",
            Self::TokenRevoke => "token-revoke",
        }
    }
}

/// Why central mode stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralError {
    /// The step that failed.
    pub step: Step,
    /// What a person should know, with no credential in it.
    pub detail: String,
    /// The HTTP status, when a service answered.
    pub status: Option<u16>,
    /// The service's error code, when it gave one.
    pub code: Option<String>,
}

impl CentralError {
    fn new(step: Step, detail: impl Into<String>) -> Self {
        Self {
            step,
            detail: detail.into(),
            status: None,
            code: None,
        }
    }
}

impl fmt::Display for CentralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.step.code(), self.detail)?;
        match (self.status, &self.code) {
            (Some(status), Some(code)) => write!(formatter, " (http {status}, {code})"),
            (Some(status), None) => write!(formatter, " (http {status})"),
            (None, Some(code)) => write!(formatter, " ({code})"),
            (None, None) => Ok(()),
        }
    }
}

impl std::error::Error for CentralError {}

/// The central inputs, as the Action passes them from the audit
/// repository's `airlock-safe` environment variables.
#[derive(Debug, Clone, Default)]
pub struct CentralInputs {
    /// `AIRLOCK_SAFE_APP_ID`.
    pub app_id: String,
    /// `AIRLOCK_SAFE_KEY_NAME`.
    pub key_name: String,
    /// `AIRLOCK_SAFE_INSTALLED_ON`.
    pub installation_repositories: String,
    /// `AZURE_KEY_VAULT_URL`.
    pub vault_url: String,
    /// `AZURE_TENANT_ID`.
    pub azure_tenant_id: String,
    /// `AZURE_CLIENT_ID`.
    pub azure_client_id: String,
}

/// Where an installation may reach, as `installation-repositories` states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledOn {
    /// `<owner>/*`: every repository of the owner.
    Owner(String),
    /// Named repositories, each `<owner>/<repository>`.
    Repositories(Vec<String>),
}

impl InstalledOn {
    /// Parse the value as the token action reads `installation-repositories`.
    ///
    /// Entries are separated by commas or newlines. `*` is allowed only as
    /// the single entry `<owner>/*`. An empty value is absent, and central
    /// mode must check, so absent is a refusal.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error for an absent value, a malformed entry, or a
    /// `*` that is not the single `<owner>/*` entry.
    pub fn parse(value: &str) -> Result<Self, CentralError> {
        let entries: Vec<&str> = value
            .split([',', '\n'])
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        if entries.is_empty() {
            return Err(CentralError::new(
                Step::Inputs,
                "`installation-repositories` is empty. Central mode checks the installation \
                 against it, so it must be `<owner>/*`.",
            ));
        }
        let malformed = |entry: &str| {
            CentralError::new(
                Step::Inputs,
                format!(
                    "`installation-repositories` entry `{entry}` is not `<owner>/<repository>`, \
                     and `*` is allowed only as the single entry `<owner>/*`."
                ),
            )
        };
        let mut repositories = Vec::new();
        for entry in &entries {
            let Some((owner, name)) = entry.split_once('/') else {
                return Err(malformed(entry));
            };
            if !is_github_name(owner) {
                return Err(malformed(entry));
            }
            if name == "*" {
                if entries.len() != 1 {
                    return Err(malformed(entry));
                }
                return Ok(Self::Owner(owner.to_owned()));
            }
            if !is_github_name(name) {
                return Err(malformed(entry));
            }
            repositories.push((*entry).to_owned());
        }
        Ok(Self::Repositories(repositories))
    }
}

fn is_github_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The validated central configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralConfig {
    /// The account whose installation Airlock Safe signs in to, and whose
    /// repositories are audited.
    pub owner: String,
    /// The App id, which is Airlock Safe's.
    pub app_id: u64,
    /// The Key Vault key that holds the App's private key.
    pub key_name: String,
    /// `installation-repositories`.
    pub installed_on: InstalledOn,
    /// The vault's origin, with no trailing slash.
    pub vault_url: String,
    /// The Entra ID tenant.
    pub azure_tenant_id: String,
    /// The client id of the identity whose federated credential trusts the
    /// job.
    pub azure_client_id: String,
}

impl CentralConfig {
    /// Validate the inputs for an audit of `owner`.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error, before any request, for an App other than
    /// Airlock Safe, a key name Key Vault would not accept, a vault address
    /// that is not an `https://` origin, an Azure id that is not one, or an
    /// `installation-repositories` value that does not parse.
    pub fn parse(owner: &str, inputs: &CentralInputs) -> Result<Self, CentralError> {
        if !is_github_name(owner) {
            return Err(CentralError::new(
                Step::Inputs,
                format!("`{owner}` is not an account name."),
            ));
        }
        let app_id = inputs.app_id.trim();
        if app_id.parse::<u64>().ok() != Some(AIRLOCK_SAFE_APP_ID) {
            return Err(CentralError::new(
                Step::Inputs,
                format!(
                    "`app-id` is `{app_id}`. Central mode signs only as \
                     `{AIRLOCK_SAFE_APP_SLUG}` (app id {AIRLOCK_SAFE_APP_ID}), the App it is \
                     built with."
                ),
            ));
        }

        let key_name = inputs.key_name.trim();
        let key_name_valid = !key_name.is_empty()
            && key_name.len() <= 127
            && key_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !key_name_valid {
            return Err(CentralError::new(
                Step::Inputs,
                "`key-name` must be one to 127 letters, digits and dashes.",
            ));
        }

        let vault_url = vault_origin(inputs.vault_url.trim())?;

        let azure_id = |name: &str, value: &str| {
            let value = value.trim();
            let valid = !value.is_empty()
                && value.len() <= 256
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
            if valid {
                Ok(value.to_owned())
            } else {
                Err(CentralError::new(
                    Step::Inputs,
                    format!("`{name}` must be an Azure id: letters, digits, dots and dashes."),
                ))
            }
        };

        Ok(Self {
            owner: owner.to_owned(),
            app_id: AIRLOCK_SAFE_APP_ID,
            key_name: key_name.to_owned(),
            installed_on: InstalledOn::parse(&inputs.installation_repositories)?,
            vault_url,
            azure_tenant_id: azure_id("azure-tenant-id", &inputs.azure_tenant_id)?,
            azure_client_id: azure_id("azure-client-id", &inputs.azure_client_id)?,
        })
    }
}

/// The vault's origin: `https://` and a host, with no path, query or
/// credentials.
///
/// Plain `http://` is accepted for a loopback host alone, which is where the
/// test suite's fake vault listens; no request leaves the machine there.
fn vault_origin(value: &str) -> Result<String, CentralError> {
    let refused = || {
        CentralError::new(
            Step::Inputs,
            "`vault-url` must be `https://` and a host, with no path.",
        )
    };
    let url = url::Url::parse(value).map_err(|_| refused())?;
    let host = url.host_str().ok_or_else(refused)?;
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    let scheme_allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    let bare = url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !scheme_allowed || !bare {
        return Err(refused());
    }
    Ok(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// How the job asks GitHub for its OpenID Connect token.
pub struct OidcRequest {
    url: String,
    token: Zeroizing<String>,
}

impl fmt::Debug for OidcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcRequest")
            .finish_non_exhaustive()
    }
}

impl OidcRequest {
    /// Read `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns an `azure-sign-in` error when either is absent, which is what a
    /// job without `id-token: write`, or a run outside Actions, looks like.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, CentralError> {
        let read = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        match (
            read("ACTIONS_ID_TOKEN_REQUEST_URL"),
            read("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
        ) {
            (Some(url), Some(token)) => Ok(Self {
                url,
                token: Zeroizing::new(token),
            }),
            _ => Err(CentralError::new(
                Step::AzureSignIn,
                "the job cannot request an OpenID Connect token. Central mode runs inside \
                 GitHub Actions, in a job with `id-token: write`.",
            )),
        }
    }
}

/// How central mode proves itself to Entra ID for the Key Vault token.
///
/// The token is the same in every case: Key Vault's data-plane scope, for
/// the identity `azure-client-id` names. Only the proof differs, by where
/// Airlock runs.
pub enum AzureCredential {
    /// The job's GitHub OpenID Connect token, which the identity's federated
    /// credential trusts. This is how a GitHub Actions job signs in.
    GitHubOidc(OidcRequest),
    /// The identity's client secret. This is how a host with no OpenID
    /// Connect issuer signs in: the Airlock Worker, holding the secret in the
    /// Cloudflare Secrets Store (wyrd-company/.github#26).
    ClientSecret(Zeroizing<String>),
}

impl AzureCredential {
    /// A client secret.
    ///
    /// # Errors
    ///
    /// Returns an `inputs` error for an empty value.
    pub fn client_secret(value: impl Into<String>) -> Result<Self, CentralError> {
        let value = Zeroizing::new(value.into());
        if value.trim().is_empty() {
            return Err(CentralError::new(
                Step::Inputs,
                "the Entra ID client secret is empty",
            ));
        }
        Ok(Self::ClientSecret(value))
    }

    /// The credential's kind, which is safe to show.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::GitHubOidc(_) => "github-oidc",
            Self::ClientSecret(_) => "client-secret",
        }
    }
}

impl From<OidcRequest> for AzureCredential {
    fn from(request: OidcRequest) -> Self {
        Self::GitHubOidc(request)
    }
}

impl fmt::Debug for AzureCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value is deliberately absent.
        formatter
            .debug_struct("AzureCredential")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// The hosts central mode talks to. Overridden in tests.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The GitHub REST API root, with no trailing slash.
    pub github_api: String,
    /// Entra ID's sign-in host, with no trailing slash.
    pub azure_login: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            github_api: "https://api.github.com".to_owned(),
            azure_login: AZURE_LOGIN_BASE.to_owned(),
        }
    }
}

/// A signed-in central run: Airlock Safe's installation token, and what was
/// checked about it.
pub struct CentralSession {
    token: Zeroizing<String>,
    /// The verified grant, for the audit and the report.
    pub grant: VerifiedGrant,
    /// The owner's installation id.
    pub installation_id: u64,
    /// The token's expiry, as GitHub stated it.
    pub expires_at: Option<String>,
    http: Http,
    github_api: String,
}

impl fmt::Debug for CentralSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token is deliberately absent.
        formatter
            .debug_struct("CentralSession")
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

impl CentralSession {
    /// The installation token, to build the read-only client with.
    ///
    /// The session keeps it only in memory and overwrites it when dropped.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Revoke the installation token.
    ///
    /// The session can still redact after this, which is when its output is
    /// rendered.
    ///
    /// # Errors
    ///
    /// Returns a `token-revoke` error when GitHub does not confirm it.
    pub async fn revoke(&self) -> Result<(), CentralError> {
        revoke_token(&self.http, &self.github_api, &self.token).await
    }

    /// The transport the session signed in through, for the clients that
    /// audit with its token.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.http.transport)
    }

    /// Replace every occurrence of the session's token in `text`.
    ///
    /// The last guard on everything central mode prints: a report or a
    /// message that came to carry the token through some service's echo
    /// carries `[redacted]` instead.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        if self.token.is_empty() {
            text.to_owned()
        } else {
            text.replace(self.token.as_str(), "[redacted]")
        }
    }
}

/// Sign in as Airlock Safe and mint a read-only installation token.
///
/// Every request goes through `transport`, which also supplies the clock the
/// App's JSON Web Token is dated by.
///
/// # Errors
///
/// Returns a [`CentralError`] naming the first step that failed.
pub async fn sign_in(
    config: &CentralConfig,
    credential: &AzureCredential,
    endpoints: &Endpoints,
    limits: Limits,
    transport: Arc<dyn Transport>,
) -> Result<CentralSession, CentralError> {
    let http = Http {
        transport,
        timeout: limits.request_timeout,
    };
    let budget = limits.max_response_bytes;

    let vault_token = azure_sign_in(&http, config, credential, endpoints, budget).await?;
    let now = http
        .transport
        .unix_time()
        .map_err(|_| {
            CentralError::new(
                Step::KeyVaultSign,
                "the clock gave no usable time to date the App's JSON Web Token",
            )
        })?
        .as_secs();
    let jwt = sign_app_jwt(&http, config, &vault_token, budget, now).await?;
    drop(vault_token);

    check_app(&http, &endpoints.github_api, &jwt, budget).await?;
    let installation =
        find_installation(&http, config, &endpoints.github_api, &jwt, budget).await?;
    check_scope(config, &installation)?;
    let minted = mint_token(&http, &endpoints.github_api, &jwt, installation.id, budget).await?;

    let grant = VerifiedGrant {
        kind: TokenKind::Installation,
        issuer: Some(AIRLOCK_SAFE_APP_SLUG.to_owned()),
        login: None,
        scopes: Vec::new(),
        installations: vec![InstallationGrant {
            id: installation.id,
            account: Some(installation.account.clone()),
            permissions: minted
                .permissions
                .iter()
                .map(|(name, level)| format!("{name}={level}"))
                .collect(),
        }],
        run: None,
    };
    Ok(CentralSession {
        token: minted.token,
        grant,
        installation_id: installation.id,
        expires_at: minted.expires_at,
        http,
        github_api: endpoints.github_api.clone(),
    })
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

async fn azure_sign_in(
    http: &Http,
    config: &CentralConfig,
    credential: &AzureCredential,
    endpoints: &Endpoints,
    budget: usize,
) -> Result<Zeroizing<String>, CentralError> {
    let assertion;
    let (proof, refused) = match credential {
        AzureCredential::GitHubOidc(oidc) => {
            assertion = github_oidc_assertion(http, oidc, budget).await?;
            (
                ("client_assertion", assertion.as_str()),
                "Entra ID refused the job's federated credential",
            )
        }
        AzureCredential::ClientSecret(value) => (
            ("client_secret", value.as_str()),
            "Entra ID refused the client secret",
        ),
    };

    let mut form = vec![
        ("client_id", config.azure_client_id.as_str()),
        ("scope", KEY_VAULT_SCOPE),
    ];
    if proof.0 == "client_assertion" {
        form.push((
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ));
    }
    form.push(proof);
    form.push(("grant_type", "client_credentials"));
    let encoded = Zeroizing::new(
        form.iter()
            .map(|(name, value)| {
                format!(
                    "{name}={}",
                    percent_encoding::utf8_percent_encode(value, FORM_VALUE)
                )
            })
            .collect::<Vec<_>>()
            .join("&"),
    );
    drop(form);
    let request = transport::Request::new(
        Method::Post,
        format!(
            "{}/{}/oauth2/v2.0/token",
            endpoints.azure_login, config.azure_tenant_id
        ),
    )
    .header("content-type", "application/x-www-form-urlencoded")
    .header("accept", "application/json")
    .body(encoded.as_bytes());
    let (status, body) = http
        .call(
            request,
            Step::AzureSignIn,
            "the Entra ID token request",
            budget,
        )
        .await?;
    if !(200..300).contains(&status) {
        // Entra ID names the failure in `error`, such as `invalid_client`,
        // and in the numbers of `error_codes`, such as AADSTS70021. Only a
        // code from OAuth's closed list and those numbers are carried; the
        // description is the service's free text and is not.
        return Err(answered(
            Step::AzureSignIn,
            refused,
            status,
            entra_code(&body),
        ));
    }
    string_field(&body, "access_token")
        .map(|token| Zeroizing::new(token.to_owned()))
        .ok_or_else(|| {
            CentralError::new(
                Step::AzureSignIn,
                "Entra ID's answer carried no access token",
            )
        })
}

/// The job's OpenID Connect token, for Entra ID's federated credential.
async fn github_oidc_assertion(
    http: &Http,
    oidc: &OidcRequest,
    budget: usize,
) -> Result<Zeroizing<String>, CentralError> {
    let separator = if oidc.url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{}{separator}audience={}",
        oidc.url,
        percent_encoding::utf8_percent_encode(AZURE_AUDIENCE, percent_encoding::NON_ALPHANUMERIC)
    );
    let request = transport::Request::new(Method::Get, url)
        .bearer(oidc.token.as_str())
        .header("accept", "application/json");
    let (status, body) = http
        .call(
            request,
            Step::AzureSignIn,
            "the OpenID Connect request",
            budget,
        )
        .await?;
    if !(200..300).contains(&status) {
        return Err(answered(
            Step::AzureSignIn,
            "GitHub refused the job's OpenID Connect token request",
            status,
            None,
        ));
    }
    let assertion = Zeroizing::new(
        string_field(&body, "value")
            .ok_or_else(|| {
                CentralError::new(
                    Step::AzureSignIn,
                    "GitHub's OpenID Connect answer carried no token",
                )
            })?
            .to_owned(),
    );
    drop(body);
    Ok(assertion)
}

/// The App's JSON Web Token, signed by Key Vault.
async fn sign_app_jwt(
    http: &Http,
    config: &CentralConfig,
    vault_token: &str,
    budget: usize,
    now: u64,
) -> Result<Zeroizing<String>, CentralError> {
    let signing_input = jwt_signing_input(config.app_id, now);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(signing_input.as_bytes()));

    // Without a key version the segment is empty, as the Azure SDKs send it,
    // and Key Vault signs with the latest enabled version.
    let url = format!(
        "{}/keys/{}//sign?api-version={KEY_VAULT_API_VERSION}",
        config.vault_url, config.key_name
    );
    let request = transport::Request::new(Method::Post, url)
        .bearer(vault_token)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .body(serde_json::json!({ "alg": "RS256", "value": digest }).to_string());
    let (status, body) = http
        .call(
            request,
            Step::KeyVaultSign,
            "the Key Vault sign request",
            budget,
        )
        .await?;
    if !(200..300).contains(&status) {
        return Err(answered(
            Step::KeyVaultSign,
            format!(
                "Key Vault refused to sign with the key `{}`",
                config.key_name
            ),
            status,
            body.get("error")
                .and_then(|error| string_field(error, "code"))
                .filter(|code| KEY_VAULT_CODES.contains(code))
                .map(ToOwned::to_owned),
        ));
    }
    let signature = string_field(&body, "value")
        .and_then(|value| URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok())
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| {
            CentralError::new(
                Step::KeyVaultSign,
                "Key Vault's answer carried no base64url signature",
            )
        })?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

/// The unsigned part of the App's JSON Web Token: header and claims, each
/// base64url without padding.
///
/// `iat` is sixty seconds before now, against clock drift, and `exp` 540
/// seconds after, inside GitHub's ten-minute limit.
#[must_use]
pub fn jwt_signing_input(app_id: u64, now: u64) -> String {
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
        now.saturating_sub(60),
        now.saturating_add(540)
    );
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    )
}

// ---------------------------------------------------------------------------
// GitHub App
// ---------------------------------------------------------------------------

async fn check_app(
    http: &Http,
    github_api: &str,
    jwt: &str,
    budget: usize,
) -> Result<(), CentralError> {
    let (status, body) = github(
        http,
        transport::Request::new(Method::Get, format!("{github_api}/app")),
        jwt,
        Step::AppIdentity,
        budget,
    )
    .await?;
    if status != 200 {
        return Err(github_refusal(
            Step::AppIdentity,
            "GitHub refused the App's JSON Web Token",
            status,
            &body,
        ));
    }
    let id = body.get("id").and_then(Value::as_u64);
    let slug = string_field(&body, "slug");
    if id != Some(AIRLOCK_SAFE_APP_ID) || slug != Some(AIRLOCK_SAFE_APP_SLUG) {
        // The id is a number and safe to show; the slug GitHub returned is
        // text, and is not repeated.
        return Err(CentralError::new(
            Step::AppIdentity,
            format!(
                "the key signs for another App (app id {}), not `{AIRLOCK_SAFE_APP_SLUG}` (app id \
                 {AIRLOCK_SAFE_APP_ID}), the App central mode is built with",
                id.map_or_else(|| "unknown".to_owned(), |id| id.to_string())
            ),
        ));
    }
    let permissions = permission_map(&body).ok_or_else(|| {
        CentralError::new(
            Step::AppIdentity,
            "`GET /app` carried no readable permission map, so the App's registration is unread",
        )
    })?;
    let writes = non_reads(&permissions);
    if permissions.is_empty() || !writes.is_empty() {
        return Err(CentralError::new(
            Step::AppIdentity,
            format!(
                "`{AIRLOCK_SAFE_APP_SLUG}` is registered with {}; central mode requires every \
                 permission `read`",
                if writes.is_empty() {
                    "no permissions".to_owned()
                } else {
                    writes.join(", ")
                }
            ),
        ));
    }
    Ok(())
}

/// The owner's installation, as central mode checks it.
#[derive(Debug, Clone)]
struct FoundInstallation {
    id: u64,
    account: String,
    repository_selection: Option<String>,
}

async fn find_installation(
    http: &Http,
    config: &CentralConfig,
    github_api: &str,
    jwt: &str,
    budget: usize,
) -> Result<FoundInstallation, CentralError> {
    let owner = &config.owner;
    let mut answer = github(
        http,
        transport::Request::new(
            Method::Get,
            format!("{github_api}/orgs/{owner}/installation"),
        ),
        jwt,
        Step::InstallationLookup,
        budget,
    )
    .await?;
    if answer.0 == 404 {
        // A user account answers on its own route.
        answer = github(
            http,
            transport::Request::new(
                Method::Get,
                format!("{github_api}/users/{owner}/installation"),
            ),
            jwt,
            Step::InstallationLookup,
            budget,
        )
        .await?;
    }
    let (status, body) = answer;
    if status != 200 {
        return Err(github_refusal(
            Step::InstallationLookup,
            format!("`{AIRLOCK_SAFE_APP_SLUG}` is not installed for `{owner}`"),
            status,
            &body,
        ));
    }
    let id = body.get("id").and_then(Value::as_u64).ok_or_else(|| {
        CentralError::new(Step::InstallationLookup, "the installation carried no id")
    })?;
    if body.get("app_id").and_then(Value::as_u64) != Some(AIRLOCK_SAFE_APP_ID) {
        return Err(CentralError::new(
            Step::InstallationLookup,
            format!("installation {id} does not belong to `{AIRLOCK_SAFE_APP_SLUG}`"),
        ));
    }
    Ok(FoundInstallation {
        id,
        // The owner Airlock asked for, rather than the login text GitHub
        // returned: the route already bound the installation to it.
        account: owner.clone(),
        repository_selection: string_field(&body, "repository_selection").map(ToOwned::to_owned),
    })
}

/// The installation must reach every repository of the owner, and the
/// configured `installation-repositories` must say so.
///
/// With selection `all`, the token action's rule passes only for
/// `<owner>/*`, so a list of repositories is refused too: it states a bound
/// the installation does not keep.
fn check_scope(
    config: &CentralConfig,
    installation: &FoundInstallation,
) -> Result<(), CentralError> {
    if installation.repository_selection.as_deref() != Some("all") {
        return Err(CentralError::new(
            Step::InstallationScope,
            format!(
                "installation {} reaches `{}` repositories; `delivery-apps` requires \
                 `{AIRLOCK_SAFE_APP_SLUG}` to be installed on all of `{}`'s repositories",
                installation.id,
                match installation.repository_selection.as_deref() {
                    Some(known @ ("all" | "selected")) => known,
                    Some(_) => "an unrecognised selection of",
                    None => "an unstated selection of",
                },
                config.owner
            ),
        ));
    }
    match &config.installed_on {
        InstalledOn::Owner(owner) if owner.eq_ignore_ascii_case(&config.owner) => Ok(()),
        InstalledOn::Owner(owner) => Err(CentralError::new(
            Step::InstallationScope,
            format!(
                "installation {} reaches every repository of `{}`, and \
                 `installation-repositories` names `{owner}/*`",
                installation.id, config.owner
            ),
        )),
        InstalledOn::Repositories(_) => Err(CentralError::new(
            Step::InstallationScope,
            format!(
                "installation {} reaches every repository of `{}` (selection `all`), which \
                 `installation-repositories` allows only as `{}/*`",
                installation.id, config.owner, config.owner
            ),
        )),
    }
}

struct MintedToken {
    token: Zeroizing<String>,
    permissions: BTreeMap<String, String>,
    expires_at: Option<String>,
}

async fn mint_token(
    http: &Http,
    github_api: &str,
    jwt: &str,
    installation_id: u64,
    budget: usize,
) -> Result<MintedToken, CentralError> {
    let (status, body) = github(
        http,
        transport::Request::new(
            Method::Post,
            format!("{github_api}/app/installations/{installation_id}/access_tokens"),
        )
        .header("content-type", "application/json")
        .body("{}"),
        jwt,
        Step::TokenRequest,
        budget,
    )
    .await?;
    if status != 201 {
        return Err(github_refusal(
            Step::TokenRequest,
            format!("GitHub refused a token for installation {installation_id}"),
            status,
            &body,
        ));
    }
    let token = string_field(&body, "token")
        .map(|token| Zeroizing::new(token.to_owned()))
        .ok_or_else(|| CentralError::new(Step::TokenRequest, "GitHub's answer carried no token"))?;
    // Every output is redacted against this token, which only works for a
    // value shaped like a GitHub token: a short one would redact nothing, and
    // one with `"` or `%` has escaped forms a redactor misses. So a token of
    // another shape is never used.
    if !crate::auth::has_token_shape(&token) {
        let revoked = revoke_token(http, github_api, &token).await;
        return Err(CentralError::new(
            Step::TokenRequest,
            format!(
                "the minted token is not shaped like a GitHub token (8 to 4096 letters, digits \
                 and `_`), so central mode will not use it{}",
                match revoked {
                    Ok(()) => ", and it was revoked".to_owned(),
                    Err(error) => format!(", and revoking it failed: {}", error.step.code()),
                }
            ),
        ));
    }
    let permissions = permission_map(&body);
    let writes = permissions.as_ref().map(non_reads).unwrap_or_default();
    let listed = match &permissions {
        None => Some("an unreadable permission map".to_owned()),
        Some(map) if map.is_empty() => Some("no permissions".to_owned()),
        Some(_) if !writes.is_empty() => Some(writes.join(", ")),
        Some(_) => None,
    };
    if let Some(listed) = listed {
        // The token exists, and Airlock will not use it, so it does not
        // outlive the refusal.
        let revoked = revoke_token(http, github_api, &token).await;
        return Err(CentralError::new(
            Step::TokenRequest,
            format!(
                "the minted token lists {listed}; central mode accepts only `read` permissions{}",
                match revoked {
                    Ok(()) => ", and it was revoked".to_owned(),
                    Err(error) => format!(", and revoking it failed: {error}"),
                }
            ),
        ));
    }
    Ok(MintedToken {
        token,
        permissions: permissions.unwrap_or_default(),
        // A timestamp, kept only when it looks like one.
        expires_at: string_field(&body, "expires_at")
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 40
                    && value.chars().all(|c| {
                        c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 'Z' | '.' | '+')
                    })
            })
            .map(ToOwned::to_owned),
    })
}

async fn revoke_token(http: &Http, github_api: &str, token: &str) -> Result<(), CentralError> {
    let (status, body) = github(
        http,
        transport::Request::new(Method::Delete, format!("{github_api}/installation/token")),
        token,
        Step::TokenRevoke,
        4096,
    )
    .await?;
    if status == 204 {
        Ok(())
    } else {
        Err(github_refusal(
            Step::TokenRevoke,
            "GitHub did not confirm the installation token was revoked",
            status,
            &body,
        ))
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The transport, and how long one request may take.
#[derive(Clone)]
struct Http {
    transport: Arc<dyn Transport>,
    timeout: Duration,
}

impl Http {
    /// Send one request and read its answer under the byte budget. A body
    /// that is not JSON reads as null, so a refusal still reports its status.
    ///
    /// Every request here carries a credential, and a redirect is the server
    /// choosing where it goes next, so none is followed.
    async fn call(
        &self,
        mut request: transport::Request,
        step: Step,
        what: &str,
        budget: usize,
    ) -> Result<(u16, Value), CentralError> {
        request.follow_redirects = false;
        request.timeout = self.timeout;
        request.max_response_bytes = budget;
        let request = request.header("user-agent", concat!("airlock/", env!("CARGO_PKG_VERSION")));
        let response = self.transport.send(request).await.map_err(|error| {
            // The transport's message names the URL. The URLs here carry no
            // credential, but the text is not needed, so only the kind is
            // kept.
            let kind = match error.kind {
                FailureKind::TooLarge => {
                    return CentralError::new(
                        step,
                        format!("the answer exceeded the {budget} byte limit and was abandoned"),
                    )
                }
                FailureKind::Timeout => "timed out",
                FailureKind::Connect => "could not connect",
                FailureKind::Clock => "stopped: the clock gave no usable time",
                FailureKind::Other => "failed",
            };
            CentralError::new(step, format!("{what} {kind}"))
        })?;
        Ok((
            response.status,
            serde_json::from_slice(&response.body).unwrap_or(Value::Null),
        ))
    }
}

async fn github(
    http: &Http,
    request: transport::Request,
    bearer: &str,
    step: Step,
    budget: usize,
) -> Result<(u16, Value), CentralError> {
    let request = request
        .bearer(bearer)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28");
    http.call(request, step, "the GitHub request", budget).await
}

fn answered(
    step: Step,
    detail: impl Into<String>,
    status: u16,
    code: Option<String>,
) -> CentralError {
    CentralError {
        step,
        detail: detail.into(),
        status: Some(status),
        code,
    }
}

/// A refusal from GitHub, reported by its status alone.
///
/// GitHub's `message` is free text, and a server or proxy that echoes the
/// request's credential would put it there, so it is never carried.
fn github_refusal(
    step: Step,
    detail: impl Into<String>,
    status: u16,
    _body: &Value,
) -> CentralError {
    answered(step, detail, status, None)
}

/// The OAuth error codes Entra ID's token endpoint answers with.
const ENTRA_CODES: &[&str] = &[
    "access_denied",
    "consent_required",
    "expired_token",
    "interaction_required",
    "invalid_client",
    "invalid_grant",
    "invalid_request",
    "invalid_resource",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    "unauthorized_client",
    "unsupported_grant_type",
];

/// The Key Vault error codes a sign request answers with.
const KEY_VAULT_CODES: &[&str] = &[
    "BadParameter",
    "Forbidden",
    "KeyDisabled",
    "KeyExpired",
    "KeyNotFound",
    "KeyNotYetValid",
    "NotFound",
    "ServiceUnavailable",
    "Throttled",
    "Unauthorized",
];

/// Entra ID's error, as a vetted code: the OAuth code when it is one, and
/// the first AADSTS number, which is a number and cannot carry text.
fn entra_code(body: &Value) -> Option<String> {
    let code = string_field(body, "error").filter(|code| ENTRA_CODES.contains(code));
    let number = body
        .get("error_codes")
        .and_then(Value::as_array)
        .and_then(|codes| codes.first())
        .and_then(Value::as_u64);
    match (code, number) {
        (Some(code), Some(number)) => Some(format!("{code}, AADSTS{number}")),
        (Some(code), None) => Some(code.to_owned()),
        (None, Some(number)) => Some(format!("AADSTS{number}")),
        (None, None) => None,
    }
}

fn string_field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

/// The permission map, when every entry has a permission's shape.
///
/// A name is lowercase letters and underscores, and a level is `read`,
/// `write` or `admin`. A map with any other entry is unread rather than
/// partly read, and its text is never repeated.
fn permission_map(value: &Value) -> Option<BTreeMap<String, String>> {
    let Value::Object(map) = value.get("permissions")? else {
        return None;
    };
    map.iter()
        .map(|(name, level)| {
            let named = !name.is_empty()
                && name.len() <= 64
                && name.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            match level.as_str() {
                Some(level @ ("read" | "write" | "admin")) if named => {
                    Some((name.clone(), level.to_owned()))
                }
                _ => None,
            }
        })
        .collect()
}

fn non_reads(permissions: &BTreeMap<String, String>) -> Vec<String> {
    permissions
        .iter()
        .filter(|(_, level)| level.as_str() != "read")
        .map(|(name, level)| format!("{name}={level}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> CentralInputs {
        CentralInputs {
            app_id: "4409712".to_owned(),
            key_name: "airlock-safe".to_owned(),
            installation_repositories: "wyrd-company/*".to_owned(),
            vault_url: "https://wyrd.vault.azure.net".to_owned(),
            azure_tenant_id: "11111111-2222-3333-4444-555555555555".to_owned(),
            azure_client_id: "66666666-7777-8888-9999-000000000000".to_owned(),
        }
    }

    #[test]
    fn the_inputs_the_template_passes_validate() {
        let config = CentralConfig::parse("wyrd-company", &inputs()).unwrap();
        assert_eq!(config.app_id, AIRLOCK_SAFE_APP_ID);
        assert_eq!(config.vault_url, "https://wyrd.vault.azure.net");
        assert_eq!(
            config.installed_on,
            InstalledOn::Owner("wyrd-company".to_owned())
        );
    }

    #[test]
    fn central_mode_signs_only_as_airlock_safe() {
        for app_id in ["4409767", "", "airlock-safe", "4409712x"] {
            let error = CentralConfig::parse(
                "wyrd-company",
                &CentralInputs {
                    app_id: app_id.to_owned(),
                    ..inputs()
                },
            )
            .unwrap_err();
            assert_eq!(error.step, Step::Inputs, "{app_id}");
        }
    }

    #[test]
    fn a_vault_address_must_be_an_https_origin() {
        for vault_url in [
            "http://wyrd.vault.azure.net",
            "https://wyrd.vault.azure.net/keys",
            "https://wyrd.vault.azure.net/?x=1",
            "https://user@wyrd.vault.azure.net",
            "wyrd.vault.azure.net",
            "",
        ] {
            let error = CentralConfig::parse(
                "wyrd-company",
                &CentralInputs {
                    vault_url: vault_url.to_owned(),
                    ..inputs()
                },
            )
            .unwrap_err();
            assert_eq!(error.step, Step::Inputs, "{vault_url}");
        }
        assert_eq!(
            vault_origin("https://wyrd.vault.azure.net/").unwrap(),
            "https://wyrd.vault.azure.net"
        );
        assert_eq!(
            vault_origin("http://127.0.0.1:8200").unwrap(),
            "http://127.0.0.1:8200"
        );
    }

    #[test]
    fn a_key_name_is_what_key_vault_accepts() {
        for key_name in ["", "airlock safe", "airlock_safe", &"a".repeat(128)] {
            let error = CentralConfig::parse(
                "wyrd-company",
                &CentralInputs {
                    key_name: key_name.to_owned(),
                    ..inputs()
                },
            )
            .unwrap_err();
            assert_eq!(error.step, Step::Inputs, "{key_name}");
        }
    }

    #[test]
    fn installation_repositories_parse_as_the_token_action_reads_them() {
        assert_eq!(
            InstalledOn::parse(" wyrd-company/* \n").unwrap(),
            InstalledOn::Owner("wyrd-company".to_owned())
        );
        assert_eq!(
            InstalledOn::parse("wyrd-company/a,\nwyrd-company/b").unwrap(),
            InstalledOn::Repositories(vec![
                "wyrd-company/a".to_owned(),
                "wyrd-company/b".to_owned()
            ])
        );
        for value in [
            "",
            " , ",
            "wyrd-company/*,wyrd-company/a",
            "*",
            "*/*",
            "wyrd-company",
            "wyrd-company/a/b",
        ] {
            assert_eq!(
                InstalledOn::parse(value).unwrap_err().step,
                Step::Inputs,
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_jwt_carries_the_app_id_and_a_ten_minute_window() {
        let input = jwt_signing_input(AIRLOCK_SAFE_APP_ID, 1_000_000);
        let (header, claims) = input.split_once('.').unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(header).unwrap(),
            br#"{"alg":"RS256","typ":"JWT"}"#
        );
        assert_eq!(
            String::from_utf8(URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap(),
            r#"{"iat":999940,"exp":1000540,"iss":"4409712"}"#
        );
    }

    #[test]
    fn an_owner_whose_installation_reaches_selected_repositories_is_refused() {
        let config = CentralConfig::parse("wyrd-company", &inputs()).unwrap();
        let installation = |selection: Option<&str>| FoundInstallation {
            id: 9,
            account: "wyrd-company".to_owned(),
            repository_selection: selection.map(ToOwned::to_owned),
        };
        assert!(check_scope(&config, &installation(Some("all"))).is_ok());
        for selection in [Some("selected"), None] {
            assert_eq!(
                check_scope(&config, &installation(selection))
                    .unwrap_err()
                    .step,
                Step::InstallationScope
            );
        }

        let listing = CentralConfig {
            installed_on: InstalledOn::Repositories(vec!["wyrd-company/a".to_owned()]),
            ..config.clone()
        };
        assert_eq!(
            check_scope(&listing, &installation(Some("all")))
                .unwrap_err()
                .step,
            Step::InstallationScope
        );
        let elsewhere = CentralConfig {
            installed_on: InstalledOn::Owner("someone-else".to_owned()),
            ..config
        };
        assert_eq!(
            check_scope(&elsewhere, &installation(Some("all")))
                .unwrap_err()
                .step,
            Step::InstallationScope
        );
    }

    #[test]
    fn the_oidc_request_needs_id_token_write() {
        let error = OidcRequest::from_lookup(|_| None).unwrap_err();
        assert_eq!(error.step, Step::AzureSignIn);
        assert!(error.detail.contains("id-token: write"));
    }

    #[test]
    fn an_error_renders_step_status_and_code() {
        let error = answered(
            Step::KeyVaultSign,
            "Key Vault refused",
            403,
            Some("Forbidden".to_owned()),
        );
        assert_eq!(
            error.to_string(),
            "key-vault-sign: Key Vault refused (http 403, Forbidden)"
        );
    }
}
