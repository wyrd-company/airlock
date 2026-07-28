//! The GitHub App device flow.
//!
//! Airlock acquires its own credential rather than borrowing one. The device
//! flow is the only interactive grant that never asks a user to paste a token
//! anywhere, and the client id it needs is not a secret.
//!
//! Rotation is destructive on GitHub's side: exchanging a refresh token
//! invalidates both previous tokens immediately. Everything here is written
//! with that in mind — the caller stores the new pair before doing anything
//! else with it.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;

/// GitHub's OAuth host. Overridden in tests.
pub const GITHUB_LOGIN_BASE: &str = "https://github.com";

/// The device grant type, as the specification spells it.
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Device and user codes, and how to poll for them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceCode {
    /// The code airlock polls with.
    pub device_code: String,
    /// The code the user types into GitHub.
    pub user_code: String,
    /// Where the user types it.
    pub verification_uri: String,
    /// Seconds until both codes expire.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

/// A granted credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TokenGrant {
    /// The user access token.
    pub access_token: String,
    /// Seconds until the access token expires, when expiry is enabled.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// The refresh token, when expiry is enabled.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Seconds until the refresh token expires.
    #[serde(default)]
    pub refresh_token_expires_in: Option<u64>,
}

/// What one poll learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// The user authorised airlock.
    Granted(Box<TokenGrant>),
    /// The user has not finished yet.
    Pending,
    /// Airlock is polling too fast; wait this long instead.
    SlowDown(u64),
    /// The codes expired before the user finished.
    Expired,
    /// The user declined.
    Denied,
    /// GitHub reported something airlock does not handle.
    Failed(String),
}

/// How the device flow behaves.
///
/// The timeouts matter as much here as on the audit path: acquiring a
/// credential is the first thing a new user does, and a login that hangs
/// forever is indistinguishable from a broken tool.
#[derive(Debug, Clone)]
pub struct DeviceFlowConfig {
    /// GitHub's OAuth host, without a trailing slash. Overridden in tests.
    pub base_url: String,
    /// The shortest airlock will wait between polls, whatever GitHub says.
    pub interval_floor: Duration,
    /// How long to wait to open a connection.
    pub connect_timeout: Duration,
    /// How long to wait for one request to complete.
    pub request_timeout: Duration,
    /// Largest response body airlock will read from this host, in bytes.
    pub max_response_bytes: usize,
}

impl Default for DeviceFlowConfig {
    fn default() -> Self {
        Self {
            base_url: GITHUB_LOGIN_BASE.to_owned(),
            interval_floor: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            // These responses are a handful of fields. Anything approaching
            // this is not a device-flow response.
            max_response_bytes: 64 * 1024,
        }
    }
}

/// A device flow bound to one app.
pub struct DeviceFlow {
    http: reqwest::Client,
    client_id: String,
    config: DeviceFlowConfig,
}

impl std::fmt::Debug for DeviceFlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No token ever reaches this type's fields, but the habit is cheap.
        formatter
            .debug_struct("DeviceFlow")
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

impl DeviceFlow {
    /// Build a device flow for `client_id`.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP stack cannot be built.
    pub fn new(client_id: &str, config: DeviceFlowConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
            // Without these a server that accepts the connection and never
            // answers hangs `auth login`, and hangs `audit` on the refresh
            // that happens before the bounded REST client exists.
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .context("cannot build the http client")?;
        Ok(Self {
            http,
            client_id: client_id.to_owned(),
            config: DeviceFlowConfig {
                base_url: config.base_url.trim_end_matches('/').to_owned(),
                ..config
            },
        })
    }

    async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(format!("{}{path}", self.config.base_url))
            .header("Accept", "application/json")
            .form(form)
            .send()
            .await
            .with_context(|| format!("cannot reach {path}"))?;
        let status = response.status();
        let body = self.read_body(path, response).await?;
        if !status.is_success() {
            bail!("{path} answered {status}");
        }
        serde_json::from_str(&body).with_context(|| format!("{path} did not answer with json"))
    }

    /// Read a response body under the byte budget.
    async fn read_body(&self, path: &str, mut response: reqwest::Response) -> Result<String> {
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .with_context(|| format!("cannot read the response from {path}"))?;
            let Some(chunk) = chunk else { break };
            if bytes.len() + chunk.len() > self.config.max_response_bytes {
                bail!(
                    "{path} answered with more than {} bytes, which is not a device flow \
                     response",
                    self.config.max_response_bytes
                );
            }
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes).with_context(|| format!("{path} did not answer with text"))
    }

    /// Ask GitHub for a device and user code.
    ///
    /// # Errors
    ///
    /// Returns an error when GitHub refuses the request or answers a shape
    /// airlock does not understand.
    pub async fn request_codes(&self) -> Result<DeviceCode> {
        let body = self
            .post("/login/device/code", &[("client_id", &self.client_id)])
            .await?;
        if let Some(error) = body.get("error").and_then(serde_json::Value::as_str) {
            bail!("{}", describe(error, &body));
        }
        serde_json::from_value(body)
            .context("GitHub's device code response was not the documented shape")
    }

    /// Poll once for the access token.
    ///
    /// # Errors
    ///
    /// Returns an error only when the request itself fails. A pending or
    /// refused authorisation is an outcome, not an error.
    pub async fn poll_once(&self, device_code: &str) -> Result<PollOutcome> {
        let body = self
            .post(
                "/login/oauth/access_token",
                &[
                    ("client_id", &self.client_id),
                    ("device_code", device_code),
                    ("grant_type", DEVICE_GRANT_TYPE),
                ],
            )
            .await?;

        if let Some(error) = body.get("error").and_then(serde_json::Value::as_str) {
            return Ok(match error {
                "authorization_pending" => PollOutcome::Pending,
                "slow_down" => PollOutcome::SlowDown(
                    body.get("interval")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                ),
                // GitHub's app and OAuth docs spell the same condition two ways.
                "expired_token" | "token_expired" => PollOutcome::Expired,
                "access_denied" => PollOutcome::Denied,
                other => PollOutcome::Failed(describe(other, &body)),
            });
        }

        match serde_json::from_value::<TokenGrant>(body) {
            Ok(grant) => Ok(PollOutcome::Granted(Box::new(grant))),
            Err(error) => Ok(PollOutcome::Failed(format!(
                "GitHub's token response was not the documented shape: {error}"
            ))),
        }
    }

    /// Poll until the user finishes, refuses, or the codes expire.
    ///
    /// # Errors
    ///
    /// Returns an error when the user declines, the codes expire, or GitHub
    /// reports a condition airlock cannot continue through.
    pub async fn poll_until_granted(&self, codes: &DeviceCode) -> Result<TokenGrant> {
        let mut interval = self
            .config
            .interval_floor
            .max(Duration::from_secs(codes.interval));
        let deadline = std::time::Instant::now() + Duration::from_secs(codes.expires_in);

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                bail!(
                    "the device code expired before the authorisation finished. Run \
                     `airlock auth login` again."
                );
            }
            tokio::time::sleep(interval.min(remaining)).await;

            // The per-request timeout bounds one poll; this bounds the whole
            // wait to the lifetime of the code being polled for, so a slow
            // server cannot keep airlock polling past the point of any use.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let outcome = tokio::time::timeout(remaining, self.poll_once(&codes.device_code))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "the device code expired before the authorisation finished. Run \
                         `airlock auth login` again."
                    )
                })??;

            match outcome {
                PollOutcome::Granted(grant) => return Ok(*grant),
                PollOutcome::Pending => {}
                PollOutcome::SlowDown(suggested) => {
                    // The specification says to back off by five seconds;
                    // GitHub also sends a new interval, so honour the larger.
                    interval = interval.saturating_add(Duration::from_secs(5)).max(
                        self.config
                            .interval_floor
                            .max(Duration::from_secs(suggested)),
                    );
                }
                PollOutcome::Expired => bail!(
                    "the device code expired before the authorisation finished. Run \
                     `airlock auth login` again."
                ),
                PollOutcome::Denied => bail!("the authorisation was declined."),
                PollOutcome::Failed(message) => bail!("{message}"),
            }
        }
    }

    /// Exchange a refresh token for a new pair.
    ///
    /// # Errors
    ///
    /// Returns an error when GitHub refuses the exchange. A refused exchange
    /// means both stored tokens are dead and the user must authorise again.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenGrant> {
        let body = self
            .post(
                "/login/oauth/access_token",
                &[
                    ("client_id", &self.client_id),
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                ],
            )
            .await?;

        if let Some(error) = body.get("error").and_then(serde_json::Value::as_str) {
            bail!("{}", describe(error, &body));
        }
        serde_json::from_value(body)
            .context("GitHub's refresh response was not the documented shape")
    }
}

/// Turn a documented OAuth error code into something a human can act on.
fn describe(error: &str, body: &serde_json::Value) -> String {
    let explanations: BTreeMap<&str, &str> = [
        (
            "bad_refresh_token",
            "the stored refresh token is no longer valid. Run `airlock auth login` again.",
        ),
        (
            "unsupported_grant_type",
            "GitHub rejected the grant type, which means this build sent the wrong request.",
        ),
        (
            "incorrect_client_credentials",
            "GitHub did not recognise the Airlock Safe client id.",
        ),
        (
            "incorrect_device_code",
            "GitHub did not recognise the device code. Run `airlock auth login` again.",
        ),
        (
            "device_flow_disabled",
            "device flow is disabled on the Airlock Safe app registration.",
        ),
    ]
    .into_iter()
    .collect();

    match explanations.get(error) {
        Some(explanation) => format!("{error}: {explanation}"),
        None => {
            let description = body
                .get("error_description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("GitHub reported no further detail");
            format!("{error}: {description}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_error_codes_get_an_explanation_a_human_can_act_on() {
        let described = describe("bad_refresh_token", &serde_json::json!({}));
        assert!(described.contains("airlock auth login"));
    }

    #[test]
    fn an_unknown_error_code_carries_githubs_own_description() {
        let described = describe(
            "something_new",
            &serde_json::json!({ "error_description": "a brand new condition" }),
        );
        assert!(described.contains("a brand new condition"));
    }

    #[test]
    fn an_unknown_error_code_without_a_description_still_names_itself() {
        let described = describe("something_new", &serde_json::json!({}));
        assert!(described.contains("something_new"));
    }

    use std::time::Instant;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A flow whose requests must finish quickly or not at all.
    fn impatient(server: &MockServer) -> DeviceFlow {
        DeviceFlow::new(
            "Iv23liExample",
            DeviceFlowConfig {
                base_url: server.uri(),
                interval_floor: Duration::from_millis(0),
                connect_timeout: Duration::from_millis(100),
                request_timeout: Duration::from_millis(100),
                ..DeviceFlowConfig::default()
            },
        )
        .expect("the flow builds")
    }

    /// Mount a route that accepts the request and then says nothing useful for
    /// far longer than any caller should wait.
    async fn mount_stalled(server: &MockServer, route: &str) {
        Mock::given(method("POST"))
            .and(path(route.to_owned()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("{}")
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(server)
            .await;
    }

    fn assert_prompt(started: Instant, what: &str) {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{what} should have been abandoned promptly, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_stalled_device_code_request_is_abandoned_at_the_timeout() {
        let server = MockServer::start().await;
        mount_stalled(&server, "/login/device/code").await;

        let started = Instant::now();
        let error = impatient(&server).request_codes().await.unwrap_err();
        assert_prompt(started, "the device code request");
        assert!(
            error.to_string().contains("cannot reach"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn a_stalled_poll_is_abandoned_at_the_timeout() {
        let server = MockServer::start().await;
        mount_stalled(&server, "/login/oauth/access_token").await;

        let started = Instant::now();
        let error = impatient(&server)
            .poll_once("device-code")
            .await
            .unwrap_err();
        assert_prompt(started, "the poll");
        assert!(
            error.to_string().contains("cannot reach"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn a_stalled_refresh_is_abandoned_at_the_timeout() {
        let server = MockServer::start().await;
        mount_stalled(&server, "/login/oauth/access_token").await;

        let started = Instant::now();
        let error = impatient(&server).refresh("ghr_example").await.unwrap_err();
        assert_prompt(started, "the refresh");
        assert!(
            error.to_string().contains("cannot reach"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn polling_never_outlives_the_device_code() {
        // A server that answers `authorization_pending` forever would keep a
        // caller polling indefinitely without the lifetime bound.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("{\"error\":\"authorization_pending\"}"),
            )
            .mount(&server)
            .await;

        let codes = DeviceCode {
            device_code: "device-code".to_owned(),
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: 1,
            interval: 0,
        };

        let started = Instant::now();
        let error = impatient(&server)
            .poll_until_granted(&codes)
            .await
            .unwrap_err();
        assert_prompt(started, "polling");
        assert!(
            error.to_string().contains("expired"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn an_oversized_response_is_refused_rather_than_read() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096)))
            .mount(&server)
            .await;

        let flow = DeviceFlow::new(
            "Iv23liExample",
            DeviceFlowConfig {
                base_url: server.uri(),
                max_response_bytes: 64,
                ..DeviceFlowConfig::default()
            },
        )
        .unwrap();
        let error = flow.request_codes().await.unwrap_err();
        assert!(
            error.to_string().contains("64 bytes"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn a_device_flow_debug_print_carries_no_credential_material() {
        let flow = DeviceFlow::new("Iv23liExample", DeviceFlowConfig::default()).unwrap();
        assert!(!format!("{flow:?}").contains("Iv23liExample"));
    }
}
