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

/// A device flow bound to one app.
pub struct DeviceFlow {
    http: reqwest::Client,
    base_url: String,
    client_id: String,
    interval_floor: Duration,
}

impl DeviceFlow {
    /// Build a device flow for `client_id`.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP stack cannot be built.
    pub fn new(client_id: &str, base_url: &str, interval_floor: Duration) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("cannot build the http client")?,
            base_url: base_url.trim_end_matches('/').to_owned(),
            client_id: client_id.to_owned(),
            interval_floor,
        })
    }

    async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .header("Accept", "application/json")
            .form(form)
            .send()
            .await
            .with_context(|| format!("cannot reach {path}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("cannot read the response from {path}"))?;
        if !status.is_success() {
            bail!("{path} answered {status}");
        }
        serde_json::from_str(&body).with_context(|| format!("{path} did not answer with json"))
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
        let mut interval = self.interval_floor.max(Duration::from_secs(codes.interval));
        let deadline = std::time::Instant::now() + Duration::from_secs(codes.expires_in);

        loop {
            if std::time::Instant::now() > deadline {
                bail!(
                    "the device code expired before the authorisation finished. Run \
                     `airlock auth login` again."
                );
            }
            tokio::time::sleep(interval).await;

            match self.poll_once(&codes.device_code).await? {
                PollOutcome::Granted(grant) => return Ok(*grant),
                PollOutcome::Pending => {}
                PollOutcome::SlowDown(suggested) => {
                    // The specification says to back off by five seconds;
                    // GitHub also sends a new interval, so honour the larger.
                    interval = interval
                        .saturating_add(Duration::from_secs(5))
                        .max(self.interval_floor.max(Duration::from_secs(suggested)));
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
}
