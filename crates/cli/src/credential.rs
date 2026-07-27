//! Choosing the credential an audit will run with.
//!
//! Precedence is fixed and short: what the invocation supplied, then
//! `AIRLOCK_TOKEN`, then the stored profile. Nothing else. Airlock never reads
//! `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential store, or a git credential
//! helper — a tool that refuses write access must not quietly pick up the
//! write-capable credential already sitting in the environment, and it must
//! not hint that it could.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};

use crate::config::{self, Config, Profile, RotationLock};
use crate::device::{DeviceFlow, DeviceFlowConfig};

/// The environment variable airlock reads, and the only one.
pub const TOKEN_ENVIRONMENT_VARIABLE: &str = "AIRLOCK_TOKEN";

/// Where a credential came from, for `auth status` and error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    /// `--token`, which is documented as insecure.
    Flag,
    /// `--token-file`.
    File,
    /// `--token-stdin`.
    Stdin,
    /// The `AIRLOCK_TOKEN` environment variable.
    Environment,
    /// The stored profile, used as it was.
    Profile,
    /// The stored profile, after a refresh.
    RefreshedProfile,
}

impl CredentialSource {
    /// A short description for output.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            CredentialSource::Flag => "--token",
            CredentialSource::File => "--token-file",
            CredentialSource::Stdin => "--token-stdin",
            CredentialSource::Environment => "the AIRLOCK_TOKEN environment variable",
            CredentialSource::Profile => "the stored profile",
            CredentialSource::RefreshedProfile => "the stored profile, refreshed",
        }
    }
}

/// A credential and where it came from.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The token itself. Never printed.
    pub token: String,
    /// Where it came from.
    pub source: CredentialSource,
}

/// What the invocation supplied.
#[derive(Debug, Clone, Default)]
pub struct CredentialInputs {
    /// `--token`.
    pub token: Option<String>,
    /// `--token-file`.
    pub token_file: Option<PathBuf>,
    /// `--token-stdin`.
    pub token_stdin: bool,
    /// `--profile`.
    pub profile: String,
}

/// Which credential source the inputs and environment select, without
/// touching the stored profile.
///
/// `auth status` uses this to say what *would* happen, and the resolver uses
/// it so both agree.
#[must_use]
pub fn selected_source(inputs: &CredentialInputs, environment: Option<&str>) -> CredentialSource {
    if inputs.token.is_some() {
        CredentialSource::Flag
    } else if inputs.token_file.is_some() {
        CredentialSource::File
    } else if inputs.token_stdin {
        CredentialSource::Stdin
    } else if environment.is_some_and(|value| !value.trim().is_empty()) {
        CredentialSource::Environment
    } else {
        CredentialSource::Profile
    }
}

/// Resolve the credential an audit should run with.
///
/// # Errors
///
/// Returns an error when the selected source holds nothing usable, or when a
/// stored credential cannot be refreshed.
pub async fn resolve(
    inputs: &CredentialInputs,
    config_path: &Path,
    login_base: &str,
    client_id: &str,
) -> Result<Credential> {
    match selected_source(inputs, std::env::var("AIRLOCK_TOKEN").ok().as_deref()) {
        CredentialSource::Flag => Ok(Credential {
            token: inputs.token.clone().unwrap_or_default().trim().to_owned(),
            source: CredentialSource::Flag,
        }),
        CredentialSource::File => {
            let path = inputs.token_file.clone().unwrap_or_default();
            Ok(Credential {
                token: config::read_token_file(&path)?,
                source: CredentialSource::File,
            })
        }
        CredentialSource::Stdin => {
            let mut token = String::new();
            std::io::stdin()
                .read_to_string(&mut token)
                .context("cannot read the token from standard input")?;
            let token = token.trim().to_owned();
            if token.is_empty() {
                bail!("standard input carried no token.");
            }
            Ok(Credential {
                token,
                source: CredentialSource::Stdin,
            })
        }
        CredentialSource::Environment => {
            let token = std::env::var(TOKEN_ENVIRONMENT_VARIABLE)
                .unwrap_or_default()
                .trim()
                .to_owned();
            Ok(Credential {
                token,
                source: CredentialSource::Environment,
            })
        }
        CredentialSource::Profile | CredentialSource::RefreshedProfile => {
            from_profile(&inputs.profile, config_path, login_base, client_id).await
        }
    }
}

async fn from_profile(
    profile_name: &str,
    config_path: &Path,
    login_base: &str,
    client_id: &str,
) -> Result<Credential> {
    let config = config::load(config_path)?;
    let Some(profile) = config.profile(profile_name).cloned() else {
        bail!(
            "no credential. Airlock reads --token, --token-file, --token-stdin, then \
             {TOKEN_ENVIRONMENT_VARIABLE}, then the `{profile_name}` profile — and nothing else. \
             Run `airlock auth login`."
        );
    };

    if profile.access_token_is_fresh(config::now_epoch_seconds()) {
        return Ok(Credential {
            token: profile.access_token.clone().unwrap_or_default(),
            source: CredentialSource::Profile,
        });
    }

    let Some(refresh_token) = profile.refresh_token.clone() else {
        bail!(
            "the `{profile_name}` profile's access token has expired and it carries no refresh \
             token. Run `airlock auth login`."
        );
    };

    // Rotation invalidates both previous tokens the moment it succeeds, so it
    // happens under a lock and the result is stored before it is used.
    let _lock = RotationLock::acquire(config_path, profile_name)?;

    // Another process may have rotated while this one waited for the lock.
    let config = config::load(config_path)?;
    if let Some(current) = config.profile(profile_name) {
        if current.access_token_is_fresh(config::now_epoch_seconds()) {
            return Ok(Credential {
                token: current.access_token.clone().unwrap_or_default(),
                source: CredentialSource::Profile,
            });
        }
    }

    // Refreshing happens before the bounded REST client exists, so this is
    // the client that has to carry the timeouts on that path.
    let flow = DeviceFlow::new(
        client_id,
        DeviceFlowConfig {
            base_url: login_base.to_owned(),
            interval_floor: Duration::from_secs(0),
            ..DeviceFlowConfig::default()
        },
    )?;
    let grant = flow.refresh(&refresh_token).await.with_context(|| {
        format!(
            "the `{profile_name}` profile could not be refreshed. Run `airlock auth login` to \
             authorise again."
        )
    })?;

    let mut config = config;
    let stored = store_grant(&mut config, profile_name, &grant, profile.login.clone());
    config::store(config_path, &config)?;

    Ok(Credential {
        token: stored,
        source: CredentialSource::RefreshedProfile,
    })
}

/// Record a grant in a profile, returning the access token it stored.
pub fn store_grant(
    config: &mut Config,
    profile_name: &str,
    grant: &crate::device::TokenGrant,
    login: Option<String>,
) -> String {
    let expires_at = grant
        .expires_in
        .map(|expires_in| config::now_epoch_seconds() + expires_in);
    config.profiles.insert(
        profile_name.to_owned(),
        Profile {
            access_token: Some(grant.access_token.clone()),
            access_token_expires_at: expires_at,
            refresh_token: grant.refresh_token.clone(),
            login,
        },
    );
    grant.access_token.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::TokenGrant;

    fn inputs() -> CredentialInputs {
        CredentialInputs {
            profile: config::DEFAULT_PROFILE.to_owned(),
            ..CredentialInputs::default()
        }
    }

    #[test]
    fn explicit_inputs_outrank_the_environment() {
        let mut supplied = inputs();
        supplied.token = Some("ghu_flag".to_owned());
        assert_eq!(
            selected_source(&supplied, Some("ghu_env")),
            CredentialSource::Flag
        );

        let mut supplied = inputs();
        supplied.token_file = Some(PathBuf::from("/tmp/token"));
        assert_eq!(
            selected_source(&supplied, Some("ghu_env")),
            CredentialSource::File
        );

        let mut supplied = inputs();
        supplied.token_stdin = true;
        assert_eq!(
            selected_source(&supplied, Some("ghu_env")),
            CredentialSource::Stdin
        );
    }

    #[test]
    fn the_environment_outranks_the_stored_profile() {
        assert_eq!(
            selected_source(&inputs(), Some("ghu_env")),
            CredentialSource::Environment
        );
    }

    #[test]
    fn an_empty_environment_variable_is_not_a_credential() {
        assert_eq!(
            selected_source(&inputs(), Some("   ")),
            CredentialSource::Profile
        );
        assert_eq!(selected_source(&inputs(), None), CredentialSource::Profile);
    }

    #[test]
    fn a_grant_is_stored_with_its_expiry_and_refresh_token() {
        let mut config = Config::default();
        let grant = TokenGrant {
            access_token: "ghu_new".to_owned(),
            expires_in: Some(28_800),
            refresh_token: Some("ghr_new".to_owned()),
            refresh_token_expires_in: Some(15_897_600),
        };
        let stored = store_grant(&mut config, "default", &grant, Some("user".to_owned()));
        assert_eq!(stored, "ghu_new");
        let profile = config.profile("default").unwrap();
        assert_eq!(profile.refresh_token.as_deref(), Some("ghr_new"));
        assert!(profile.access_token_is_fresh(config::now_epoch_seconds()));
    }

    #[tokio::test]
    async fn a_profile_that_does_not_exist_names_the_whole_precedence_list() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let error = from_profile("default", &path, "http://127.0.0.1:1", "Iv1")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("AIRLOCK_TOKEN"));
        assert!(error.contains("airlock auth login"));
        // The message must not advertise credentials airlock refuses to read.
        assert!(!error.contains("GH_TOKEN"));
        assert!(!error.contains("GITHUB_TOKEN"));
    }
}
