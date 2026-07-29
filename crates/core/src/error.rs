//! The typed error surface of `airlock-core`.
//!
//! Core returns typed errors so the command line front end can map them onto
//! exit codes and remediation text without matching on message strings.

use std::path::PathBuf;

use crate::auth::Refusal;
use crate::github::ApiError;

/// The result type used throughout `airlock-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong during an audit run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A policy could not be resolved, parsed, or validated.
    #[error("policy error: {0}")]
    Policy(String),

    /// A credential was rejected, or could not be positively enumerated.
    ///
    /// Airlock refuses any token that carries write permission, and refuses a
    /// token whose permissions cannot be enumerated at all.
    #[error("credential refused: {0}")]
    Credential(Refusal),

    /// The GitHub API was reachable but the request could not be completed.
    #[error("github api error: {message}")]
    GitHub {
        api_error: Box<ApiError>,
        message: String,
    },

    /// A local working tree could not serve as an observation source.
    #[error("working tree error: {0}")]
    WorkingTree(String),

    /// A file on disk could not be read.
    #[error("failed to access {path}: {source}")]
    Io {
        /// The path that could not be accessed.
        path: PathBuf,
        /// The underlying operating system error.
        source: std::io::Error,
    },
}

impl Error {
    #[must_use]
    pub fn github(&self) -> Option<&ApiError> {
        match self {
            Self::GitHub { api_error, .. } => Some(api_error),
            _ => None,
        }
    }

    #[must_use]
    pub fn credential_refusal(&self) -> Option<&Refusal> {
        match self {
            Self::Credential(refusal) => Some(refusal),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_error_names_its_cause() {
        let error = Error::Policy("unknown check id REPO-NOPE-01".to_owned());
        assert_eq!(
            error.to_string(),
            "policy error: unknown check id REPO-NOPE-01"
        );
    }

    #[test]
    fn io_error_names_the_path() {
        let error = Error::Io {
            path: PathBuf::from("policy.yml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        assert!(error
            .to_string()
            .starts_with("failed to access policy.yml:"));
    }

    #[test]
    fn alternate_rendering_does_not_repeat_the_structured_github_error() {
        let api = ApiError::local(
            crate::github::ErrorCause::Transport,
            "repos/owner/repository",
            "connection failed",
        );
        let message = api.to_string();
        let error = Error::GitHub {
            api_error: Box::new(api),
            message: message.clone(),
        };

        assert_eq!(
            format!("{:#}", anyhow::Error::new(error)),
            format!("github api error: {message}")
        );
    }
}
