//! The central run: one report for every repository Airlock Safe reaches.
//!
//! The installation token minted in [`crate::central`] lists the
//! repositories its installation reaches. Each one is audited with the
//! organization's policy, through its own client, so one repository's budget
//! is not another's. The result is one document. Its outcome is the worst
//! repository's, and a listing Airlock could not walk to the end makes the
//! whole run incomplete, because a repository it did not see is not one it
//! audited.

use std::fmt::Write as _;

use serde::Serialize;

use crate::audit::{self, AuditOptions};
use crate::auth::{AIRLOCK_SAFE_APP_ID, AIRLOCK_SAFE_APP_SLUG};
use crate::central::CentralSession;
use crate::findings::{AuditResult, Report};
use crate::github::{GitHub, RestClient, RestClientConfig};
use crate::policy::{self, PolicySource};
use crate::render;
use crate::{Error, Result};

/// The central report's schema version.
pub const CENTRAL_SCHEMA_VERSION: u32 = 1;

/// The credential the central run used, as it was verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CentralCredential {
    /// The App's slug.
    pub app_slug: String,
    /// The App's id.
    pub app_id: u64,
    /// The owner's installation.
    pub installation_id: u64,
    /// The permissions the minting response listed, as `name=read`.
    pub permissions: Vec<String>,
    /// When the token expires, as GitHub stated it.
    pub expires_at: Option<String>,
}

/// One repository's part of the central report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RepositoryResult {
    /// `owner/name`.
    pub repository: String,
    /// The repository's outcome.
    pub outcome: AuditResult,
    /// The repository's full report, when the audit ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
    /// Why the audit could not run, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Counts over the repositories.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CentralSummary {
    /// Repositories the installation reaches, as GitHub counted them.
    pub reached: u64,
    /// Repositories audited conformant.
    pub conformant: usize,
    /// Repositories with a blocking gap.
    pub nonconformant: usize,
    /// Repositories whose audit did not complete.
    pub incomplete: usize,
}

/// The central run's one report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CentralReport {
    /// [`CENTRAL_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Always `central`.
    pub mode: &'static str,
    /// The Airlock version that ran.
    pub airlock_version: String,
    /// The account whose repositories were audited.
    pub owner: String,
    /// The credential, as verified.
    pub credential: CentralCredential,
    /// The policy every repository was audited against.
    pub policy: String,
    /// Each repository, in name order.
    pub repositories: Vec<RepositoryResult>,
    /// What stopped the run from covering every repository.
    pub run_errors: Vec<String>,
    /// Counts.
    pub summary: CentralSummary,
    /// Whether every repository was reached and audited to the end.
    pub complete: bool,
    /// The worst outcome: incomplete over nonconformant over conformant.
    pub outcome: AuditResult,
}

impl CentralReport {
    /// The exit code: 0 conformant, 1 a blocking gap, 2 incomplete.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.outcome.exit_code()
    }

    /// The report as text: a header, then each repository's own report.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Central audit of {} as {} (installation {}): {}",
            self.owner,
            self.credential.app_slug,
            self.credential.installation_id,
            self.outcome.code()
        );
        let _ = writeln!(
            out,
            "{} reached, {} conformant, {} nonconformant, {} incomplete",
            self.summary.reached,
            self.summary.conformant,
            self.summary.nonconformant,
            self.summary.incomplete
        );
        for error in &self.run_errors {
            let _ = writeln!(out, "run error: {error}");
        }
        for result in &self.repositories {
            let _ = writeln!(out);
            let _ = writeln!(out, "== {} ({})", result.repository, result.outcome.code());
            if let Some(report) = &result.report {
                out.push_str(&render::report_text(report));
            }
            if let Some(error) = &result.error {
                let _ = writeln!(out, "not audited: {error}");
            }
        }
        out
    }
}

/// Audit every repository the session's installation reaches.
///
/// # Errors
///
/// Returns an error when the client cannot be built or the policy cannot be
/// resolved, before any repository is audited. A repository that cannot be
/// audited is recorded in the report instead.
pub async fn run(
    session: &CentralSession,
    owner: &str,
    client_config: &RestClientConfig,
    policy_source: Option<PolicySource>,
    options: &AuditOptions,
) -> Result<CentralReport> {
    let client = |config: &RestClientConfig| {
        RestClient::new(session.token().to_owned(), config.clone()).map_err(|api_error| {
            Error::GitHub {
                message: api_error.to_string(),
                api_error: Box::new(api_error),
            }
        })
    };

    let lister = client(client_config)?;
    let source = policy_source.unwrap_or_else(|| PolicySource::default_for_owner(owner));
    let policy = policy::resolve(&lister, &source, &options.limits).await?;

    let mut run_errors = Vec::new();
    let mut repositories = Vec::new();
    let mut reached = 0;
    match lister.token_repositories().await {
        Err(error) => run_errors.push(format!(
            "the repositories the installation reaches could not be listed: {error}"
        )),
        Ok(listing) => {
            reached = listing.total_count;
            if listing.truncated {
                run_errors.push(format!(
                    "the listing stopped at the page budget after {} of {} repositories, so \
                     the rest were not audited",
                    listing.repositories.len(),
                    listing.total_count
                ));
            }
            if listing.repositories.is_empty() && !listing.truncated {
                run_errors.push(
                    "the installation reaches no repository, so nothing was audited".to_owned(),
                );
            }
            repositories = listing.repositories;
        }
    }
    repositories.sort_by(|a, b| a.full_name.cmp(&b.full_name));

    let mut results = Vec::new();
    for repository in &repositories {
        let result = match client(client_config) {
            Err(error) => Err(error),
            Ok(client) => {
                audit::run(
                    &client,
                    &repository.owner,
                    &repository.name,
                    &policy,
                    options,
                    Some(&session.grant),
                )
                .await
            }
        };
        results.push(match result {
            Ok(report) => RepositoryResult {
                repository: repository.full_name.clone(),
                outcome: report.outcome,
                report: Some(report),
                error: None,
            },
            Err(error) => RepositoryResult {
                repository: repository.full_name.clone(),
                outcome: AuditResult::Incomplete,
                report: None,
                error: Some(error.to_string()),
            },
        });
    }

    let mut summary = CentralSummary {
        reached,
        ..CentralSummary::default()
    };
    for result in &results {
        match result.outcome {
            AuditResult::Conformant => summary.conformant += 1,
            AuditResult::Nonconformant => summary.nonconformant += 1,
            AuditResult::Incomplete => summary.incomplete += 1,
        }
    }
    let outcome = if !run_errors.is_empty() || summary.incomplete > 0 {
        AuditResult::Incomplete
    } else if summary.nonconformant > 0 {
        AuditResult::Nonconformant
    } else {
        AuditResult::Conformant
    };

    let installation = session.grant.installations.first();
    Ok(CentralReport {
        schema_version: CENTRAL_SCHEMA_VERSION,
        mode: "central",
        airlock_version: options.version.clone(),
        owner: owner.to_owned(),
        credential: CentralCredential {
            app_slug: AIRLOCK_SAFE_APP_SLUG.to_owned(),
            app_id: AIRLOCK_SAFE_APP_ID,
            installation_id: session.installation_id,
            permissions: installation
                .map(|installation| installation.permissions.clone())
                .unwrap_or_default(),
            expires_at: session.expires_at.clone(),
        },
        policy: source.label(),
        complete: outcome != AuditResult::Incomplete,
        repositories: results,
        run_errors,
        summary,
        outcome,
    })
}
