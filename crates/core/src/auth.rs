//! Credential verification.
//!
//! Airlock is a read-only tool, and it proves that about its credential before
//! it makes a single audit request. The governing rule is positive
//! enumeration: a token is accepted only when its whole grant can be listed
//! and every entry in that list is a read. A token whose permissions cannot be
//! positively enumerated is refused as unverifiable — same refusal path as a
//! write-bearing token, different message.
//!
//! Airlock never reads `GH_TOKEN`, `GITHUB_TOKEN`, the `gh` credential store,
//! or a git credential helper. That separation is deliberate: a tool that
//! refuses write access must not quietly pick up the write-capable credential
//! already sitting in the environment.

use std::collections::BTreeSet;
use std::fmt;

use crate::github::{ApiError, ErrorCause, GitHub, Installation, OAuthScopeHeader};
use crate::rules::CredentialCapability;

/// The client id of the Airlock Safe GitHub App.
///
/// A client id is not a secret; it identifies the app to GitHub's device flow
/// and appears in the app's own documentation.
pub const AIRLOCK_SAFE_CLIENT_ID: &str = "Iv23liSiShAsRmDUZAsS";

/// The slug of the Airlock Safe GitHub App.
///
/// Half of the trust root for `ghu_` tokens, and the mutable half: a slug
/// follows a rename and can later be claimed by a different app. It is checked
/// because it is what a human recognises, never on its own.
pub const AIRLOCK_SAFE_APP_SLUG: &str = "airlock-safe";

/// The numeric id of the Airlock Safe GitHub App.
///
/// The immutable half of the trust root. GitHub attests both `app_id` and
/// `app_slug` on every installation it returns, and only the id survives a
/// rename or a slug being reused, so acceptance is bound to both. Airlock
/// Safe's registration requests no account-level permissions, which is what
/// makes an installation list that is entirely this app and entirely `read` an
/// enumeration of the token's whole authority.
pub const AIRLOCK_SAFE_APP_ID: u64 = 4_409_712;

/// Classic OAuth scopes whose full authority is read-only.
///
/// A closed, reviewed list. Anything not on it — including a scope GitHub adds
/// tomorrow — is unverifiable, because airlock cannot know what a scope it has
/// never seen permits. Scopes such as `public_repo`, `repo:status`,
/// `security_events`, `notifications`, `gist`, `workflow`, and every `write:`
/// or `admin:` scope are deliberately absent: each carries write authority.
pub const READ_ONLY_SCOPES: &[&str] = &[
    "read:audit_log",
    "read:discussion",
    "read:enterprise",
    "read:gpg_key",
    "read:org",
    "read:project",
    "read:public_key",
    "read:repo_hook",
    "read:ssh_signing_key",
    "read:user",
    "user:email",
];

/// What kind of credential a token string is, by prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A GitHub App user access token.
    AppUser,
    /// A classic personal access token.
    ClassicPat,
    /// An OAuth app user token.
    OAuthUser,
    /// A fine-grained personal access token.
    FineGrainedPat,
    /// A GitHub App installation token.
    Installation,
    /// A refresh token.
    Refresh,
    /// Anything else.
    Unknown,
}

/// Whether `token` has the shape of a GitHub token: 8 to 4096 characters,
/// each a letter, a digit, `_`, `-` or `.`.
///
/// Every GitHub token has this alphabet. An installation token, the run's
/// `GITHUB_TOKEN` included, is `ghs_<app id>_<JSON Web Token>` since GitHub's
/// stateless format (rolled out 2026-10-02), so it carries the `.` and `-`
/// of a base64url JWT. Each of these characters is unreserved in JSON, a URL
/// and a form, so any encoding of such a value, escaped once or twice, is the
/// value itself, and a redactor that matches it as written matches it
/// wherever it is echoed.
#[must_use]
pub fn has_token_shape(token: &str) -> bool {
    (8..=4096).contains(&token.len())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

impl TokenKind {
    /// Classify a token by its documented prefix.
    #[must_use]
    pub fn classify(token: &str) -> Self {
        if token.starts_with("ghu_") {
            TokenKind::AppUser
        } else if token.starts_with("ghp_") {
            TokenKind::ClassicPat
        } else if token.starts_with("gho_") {
            TokenKind::OAuthUser
        } else if token.starts_with("github_pat_") {
            TokenKind::FineGrainedPat
        } else if token.starts_with("ghs_") {
            TokenKind::Installation
        } else if token.starts_with("ghr_") {
            TokenKind::Refresh
        } else {
            TokenKind::Unknown
        }
    }

    /// The stable machine-readable name.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            TokenKind::AppUser => "app_user",
            TokenKind::ClassicPat => "classic_pat",
            TokenKind::OAuthUser => "oauth_user",
            TokenKind::FineGrainedPat => "fine_grained_pat",
            TokenKind::Installation => "installation",
            TokenKind::Refresh => "refresh",
            TokenKind::Unknown => "unknown",
        }
    }
}

/// Why a credential was refused.
///
/// A refusal never carries the token, and never hints that airlock might have
/// found a credential elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    UnverifiableFineGrainedPat,
    UnverifiableInstallationToken,
    RefreshTokenSupplied,
    UnverifiableUnknownToken,
    NoInstallations,
    MalformedIssuer,
    ForeignIssuer,
    WritePermission,
    MissingScopeHeader,
    DuplicateScopeHeader,
    NonReadScope,
    MalformedScopeHeader,
    RejectedCredential,
    RateLimited,
    BudgetExhausted,
    VerificationFailed,
    OutsideActions,
    RunUndescribed,
    ForeignRepository,
    WorkflowUnreadable,
    JobNotFound,
    PermissionsUndeclared,
    RunTokenUnbound,
    ForeignInstallationToken,
    NotActionsToken,
    RunTokenUnconfirmed,
    RunRepositoryMismatch,
}

impl RefusalCode {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnverifiableFineGrainedPat => "unverifiable_fine_grained_pat",
            Self::UnverifiableInstallationToken => "unverifiable_installation_token",
            Self::RefreshTokenSupplied => "refresh_token_supplied",
            Self::UnverifiableUnknownToken => "unverifiable_unknown_token",
            Self::NoInstallations => "no_installations",
            Self::MalformedIssuer => "malformed_issuer",
            Self::ForeignIssuer => "foreign_issuer",
            Self::WritePermission => "write_permission",
            Self::MissingScopeHeader => "missing_scope_header",
            Self::DuplicateScopeHeader => "duplicate_scope_header",
            Self::NonReadScope => "non_read_scope",
            Self::MalformedScopeHeader => "malformed_scope_header",
            Self::RejectedCredential => "rejected_credential",
            Self::RateLimited => "rate_limited",
            Self::BudgetExhausted => "budget_exhausted",
            Self::VerificationFailed => "verification_failed",
            Self::OutsideActions => "outside_actions",
            Self::RunUndescribed => "run_undescribed",
            Self::ForeignRepository => "foreign_repository",
            Self::WorkflowUnreadable => "workflow_unreadable",
            Self::JobNotFound => "job_not_found",
            Self::PermissionsUndeclared => "permissions_undeclared",
            Self::RunTokenUnbound => "run_token_unbound",
            Self::ForeignInstallationToken => "foreign_installation_token",
            Self::NotActionsToken => "not_actions_token",
            Self::RunTokenUnconfirmed => "run_token_unconfirmed",
            Self::RunRepositoryMismatch => "run_repository_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// A stable code naming the refusal.
    pub code: RefusalCode,
    /// What a human should do about it.
    pub detail: String,
}

impl Refusal {
    pub(crate) fn new(code: RefusalCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.detail, self.code.code())
    }
}

impl std::error::Error for Refusal {}

/// One installation, reduced to what a grant summary shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationGrant {
    /// The installation id.
    pub id: u64,
    /// The account the app is installed on.
    pub account: Option<String>,
    /// The permissions GitHub attests, as `name=level` pairs.
    pub permissions: Vec<String>,
}

/// A credential whose whole grant has been enumerated and found read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    /// What kind of token it is.
    pub kind: TokenKind,
    /// The app that issued it, for app user tokens.
    pub issuer: Option<String>,
    /// The authenticated login, when the verification path learned one.
    pub login: Option<String>,
    /// The exact scopes GitHub reported, for scope-based tokens.
    pub scopes: Vec<String>,
    /// The installations the token can reach, for app user tokens, and the
    /// one installation an installation token was minted from.
    pub installations: Vec<InstallationGrant>,
    /// The job whose declared permissions are the grant, for the run's own
    /// token in repository mode.
    pub run: Option<RunGrant>,
}

/// The run's own token, enumerated from the job that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunGrant {
    /// `owner/repo` the token was issued for, and the only one it audits.
    pub repository: String,
    /// The workflow file and the commit it was read at, as `path@sha`.
    pub workflow: String,
    /// The job id.
    pub job: String,
    /// The job's declared permissions, as `name=read` pairs; `*=read` for
    /// `read-all`.
    pub permissions: Vec<String>,
}

impl VerifiedGrant {
    /// What the enumerated grant lets this credential do.
    ///
    /// Derived from what GitHub attested, in whichever representation carries
    /// this credential's grant: installation permissions for an app user token,
    /// the scope list for a scoped one. Both are read, so a credential cannot
    /// be classified from a representation that happens to be empty.
    ///
    /// `ReadOnly` is the answer that excuses: it is what lets a rule's declared
    /// disclosure gate turn an undisclosed field into a permanent, non-blocking
    /// gap. So the errors here are not symmetric. Calling a write-capable
    /// credential read-only excuses a field that credential should have been
    /// shown, which converts a real gap into a claim that nobody need look
    /// again; calling a read-only credential write-capable only turns a
    /// permanent gap into a blocking one, which is an honest overstatement of
    /// what a retry might achieve. Every uncertain case therefore resolves to
    /// `WriteCapable`: a scope airlock's reviewed list does not classify as a
    /// read, and a credential whose grant representation cannot be read at all.
    ///
    /// This is the same rule [`verify_scoped`] applies when accepting a token —
    /// a scope it cannot classify as read-only is refused rather than assumed
    /// safe — asked of the capability rather than of admission.
    #[must_use]
    pub fn capability(&self) -> CredentialCapability {
        let read_only_scopes: BTreeSet<&str> = READ_ONLY_SCOPES.iter().copied().collect();
        // Either representation carrying something that is not provably a read
        // settles it, whatever kind of token claims to be presenting it.
        let writes = self.installations.iter().any(|installation| {
            installation
                .permissions
                .iter()
                .any(|permission| !permission.ends_with("=read"))
        }) || self.run.as_ref().is_some_and(|run| {
            run.permissions
                .iter()
                .any(|permission| !permission.ends_with("=read"))
        }) || self
            .scopes
            .iter()
            .any(|scope| !read_only_scopes.contains(scope.as_str()));
        if writes {
            return CredentialCapability::WriteCapable;
        }

        match self.kind {
            // An app user token's grant is its installation permissions, and
            // verification refuses a token whose app is installed nowhere, so
            // an empty list is not an enumerated grant.
            TokenKind::AppUser if !self.installations.is_empty() => CredentialCapability::ReadOnly,
            // An installation token's grant is the job that holds it, in
            // repository mode, or the permissions its minting response listed,
            // in central mode. Without either, nothing was enumerated.
            TokenKind::Installation if self.run.is_some() || !self.installations.is_empty() => {
                CredentialCapability::ReadOnly
            }
            // A scoped token's grant is its scope list, and an empty list is a
            // real answer rather than a missing one: a classic token with no
            // scopes reads public repository data and nothing else.
            TokenKind::ClassicPat | TokenKind::OAuthUser => CredentialCapability::ReadOnly,
            // Nothing left to read the grant from. Excuse nothing.
            _ => CredentialCapability::WriteCapable,
        }
    }

    /// The accounts this credential can see, for diagnosing a 404.
    #[must_use]
    pub fn visible_accounts(&self) -> Vec<String> {
        self.installations
            .iter()
            .filter_map(|installation| installation.account.clone())
            .collect()
    }
}

/// Where a token is being presented, which decides what Airlock may accept.
#[derive(Debug, Clone, Copy)]
pub enum Admission<'a> {
    /// Every surface except the Action's repository mode: the command line,
    /// the stored profile, `auth status`, and the Action given its own
    /// credential.
    Standard,
    /// The Action's repository mode: the run's own `GITHUB_TOKEN`, auditing
    /// the one repository it was issued for.
    Repository {
        /// The run Airlock is executing in.
        run: &'a crate::workflow_token::ActionsRun,
        /// The audited repository's owner.
        owner: &'a str,
        /// The audited repository's name.
        repo: &'a str,
        /// The run's own token, as the workflow handed it over in
        /// `AIRLOCK_RUN_TOKEN`. Never used as a credential: an installation
        /// token is admitted only when it is this token, because the job's
        /// permissions bound no other.
        run_token: Option<&'a str>,
    },
}

/// Verify a token before it is used for anything else.
///
/// # Errors
///
/// Returns a [`Refusal`] whenever the grant cannot be enumerated, or when any
/// part of the enumerated grant is not a read.
pub async fn verify<G: GitHub>(token: &str, client: &G) -> Result<VerifiedGrant, Refusal> {
    verify_for(token, client, Admission::Standard).await
}

/// Verify a token where it is presented.
///
/// Only the token's kind decides whether the admission matters: an
/// installation token is enumerable in repository mode alone, and every other
/// kind is verified the same way everywhere.
///
/// # Errors
///
/// Returns a [`Refusal`] whenever the grant cannot be enumerated, or when any
/// part of the enumerated grant is not a read.
pub async fn verify_for<G: GitHub>(
    token: &str,
    client: &G,
    admission: Admission<'_>,
) -> Result<VerifiedGrant, Refusal> {
    match TokenKind::classify(token) {
        TokenKind::AppUser => verify_app_user(client).await,
        kind @ (TokenKind::ClassicPat | TokenKind::OAuthUser) => verify_scoped(kind, client).await,
        TokenKind::FineGrainedPat => Err(Refusal::new(
            RefusalCode::UnverifiableFineGrainedPat,
            "GitHub offers no way to enumerate a fine-grained personal access \
             token's permissions, and a write probe would break airlock's \
             read-only contract. Run `airlock auth login` for a credential \
             airlock can verify.",
        )),
        TokenKind::Installation => match admission {
            Admission::Repository {
                run,
                owner,
                repo,
                run_token,
            } => {
                bind_to_run(token, run_token)?;
                // Placed by what a caller cannot forge, before any request:
                // the run's token is the GitHub Actions app's.
                crate::workflow_token::check_actions_token_form(token)?;
                crate::workflow_token::verify_run_token(client, run, owner, repo).await
            }
            Admission::Standard => Err(Refusal::new(
                RefusalCode::UnverifiableInstallationToken,
                "An installation token carries its permissions only in the \
                 response that minted it, which airlock never sees. The Airlock \
                 Action accepts one only in repository mode, as the run's own \
                 token. Run `airlock auth login` for a credential airlock can \
                 verify.",
            )),
        },
        TokenKind::Refresh => Err(Refusal::new(
            RefusalCode::RefreshTokenSupplied,
            "That is a refresh token, not an access token. Run \
             `airlock auth login` to exchange it, or supply the access token.",
        )),
        TokenKind::Unknown => Err(Refusal::new(
            RefusalCode::UnverifiableUnknownToken,
            "The token carries no prefix airlock recognises, so its \
             permissions cannot be enumerated. Run `airlock auth login` for a \
             credential airlock can verify.",
        )),
    }
}

/// Require an installation token to be the run's own, compared after both
/// are trimmed, as every credential source trims what it reads.
///
/// The job's declared permissions are the grant of the run's token and of no
/// other, so another installation token judged by them would be judged by
/// permissions that are not its own. Without the run's token to compare with,
/// no installation token is admitted.
fn bind_to_run(token: &str, run_token: Option<&str>) -> Result<(), Refusal> {
    let Some(run_token) = run_token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(Refusal::new(
            RefusalCode::RunTokenUnbound,
            "Repository mode admits an installation token only as the run's own token, and \
             `AIRLOCK_RUN_TOKEN` does not name it. Set `AIRLOCK_RUN_TOKEN` to \
             `${{ github.token }}`; the Airlock Action does this itself.",
        ));
    };
    if constant_time_eq(token.trim().as_bytes(), run_token.as_bytes()) {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusalCode::ForeignInstallationToken,
            "The installation token is not this run's own token. The job's permissions bound \
             only the run's token, so repository mode refuses any other.",
        ))
    }
}

/// Byte equality whose time does not depend on where two equal-length values
/// first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

async fn verify_app_user<G: GitHub>(client: &G) -> Result<VerifiedGrant, Refusal> {
    let installations = client.user_installations().await.map_err(api_refusal)?;

    if installations.is_empty() {
        return Err(Refusal::new(
            RefusalCode::NoInstallations,
            "The token's app is not installed on any account this user can \
             reach, so there is nothing for airlock to audit and no permission \
             map to enumerate. Install Airlock Safe on the account that owns \
             the repository.",
        ));
    }

    for installation in &installations {
        // Both halves, every time. A slug alone follows a rename and can be
        // reclaimed; an id alone tells a human nothing.
        if installation.app_id == 0 {
            return Err(Refusal::new(
                RefusalCode::MalformedIssuer,
                format!(
                    "Installation {} reports app id 0, which is not an app identity airlock can \
                     bind to. An issuer it cannot verify is an issuer it refuses.",
                    installation.id
                ),
            ));
        }
        if installation.app_slug != AIRLOCK_SAFE_APP_SLUG
            || installation.app_id != AIRLOCK_SAFE_APP_ID
        {
            return Err(Refusal::new(
                RefusalCode::ForeignIssuer,
                format!(
                    "The token was issued by `{}` (app id {}), not `{AIRLOCK_SAFE_APP_SLUG}` \
                     (app id {AIRLOCK_SAFE_APP_ID}). Airlock can enumerate installation \
                     permissions but not account-level ones, so it accepts app user tokens only \
                     from the app whose reviewed registration requests none. Run \
                     `airlock auth login`.",
                    installation.app_slug, installation.app_id
                ),
            ));
        }
    }

    for installation in &installations {
        let writes = write_permissions(installation);
        if !writes.is_empty() {
            return Err(Refusal::new(
                RefusalCode::WritePermission,
                format!(
                    "Installation {} on {} carries {}. Airlock refuses any token with write \
                     permission.",
                    installation.id,
                    installation.account.as_deref().unwrap_or("an account"),
                    writes.join(", ")
                ),
            ));
        }
    }

    Ok(VerifiedGrant {
        kind: TokenKind::AppUser,
        issuer: Some(AIRLOCK_SAFE_APP_SLUG.to_owned()),
        login: None,
        scopes: Vec::new(),
        installations: installations
            .iter()
            .map(|installation| InstallationGrant {
                id: installation.id,
                account: installation.account.clone(),
                permissions: installation
                    .permissions
                    .iter()
                    .map(|(name, level)| format!("{name}={level}"))
                    .collect(),
            })
            .collect(),
        run: None,
    })
}

fn write_permissions(installation: &Installation) -> Vec<String> {
    installation
        .permissions
        .iter()
        .filter(|(_, level)| level.as_str() != "read")
        .map(|(name, level)| format!("{name}={level}"))
        .collect()
}

async fn verify_scoped<G: GitHub>(kind: TokenKind, client: &G) -> Result<VerifiedGrant, Refusal> {
    let user = client.authenticated_user().await.map_err(api_refusal)?;

    let header = match &user.oauth_scopes {
        // GitHub sent one header. Its value may be empty, and that is a real
        // answer — see below.
        OAuthScopeHeader::Single(value) => value.clone(),

        // A missing header is not an empty grant. It is an unread one, and
        // brief §3 refuses an unread grant as unverifiable. This is the case a
        // proxy that strips headers produces, and reading it as "no scopes"
        // would accept a `repo`-scoped token that simply lost its header.
        OAuthScopeHeader::Absent => {
            return Err(Refusal::new(
                RefusalCode::MissingScopeHeader,
                "GitHub did not return an `X-OAuth-Scopes` header, so the token's \
                 scopes could not be read. An unreadable grant is unverifiable.",
            ));
        }

        // Two scope headers have no combination rule airlock is willing to
        // invent. Reading whichever arrived first would let a response
        // carrying both a read-only value and `repo` be accepted.
        OAuthScopeHeader::Repeated(values) => {
            return Err(Refusal::new(
                RefusalCode::DuplicateScopeHeader,
                format!(
                    "GitHub returned {} `X-OAuth-Scopes` headers ({}). A grant with more than \
                     one answer is not enumerated, so the token is refused.",
                    values.len(),
                    values
                        .iter()
                        .map(|value| format!("`{value}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    };

    // A present-but-empty header is ACCEPTED, deliberately.
    //
    // `X-OAuth-Scopes: ` is GitHub positively stating that this token holds no
    // scopes at all — the grant is enumerated, and it is empty. A classic
    // token with no scopes can read public repository data and nothing else,
    // which is exactly the authority airlock wants. Refusing it would refuse
    // the most read-only credential of its kind on the grounds that it is too
    // restricted, which inverts the rule.
    //
    // The distinction from an absent header is the whole point: absent means
    // airlock could not read the grant, empty means it read it and there was
    // nothing in it.
    let scopes = parse_scopes(&header)?;
    let allowed: BTreeSet<&str> = READ_ONLY_SCOPES.iter().copied().collect();
    let rejected: Vec<String> = scopes
        .iter()
        .filter(|scope| !allowed.contains(scope.as_str()))
        .cloned()
        .collect();

    if !rejected.is_empty() {
        return Err(Refusal::new(
            RefusalCode::NonReadScope,
            format!(
                "The token carries {}, which airlock's reviewed read-only scope list does not \
                 contain. A scope airlock cannot classify as read-only is refused rather than \
                 assumed safe.",
                rejected.join(", ")
            ),
        ));
    }

    Ok(VerifiedGrant {
        kind,
        issuer: None,
        login: Some(user.login),
        scopes,
        installations: Vec::new(),
        run: None,
    })
}

/// Parse the exact comma-separated scope tokens GitHub returns.
///
/// No substring matching and no prefix inference: a scope is either one of the
/// exact strings on the allowlist or it is unknown.
fn parse_scopes(header: &str) -> Result<Vec<String>, Refusal> {
    let mut scopes = Vec::new();
    for raw in header.split(',') {
        let scope = raw.trim();
        if scope.is_empty() {
            continue;
        }
        if scope.contains(char::is_whitespace) {
            return Err(Refusal::new(
                RefusalCode::MalformedScopeHeader,
                format!("The scope `{scope}` is not a well-formed scope token."),
            ));
        }
        if !scopes.contains(&scope.to_owned()) {
            scopes.push(scope.to_owned());
        }
    }
    scopes.sort();
    Ok(scopes)
}

fn api_refusal(error: ApiError) -> Refusal {
    match error.cause {
        ErrorCause::Unauthenticated => Refusal::new(
            RefusalCode::RejectedCredential,
            "GitHub rejected the credential. Run `airlock auth login`.",
        ),
        ErrorCause::RateLimit => Refusal::new(
            RefusalCode::RateLimited,
            "GitHub rate-limited the verification request, so the credential \
             could not be verified. Try again after the limit resets.",
        ),
        ErrorCause::Budget => Refusal::new(
            RefusalCode::BudgetExhausted,
            format!(
                "The credential could not be verified within airlock's time and size budgets, \
                 so nothing about it was established: {error}"
            ),
        ),
        _ => Refusal::new(
            RefusalCode::VerificationFailed,
            format!("The credential could not be verified: {error}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_prefixes_classify() {
        assert_eq!(TokenKind::classify("ghu_abc"), TokenKind::AppUser);
        assert_eq!(TokenKind::classify("ghp_abc"), TokenKind::ClassicPat);
        assert_eq!(TokenKind::classify("gho_abc"), TokenKind::OAuthUser);
        assert_eq!(
            TokenKind::classify("github_pat_abc"),
            TokenKind::FineGrainedPat
        );
        assert_eq!(TokenKind::classify("ghs_abc"), TokenKind::Installation);
        assert_eq!(TokenKind::classify("ghr_abc"), TokenKind::Refresh);
        assert_eq!(TokenKind::classify("abc"), TokenKind::Unknown);
    }

    #[test]
    fn the_read_only_scope_list_excludes_every_write_bearing_scope() {
        for scope in [
            "repo",
            "public_repo",
            "repo:status",
            "repo_deployment",
            "security_events",
            "admin:org",
            "write:org",
            "admin:repo_hook",
            "write:repo_hook",
            "admin:public_key",
            "write:public_key",
            "admin:org_hook",
            "gist",
            "notifications",
            "user",
            "user:follow",
            "delete_repo",
            "write:discussion",
            "write:packages",
            "read:packages",
            "delete:packages",
            "admin:gpg_key",
            "write:gpg_key",
            "codespace",
            "project",
            "workflow",
            "admin:enterprise",
            "manage_runners:enterprise",
            "manage_billing:enterprise",
            "audit_log",
            "copilot",
            "manage_billing:copilot",
            "admin:ssh_signing_key",
            "write:ssh_signing_key",
        ] {
            assert!(
                !READ_ONLY_SCOPES.contains(&scope),
                "{scope} must not be on the read-only allowlist"
            );
        }
    }

    #[test]
    fn the_read_only_scope_list_is_sorted_and_unique() {
        let mut sorted = READ_ONLY_SCOPES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, READ_ONLY_SCOPES.to_vec());
    }

    #[test]
    fn scopes_parse_as_exact_comma_separated_tokens() {
        assert_eq!(
            parse_scopes("read:org, read:user").unwrap(),
            vec!["read:org".to_owned(), "read:user".to_owned()]
        );
        assert_eq!(parse_scopes("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_scopes("read:org,read:org").unwrap(),
            vec!["read:org".to_owned()]
        );
    }

    #[test]
    fn a_scope_with_whitespace_inside_it_is_malformed() {
        let refusal = parse_scopes("read org").unwrap_err();
        assert_eq!(refusal.code, RefusalCode::MalformedScopeHeader);
    }

    #[test]
    fn a_credentials_capability_is_read_from_its_enumerated_permissions() {
        // Not asserted from "verification passed". A grant carrying a write is
        // write-capable whatever path produced it, and that is what decides
        // whether a disclosure gate explains an absent field.
        let grant = |permissions: &[&str]| VerifiedGrant {
            kind: TokenKind::AppUser,
            issuer: Some(AIRLOCK_SAFE_APP_SLUG.to_owned()),
            login: None,
            scopes: Vec::new(),
            installations: vec![InstallationGrant {
                id: 7,
                account: Some("owner".to_owned()),
                permissions: permissions
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect(),
            }],
            run: None,
        };

        assert_eq!(
            grant(&["metadata=read", "contents=read"]).capability(),
            CredentialCapability::ReadOnly
        );
        assert_eq!(
            grant(&["metadata=read", "contents=write"]).capability(),
            CredentialCapability::WriteCapable
        );
    }

    /// A scoped credential, whose grant is its scope list and whose
    /// installation list is empty.
    fn scoped_grant(kind: TokenKind, scopes: &[&str]) -> VerifiedGrant {
        VerifiedGrant {
            kind,
            issuer: None,
            login: Some("operator".to_owned()),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            installations: Vec::new(),
            run: None,
        }
    }

    #[test]
    fn a_scoped_write_capable_credential_is_not_excused_by_a_disclosure_gate() {
        // The interactive session authorises per launch through the device
        // flow, so this is the credential shape most likely to be write-capable
        // — and the one that must not inherit the audit surface's exemption. A
        // scope the reviewed read-only list does not contain is not a read, so
        // the gate does not explain a field this credential was not shown.
        for scope in ["repo", "public_repo", "admin:org", "write:discussion"] {
            let grant = scoped_grant(TokenKind::ClassicPat, &[scope]);
            assert_eq!(
                grant.capability(),
                CredentialCapability::WriteCapable,
                "{scope}"
            );
            assert!(
                !crate::rules::MERGE_SETTINGS_DISCLOSURE.withholds_from(grant.capability()),
                "{scope} must not be excused by the merge-settings gate"
            );
        }
    }

    #[test]
    fn an_unclassifiable_scope_resolves_to_the_capability_that_excuses_nothing() {
        // Airlock refuses a scope it cannot classify as a read rather than
        // assuming it safe. The capability answer follows the same rule: an
        // unknown scope is not evidence of read-only access, and read-only is
        // the answer that turns a gap into one nobody need look at again.
        let grant = scoped_grant(TokenKind::OAuthUser, &["gist"]);
        assert_eq!(grant.capability(), CredentialCapability::WriteCapable);
    }

    #[test]
    fn a_scoped_read_only_credential_is_read_only_including_an_empty_scope_list() {
        // An empty scope list is an enumerated answer, not a missing one: a
        // classic token with no scopes reads public data and nothing else.
        for scopes in [&["read:org", "user:email"][..], &[][..]] {
            let grant = scoped_grant(TokenKind::ClassicPat, scopes);
            assert_eq!(
                grant.capability(),
                CredentialCapability::ReadOnly,
                "{scopes:?}"
            );
            assert!(
                crate::rules::MERGE_SETTINGS_DISCLOSURE.withholds_from(grant.capability()),
                "{scopes:?} provably cannot hold contents:write"
            );
        }
    }

    #[test]
    fn every_read_only_scope_reads_as_read_only() {
        // The capability derivation and the admission rule share one list, so a
        // scope airlock accepts can never be classified write-capable and a
        // scope it refuses can never be classified read-only.
        for scope in READ_ONLY_SCOPES {
            assert_eq!(
                scoped_grant(TokenKind::ClassicPat, &[scope]).capability(),
                CredentialCapability::ReadOnly,
                "{scope}"
            );
        }
    }

    #[test]
    fn a_grant_with_no_readable_representation_excuses_nothing() {
        // Neither representation carries a grant here. There is nothing to
        // derive read-only access from, so nothing is excused.
        assert_eq!(
            VerifiedGrant {
                kind: TokenKind::AppUser,
                issuer: Some(AIRLOCK_SAFE_APP_SLUG.to_owned()),
                login: None,
                scopes: Vec::new(),
                installations: Vec::new(),
                run: None,
            }
            .capability(),
            CredentialCapability::WriteCapable
        );
    }

    #[test]
    fn an_installation_token_is_read_only_only_where_its_grant_was_enumerated() {
        let run = |permissions: &[&str]| VerifiedGrant {
            kind: TokenKind::Installation,
            issuer: None,
            login: None,
            scopes: Vec::new(),
            installations: Vec::new(),
            run: Some(RunGrant {
                repository: "owner/name".to_owned(),
                workflow: ".github/workflows/audit.yml@0".to_owned(),
                job: "audit".to_owned(),
                permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
            }),
        };
        assert_eq!(
            run(&["contents=read", "actions=read"]).capability(),
            CredentialCapability::ReadOnly
        );
        assert_eq!(
            run(&["contents=read", "issues=write"]).capability(),
            CredentialCapability::WriteCapable
        );

        let unenumerated = VerifiedGrant {
            run: None,
            ..run(&[])
        };
        assert_eq!(
            unenumerated.capability(),
            CredentialCapability::WriteCapable
        );
    }

    #[test]
    fn an_installation_token_is_bound_to_the_run_after_trimming() {
        assert!(bind_to_run("ghs_placeholder_run", Some("ghs_placeholder_run")).is_ok());
        assert!(bind_to_run(" ghs_placeholder_run\n", Some("\tghs_placeholder_run ")).is_ok());
        assert_eq!(
            bind_to_run("ghs_placeholder_other", Some("ghs_placeholder_run"))
                .unwrap_err()
                .code,
            RefusalCode::ForeignInstallationToken
        );
        assert_eq!(
            bind_to_run("ghs_placeholder_run", Some("ghs_placeholder_ru"))
                .unwrap_err()
                .code,
            RefusalCode::ForeignInstallationToken
        );
        for unbound in [None, Some(""), Some("  ")] {
            assert_eq!(
                bind_to_run("ghs_placeholder_run", unbound)
                    .unwrap_err()
                    .code,
                RefusalCode::RunTokenUnbound,
                "{unbound:?}"
            );
        }
    }

    #[test]
    fn a_binding_refusal_never_renders_either_token() {
        for refusal in [
            bind_to_run("ghs_placeholder_other", Some("ghs_placeholder_run")).unwrap_err(),
            bind_to_run("ghs_placeholder_other", None).unwrap_err(),
        ] {
            let rendered = refusal.to_string();
            assert!(!rendered.contains("ghs_placeholder"), "{rendered}");
        }
    }

    #[test]
    fn write_permissions_are_listed_by_name() {
        let installation = Installation {
            id: 7,
            app_id: 1,
            app_slug: AIRLOCK_SAFE_APP_SLUG.to_owned(),
            account: Some("owner".to_owned()),
            account_kind: crate::github::AccountKind::Organization,
            repository_selection: crate::github::RepositorySelection::All,
            permissions: [
                ("metadata".to_owned(), "read".to_owned()),
                ("checks".to_owned(), "write".to_owned()),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(write_permissions(&installation), vec!["checks=write"]);
    }

    #[test]
    fn an_absent_and_an_empty_scope_header_are_different_answers() {
        // Guards the distinction at the type level, so an accidental
        // `Vec`-flattening refactor cannot quietly merge the two again.
        assert_ne!(
            OAuthScopeHeader::Absent,
            OAuthScopeHeader::Single(String::new())
        );
        assert_eq!(parse_scopes("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_refusal_never_renders_a_token() {
        let refusal = Refusal::new(
            RefusalCode::UnverifiableUnknownToken,
            "no prefix airlock knows",
        );
        assert!(!refusal.to_string().contains("ghu_"));
    }
}
