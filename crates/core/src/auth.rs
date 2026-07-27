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

use crate::github::{ApiError, ErrorCause, GitHub, Installation};

/// The client id of the Airlock Safe GitHub App.
///
/// A client id is not a secret; it identifies the app to GitHub's device flow
/// and appears in the app's own documentation.
pub const AIRLOCK_SAFE_CLIENT_ID: &str = "Iv23liSiShAsRmDUZAsS";

/// The slug of the Airlock Safe GitHub App.
///
/// This is the trust root for `ghu_` tokens. GitHub attests the issuing app on
/// every installation it returns, and Airlock Safe's registration requests no
/// account-level permissions, so an installation list that is entirely Airlock
/// Safe and entirely `read` enumerates the token's whole authority.
pub const AIRLOCK_SAFE_APP_SLUG: &str = "airlock-safe";

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// A stable code naming the refusal.
    pub code: String,
    /// What a human should do about it.
    pub detail: String,
}

impl Refusal {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.detail, self.code)
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
    /// The installations the token can reach, for app user tokens.
    pub installations: Vec<InstallationGrant>,
}

impl VerifiedGrant {
    /// The accounts this credential can see, for diagnosing a 404.
    #[must_use]
    pub fn visible_accounts(&self) -> Vec<String> {
        self.installations
            .iter()
            .filter_map(|installation| installation.account.clone())
            .collect()
    }
}

/// Verify a token before it is used for anything else.
///
/// # Errors
///
/// Returns a [`Refusal`] whenever the grant cannot be enumerated, or when any
/// part of the enumerated grant is not a read.
pub async fn verify<G: GitHub>(token: &str, client: &G) -> Result<VerifiedGrant, Refusal> {
    match TokenKind::classify(token) {
        TokenKind::AppUser => verify_app_user(client).await,
        kind @ (TokenKind::ClassicPat | TokenKind::OAuthUser) => verify_scoped(kind, client).await,
        TokenKind::FineGrainedPat => Err(Refusal::new(
            "unverifiable_fine_grained_pat",
            "GitHub offers no way to enumerate a fine-grained personal access \
             token's permissions, and a write probe would break airlock's \
             read-only contract. Run `airlock auth login` for a credential \
             airlock can verify.",
        )),
        TokenKind::Installation => Err(Refusal::new(
            "unverifiable_installation_token",
            "An installation token carries its permissions only in the \
             response that minted it, which airlock never sees. Run \
             `airlock auth login` for a credential airlock can verify.",
        )),
        TokenKind::Refresh => Err(Refusal::new(
            "refresh_token_supplied",
            "That is a refresh token, not an access token. Run \
             `airlock auth login` to exchange it, or supply the access token.",
        )),
        TokenKind::Unknown => Err(Refusal::new(
            "unverifiable_unknown_token",
            "The token carries no prefix airlock recognises, so its \
             permissions cannot be enumerated. Run `airlock auth login` for a \
             credential airlock can verify.",
        )),
    }
}

async fn verify_app_user<G: GitHub>(client: &G) -> Result<VerifiedGrant, Refusal> {
    let installations = client.user_installations().await.map_err(api_refusal)?;

    if installations.is_empty() {
        return Err(Refusal::new(
            "no_installations",
            "The token's app is not installed on any account this user can \
             reach, so there is nothing for airlock to audit and no permission \
             map to enumerate. Install Airlock Safe on the account that owns \
             the repository.",
        ));
    }

    for installation in &installations {
        if installation.app_slug != AIRLOCK_SAFE_APP_SLUG {
            return Err(Refusal::new(
                "foreign_issuer",
                format!(
                    "The token was issued by `{}`, not `{AIRLOCK_SAFE_APP_SLUG}`. Airlock can \
                     enumerate installation permissions but not account-level ones, so it \
                     accepts app user tokens only from the app whose reviewed registration \
                     requests none. Run `airlock auth login`.",
                    installation.app_slug
                ),
            ));
        }
    }

    for installation in &installations {
        let writes = write_permissions(installation);
        if !writes.is_empty() {
            return Err(Refusal::new(
                "write_permission",
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

    let Some(header) = user.oauth_scopes else {
        // A missing header is not an empty grant. It is an unread one.
        return Err(Refusal::new(
            "missing_scope_header",
            "GitHub did not return an `X-OAuth-Scopes` header, so the token's \
             scopes could not be read. An unreadable grant is unverifiable.",
        ));
    };

    let scopes = parse_scopes(&header)?;
    let allowed: BTreeSet<&str> = READ_ONLY_SCOPES.iter().copied().collect();
    let rejected: Vec<String> = scopes
        .iter()
        .filter(|scope| !allowed.contains(scope.as_str()))
        .cloned()
        .collect();

    if !rejected.is_empty() {
        return Err(Refusal::new(
            "non_read_scope",
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
                "malformed_scope_header",
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
            "rejected_credential",
            "GitHub rejected the credential. Run `airlock auth login`.",
        ),
        ErrorCause::RateLimit => Refusal::new(
            "rate_limited",
            "GitHub rate-limited the verification request, so the credential \
             could not be verified. Try again after the limit resets.",
        ),
        _ => Refusal::new(
            "verification_failed",
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
        assert_eq!(refusal.code, "malformed_scope_header");
    }

    #[test]
    fn write_permissions_are_listed_by_name() {
        let installation = Installation {
            id: 7,
            app_id: 1,
            app_slug: AIRLOCK_SAFE_APP_SLUG.to_owned(),
            account: Some("owner".to_owned()),
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
    fn a_refusal_never_renders_a_token() {
        let refusal = Refusal::new("unverifiable_unknown_token", "no prefix airlock knows");
        assert!(!refusal.to_string().contains("ghu_"));
    }
}
