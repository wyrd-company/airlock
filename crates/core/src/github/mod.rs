//! The GitHub API client.
//!
//! Access sits behind a trait so checks can be exercised against recorded
//! fixtures without a network. Airlock speaks REST directly and never shells
//! out to `git` or `gh`.
//!
//! Response classification lives in [`classify`] and nowhere else:
//! authentication failures, rate limiting, plan limitations, permission gaps,
//! and the ambiguous "not found or not visible" case are each distinguished
//! once, so every check inherits the same interpretation.

pub mod classify;
mod client;

use std::collections::BTreeMap;
use std::fmt;

pub use classify::{ErrorCause, MESSAGE_HINTS_VERSION};
pub use client::{RestClient, RestClientConfig};

/// A failed GitHub API call, with every diagnostic that is safe to keep.
///
/// Credentials never appear here. Request identifiers and documentation links
/// do, because they are what makes a failure reproducible with GitHub support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The classified cause.
    pub cause: ErrorCause,
    /// The endpoint that failed, as a path template with the target
    /// interpolated — never a full URL with query parameters.
    pub endpoint: String,
    /// HTTP status, when there was a response.
    pub status: Option<u16>,
    /// The `message` field of the response body, when there was one.
    pub message: Option<String>,
    /// The `documentation_url` field of the response body, when there was one.
    pub documentation_url: Option<String>,
    /// The `X-Accepted-GitHub-Permissions` header, when GitHub named what the
    /// endpoint required.
    pub accepted_permissions: Option<String>,
    /// The `X-GitHub-Request-Id` header, for support escalation.
    pub request_id: Option<String>,
}

impl ApiError {
    /// A failure that never reached GitHub, or whose response was unreadable.
    #[must_use]
    pub fn local(
        cause: ErrorCause,
        endpoint: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            cause,
            endpoint: endpoint.into(),
            status: None,
            message: Some(message.into()),
            documentation_url: None,
            accepted_permissions: None,
            request_id: None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} on {}", self.cause.code(), self.endpoint)?;
        if let Some(status) = self.status {
            write!(formatter, " (http {status})")?;
        }
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        if let Some(permissions) = &self.accepted_permissions {
            write!(formatter, " [endpoint accepts: {permissions}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// The result of a GitHub call.
pub type ApiResult<T> = Result<T, ApiError>;

/// A listing, and whether airlock saw all of it.
///
/// GitHub paginates. A caller asserting something about a *whole* collection —
/// "no tag carries a `v` prefix", "no organisation ruleset covers this branch"
/// — cannot conclude anything from a prefix, so the page budget travels with
/// the items rather than being discarded at the client boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paged<T> {
    /// The items airlock collected.
    pub items: Vec<T>,
    /// True when the walk stopped at a budget rather than at the last page.
    pub truncated: bool,
}

impl<T> Paged<T> {
    /// A complete listing.
    #[must_use]
    pub fn complete(items: Vec<T>) -> Self {
        Self {
            items,
            truncated: false,
        }
    }

    /// How many items were collected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether nothing was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate the collected items.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }
}

/// A repository, as the settings snapshot sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// `owner/name`.
    pub full_name: String,
    /// The numeric repository id.
    pub id: u64,
    /// The owner login.
    pub owner: String,
    /// The repository name.
    pub name: String,
    /// The default branch name.
    pub default_branch: String,
    /// `public`, `private`, or `internal`.
    pub visibility: String,
    /// The declared description, if any.
    pub description: Option<String>,
    /// SPDX identifier of the detected license, if any.
    pub license_spdx: Option<String>,
    /// Whether merge commits are allowed.
    pub allow_merge_commit: bool,
    /// Whether squash merges are allowed.
    pub allow_squash_merge: bool,
    /// Whether rebase merges are allowed.
    pub allow_rebase_merge: bool,
    /// Whether head branches are deleted on merge.
    pub delete_branch_on_merge: bool,
    /// Whether the wiki is enabled.
    pub has_wiki: bool,
    /// Whether projects are enabled.
    pub has_projects: bool,
    /// Whether discussions are enabled.
    pub has_discussions: bool,
    /// Whether issues are enabled.
    pub has_issues: bool,
    /// The `Date` header of the response the settings came from, so a reader
    /// knows the settings snapshot is a different moment from the git one.
    pub observed_at: Option<String>,
}

/// What a git tree entry is.
///
/// The distinction matters: a symlink is not a file, a submodule is not a
/// directory, and a check that conflates them can be talked into a wrong
/// answer by the repository it is auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    Blob,
    /// An executable file.
    ExecutableBlob,
    /// A symbolic link. The blob payload is the link target.
    Symlink,
    /// A directory.
    Tree,
    /// A gitlink to another repository.
    Submodule,
}

impl EntryKind {
    /// The git tree mode this kind corresponds to.
    #[must_use]
    pub fn from_mode(mode: &str) -> Option<Self> {
        match mode {
            "100644" => Some(EntryKind::Blob),
            "100755" => Some(EntryKind::ExecutableBlob),
            "120000" => Some(EntryKind::Symlink),
            "040000" | "40000" => Some(EntryKind::Tree),
            "160000" => Some(EntryKind::Submodule),
            _ => None,
        }
    }

    /// Whether the entry holds file content airlock may read.
    #[must_use]
    pub fn is_file(self) -> bool {
        matches!(self, EntryKind::Blob | EntryKind::ExecutableBlob)
    }
}

/// One entry in a recursive git tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Path relative to the repository root.
    pub path: String,
    /// What the entry is.
    pub kind: EntryKind,
    /// The raw git mode, preserved for evidence.
    pub mode: String,
    /// The object sha.
    pub sha: String,
    /// Size in bytes, for blobs.
    pub size: Option<u64>,
}

/// A recursive git tree at one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// The tree entries.
    pub entries: Vec<TreeEntry>,
    /// Whether GitHub truncated the listing.
    pub truncated: bool,
}

/// A GitHub App installation the credential can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    /// The installation id.
    pub id: u64,
    /// The id of the app that owns the installation.
    pub app_id: u64,
    /// The slug of the app that owns the installation.
    pub app_slug: String,
    /// The account the app is installed on.
    pub account: Option<String>,
    /// The permission map GitHub attests for this installation.
    pub permissions: BTreeMap<String, String>,
}

/// The authenticated user, plus the scope header that came back with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    /// The login.
    pub login: String,
    /// What the response said about the token's scopes.
    pub oauth_scopes: OAuthScopeHeader,
}

/// What a response said about `X-OAuth-Scopes`.
///
/// Three distinct answers that a `Vec<String>` collapses into shapes a reader
/// has to decode: no header at all, one header (whose value may legitimately
/// be empty), and more than one header. They lead to different decisions, so
/// they are different variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthScopeHeader {
    /// GitHub sent no `X-OAuth-Scopes` header.
    ///
    /// Not an empty grant — an unread one.
    Absent,
    /// GitHub sent exactly one header, carrying this raw value.
    ///
    /// The value may be the empty string, which is a real and different answer
    /// from the header being absent: it is GitHub stating that this token
    /// holds no scopes.
    Single(String),
    /// GitHub sent the header more than once.
    ///
    /// A grant with more than one answer is not enumerated.
    Repeated(Vec<String>),
}

impl OAuthScopeHeader {
    /// Read the header out of the values a response carried.
    #[must_use]
    pub fn from_values(values: &[String]) -> Self {
        match values {
            [] => OAuthScopeHeader::Absent,
            [only] => OAuthScopeHeader::Single(only.clone()),
            many => OAuthScopeHeader::Repeated(many.to_vec()),
        }
    }
}

/// One commit, reduced to what a history scan needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSummary {
    /// The commit sha.
    pub sha: String,
    /// How many parents the commit has. Two or more means a merge.
    pub parents: usize,
}

/// A tag reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRef {
    /// The tag name, with `refs/tags/` stripped.
    pub name: String,
    /// The object the tag points at.
    pub sha: String,
}

/// A repository ruleset, including ones inherited from the organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// The ruleset id.
    pub id: u64,
    /// The ruleset name.
    pub name: String,
    /// `branch` or `tag`.
    pub target: Option<String>,
    /// `Repository` or `Organization`.
    pub source_type: Option<String>,
    /// The account or repository the ruleset comes from.
    pub source: Option<String>,
    /// `active`, `evaluate`, or `disabled`.
    pub enforcement: Option<String>,
}

/// One effective rule on a branch.
#[derive(Debug, Clone, PartialEq)]
pub struct BranchRule {
    /// The rule type, for example `pull_request`.
    pub rule_type: String,
    /// Where the rule comes from.
    pub source_type: Option<String>,
    /// The rule parameters, verbatim.
    pub parameters: serde_json::Value,
}

/// The read-only GitHub surface airlock needs.
///
/// Every method is a read. There is deliberately no write anywhere in the
/// trait: a check cannot mutate a repository even by mistake.
// Async functions in traits are enough here: airlock never needs a boxed
// `dyn GitHub`, every consumer is generic over the implementation.
#[allow(async_fn_in_trait)]
pub trait GitHub {
    /// Fetch the repository settings snapshot.
    async fn repository(&self, owner: &str, repo: &str) -> ApiResult<Repository>;

    /// Fetch the declared repository topics.
    async fn topics(&self, owner: &str, repo: &str) -> ApiResult<Vec<String>>;

    /// Resolve a branch name, tag, or sha to a commit sha.
    async fn resolve_commit(&self, owner: &str, repo: &str, reference: &str) -> ApiResult<String>;

    /// Fetch the recursive tree at a commit.
    async fn tree(&self, owner: &str, repo: &str, commit: &str) -> ApiResult<Tree>;

    /// Fetch a blob's bytes by object sha.
    async fn blob(&self, owner: &str, repo: &str, sha: &str) -> ApiResult<Vec<u8>>;

    /// List tags, bounded by the client's page budget.
    async fn tags(&self, owner: &str, repo: &str) -> ApiResult<Paged<TagRef>>;

    /// Walk history from a commit, bounded by the page and commit budgets.
    async fn history(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
        max_commits: usize,
    ) -> ApiResult<Paged<CommitSummary>>;

    /// List rulesets covering the repository, including inherited ones.
    async fn rulesets(&self, owner: &str, repo: &str) -> ApiResult<Paged<Ruleset>>;

    /// List the effective rules on a branch.
    async fn branch_rules(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ApiResult<Paged<BranchRule>>;

    /// List every installation the credential can see, across every page.
    async fn user_installations(&self) -> ApiResult<Vec<Installation>>;

    /// Fetch the authenticated user and the scope header GitHub returned.
    async fn authenticated_user(&self) -> ApiResult<AuthenticatedUser>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_modes_map_to_entry_kinds() {
        assert_eq!(EntryKind::from_mode("100644"), Some(EntryKind::Blob));
        assert_eq!(EntryKind::from_mode("120000"), Some(EntryKind::Symlink));
        assert_eq!(EntryKind::from_mode("040000"), Some(EntryKind::Tree));
        assert_eq!(EntryKind::from_mode("160000"), Some(EntryKind::Submodule));
        assert_eq!(
            EntryKind::from_mode("100755"),
            Some(EntryKind::ExecutableBlob)
        );
        assert_eq!(EntryKind::from_mode("777777"), None);
    }

    #[test]
    fn only_blobs_hold_readable_file_content() {
        assert!(EntryKind::Blob.is_file());
        assert!(EntryKind::ExecutableBlob.is_file());
        assert!(!EntryKind::Symlink.is_file());
        assert!(!EntryKind::Tree.is_file());
        assert!(!EntryKind::Submodule.is_file());
    }

    #[test]
    fn api_errors_render_without_a_credential() {
        let error = ApiError {
            cause: ErrorCause::Permission,
            endpoint: "GET /repos/owner/name/rulesets".to_owned(),
            status: Some(403),
            message: Some("Resource not accessible by integration".to_owned()),
            documentation_url: None,
            accepted_permissions: Some("administration=read".to_owned()),
            request_id: Some("ABCD:1234".to_owned()),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("permission"));
        assert!(rendered.contains("administration=read"));
        assert!(!rendered.contains("ghu_"));
    }
}
