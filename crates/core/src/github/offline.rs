//! The offline GitHub client.
//!
//! A credential-less, network-less implementation of [`GitHub`] for runs
//! whose file observation comes from a local working tree. Every call
//! answers with the same refusal: the fact lives on the API and this run
//! had no credential. Nothing here ever fabricates platform state, so
//! nothing read through it can pass a check.

use super::{
    ApiError, ApiResult, AuthenticatedUser, BranchRule, CommitSummary, ErrorCause, GitHub,
    Installation, Paged, Repository, Ruleset, TagRef, Tree,
};

/// A [`GitHub`] implementation with no credential and no network.
#[derive(Debug, Clone, Copy, Default)]
pub struct Offline;

fn refusal(subject: &str) -> ApiError {
    ApiError::local(
        ErrorCause::Unauthenticated,
        format!("local://not-observed/{subject}"),
        format!(
            "{subject} live on the GitHub API and this run had no credential, so they were not \
             observed"
        ),
    )
}

impl GitHub for Offline {
    async fn repository(&self, _owner: &str, _repo: &str) -> ApiResult<Repository> {
        Err(refusal("repository settings"))
    }

    async fn topics(&self, _owner: &str, _repo: &str) -> ApiResult<Vec<String>> {
        Err(refusal("topics"))
    }

    async fn resolve_commit(
        &self,
        _owner: &str,
        _repo: &str,
        _reference: &str,
    ) -> ApiResult<String> {
        Err(refusal("commits"))
    }

    async fn tree(&self, _owner: &str, _repo: &str, _commit: &str) -> ApiResult<Tree> {
        Err(refusal("trees"))
    }

    async fn blob(&self, _owner: &str, _repo: &str, _sha: &str) -> ApiResult<Vec<u8>> {
        Err(refusal("blobs"))
    }

    async fn tags(&self, _owner: &str, _repo: &str) -> ApiResult<Paged<TagRef>> {
        Err(refusal("tags"))
    }

    async fn history(
        &self,
        _owner: &str,
        _repo: &str,
        _commit: &str,
        _max_commits: usize,
    ) -> ApiResult<Paged<CommitSummary>> {
        Err(refusal("history"))
    }

    async fn rulesets(&self, _owner: &str, _repo: &str) -> ApiResult<Paged<Ruleset>> {
        Err(refusal("rulesets"))
    }

    async fn branch_rules(
        &self,
        _owner: &str,
        _repo: &str,
        _branch: &str,
    ) -> ApiResult<Paged<BranchRule>> {
        Err(refusal("branch rules"))
    }

    async fn user_installations(&self) -> ApiResult<Vec<Installation>> {
        Err(refusal("installations"))
    }

    async fn authenticated_user(&self) -> ApiResult<AuthenticatedUser> {
        Err(refusal("the authenticated user"))
    }
}
