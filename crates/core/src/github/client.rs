//! The REST implementation of [`GitHub`].

// `ApiError` is deliberately wide: it carries the status, GitHub's message and
// documentation link, the accepted-permissions header, and the request id,
// because a failure that cannot be reproduced with GitHub support is a failure
// that wastes someone's afternoon. Boxing it would trade that clarity for a
// pointer chase on a path that has just done network I/O.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::Value;

use super::classify::{self, ErrorCause, Response};
use super::{
    ApiError, ApiResult, AuthenticatedUser, BranchRule, CommitSummary, EntryKind, GitHub,
    Installation, Repository, Ruleset, TagRef, Tree, TreeEntry,
};

/// Everything in a path segment that is not unreserved gets escaped. Git path
/// bytes are arbitrary, so nothing is interpolated raw.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\')
    .add(b'+')
    .add(b'&')
    .add(b'=')
    .add(b';')
    .add(b':')
    .add(b'@')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|');

/// Percent-encode one path segment.
#[must_use]
pub fn encode_segment(segment: &str) -> String {
    utf8_percent_encode(segment, PATH_SEGMENT).to_string()
}

/// How the REST client behaves.
#[derive(Debug, Clone)]
pub struct RestClientConfig {
    /// API root, without a trailing slash. Overridden in tests.
    pub base_url: String,
    /// The `User-Agent` airlock identifies itself with.
    pub user_agent: String,
    /// Largest number of pages one listing may walk.
    pub max_pages: usize,
    /// How many times a rate-limited request may be retried.
    pub max_rate_limit_retries: usize,
    /// The longest airlock will wait for a rate limit to reset, in seconds.
    pub max_rate_limit_wait_seconds: u64,
}

impl Default for RestClientConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.github.com".to_owned(),
            user_agent: concat!("airlock/", env!("CARGO_PKG_VERSION")).to_owned(),
            max_pages: 20,
            max_rate_limit_retries: 2,
            max_rate_limit_wait_seconds: 60,
        }
    }
}

/// A GitHub REST client bound to one credential.
pub struct RestClient {
    http: reqwest::Client,
    token: String,
    config: RestClientConfig,
}

impl std::fmt::Debug for RestClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is deliberately absent. A debug print of a client must
        // never be the thing that leaks a credential into a log.
        formatter
            .debug_struct("RestClient")
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

/// One response, reduced to what the client and the classifier need.
struct RawResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

impl RestClient {
    /// Build a client for `token`.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying HTTP stack cannot be built.
    pub fn new(token: impl Into<String>, config: RestClientConfig) -> ApiResult<Self> {
        let http = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .build()
            .map_err(|error| ApiError::local(ErrorCause::Transport, "client", error.to_string()))?;
        Ok(Self {
            http,
            token: token.into(),
            config,
        })
    }

    async fn send(&self, endpoint: &str, url: &str) -> ApiResult<RawResponse> {
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|error| {
                // reqwest's Display can include the URL but never the
                // Authorization header, so this is safe to surface.
                ApiError::local(ErrorCause::Transport, endpoint, error.to_string())
            })?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_lowercase(), value.to_owned()))
            })
            .collect();
        let body = response
            .text()
            .await
            .map_err(|error| ApiError::local(ErrorCause::Transport, endpoint, error.to_string()))?;

        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }

    /// Perform one GET, retrying a rate-limited response within budget.
    async fn get(&self, endpoint: &str, url: &str) -> ApiResult<RawResponse> {
        let mut attempt = 0;
        loop {
            let raw = self.send(endpoint, url).await?;
            if (200..300).contains(&raw.status) {
                return Ok(raw);
            }

            let error = self.to_error(endpoint, &raw);
            if error.cause != ErrorCause::RateLimit || attempt >= self.config.max_rate_limit_retries
            {
                return Err(error);
            }

            let summary = summarise(&raw);
            let wait = classify::retry_delay_seconds(&summary, now_epoch_seconds()).unwrap_or(1);
            if wait > self.config.max_rate_limit_wait_seconds {
                return Err(error);
            }
            tokio::time::sleep(Duration::from_secs(wait)).await;
            attempt += 1;
        }
    }

    fn to_error(&self, endpoint: &str, raw: &RawResponse) -> ApiError {
        let summary = summarise(raw);
        ApiError {
            cause: classify::classify(&summary),
            endpoint: endpoint.to_owned(),
            status: Some(raw.status),
            message: summary.message,
            documentation_url: summary.documentation_url,
            accepted_permissions: raw.headers.get("x-accepted-github-permissions").cloned(),
            request_id: raw.headers.get("x-github-request-id").cloned(),
        }
    }

    async fn get_json(&self, endpoint: &str, path: &str) -> ApiResult<(Value, RawResponse)> {
        let url = format!("{}{path}", self.config.base_url);
        let raw = self.get(endpoint, &url).await?;
        let value = parse_json(endpoint, &raw.body)?;
        Ok((value, raw))
    }

    /// Walk a paginated listing, following `Link: rel="next"` within budget.
    ///
    /// The boolean is true when the walk stopped at the page budget rather
    /// than at the last page — the caller decides whether a truncated listing
    /// can still answer its question.
    async fn get_paged(&self, endpoint: &str, path: &str) -> ApiResult<(Vec<Value>, bool)> {
        let mut url = format!("{}{path}", self.config.base_url);
        let mut collected = Vec::new();
        for page in 0..self.config.max_pages {
            let raw = self.get(endpoint, &url).await?;
            let value = parse_json(endpoint, &raw.body)?;
            match value {
                Value::Array(items) => collected.extend(items),
                other => {
                    return Err(ApiError::local(
                        ErrorCause::Malformed,
                        endpoint,
                        format!("expected an array, found {other}"),
                    ))
                }
            }
            match next_link(&raw) {
                Some(next) => url = next,
                None => return Ok((collected, false)),
            }
            if page + 1 == self.config.max_pages {
                return Ok((collected, true));
            }
        }
        Ok((collected, true))
    }
}

fn summarise(raw: &RawResponse) -> Response {
    let body: Option<Value> = serde_json::from_str(&raw.body).ok();
    Response {
        status: raw.status,
        headers: raw.headers.clone(),
        message: body
            .as_ref()
            .and_then(|body| body.get("message"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        documentation_url: body
            .as_ref()
            .and_then(|body| body.get("documentation_url"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn parse_json(endpoint: &str, body: &str) -> ApiResult<Value> {
    serde_json::from_str(body).map_err(|error| {
        ApiError::local(
            ErrorCause::Malformed,
            endpoint,
            format!("response was not json: {error}"),
        )
    })
}

fn next_link(raw: &RawResponse) -> Option<String> {
    let link = raw.headers.get("link")?;
    for part in link.split(',') {
        let (target, relation) = part.split_once(';')?;
        if relation.trim().trim_end_matches(';') == "rel=\"next\"" {
            let target = target.trim().trim_start_matches('<').trim_end_matches('>');
            return Some(target.to_owned());
        }
    }
    None
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn field_bool(value: &Value, name: &str) -> bool {
    value.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn field_string(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn require_string(endpoint: &str, value: &Value, name: &str) -> ApiResult<String> {
    field_string(value, name).ok_or_else(|| {
        ApiError::local(
            ErrorCause::Malformed,
            endpoint,
            format!("response is missing the string field `{name}`"),
        )
    })
}

impl GitHub for RestClient {
    async fn repository(&self, owner: &str, repo: &str) -> ApiResult<Repository> {
        let endpoint = format!("GET /repos/{owner}/{repo}");
        let path = format!("/repos/{}/{}", encode_segment(owner), encode_segment(repo));
        let (value, raw) = self.get_json(&endpoint, &path).await?;
        Ok(Repository {
            full_name: require_string(&endpoint, &value, "full_name")?,
            id: value.get("id").and_then(Value::as_u64).ok_or_else(|| {
                ApiError::local(ErrorCause::Malformed, &endpoint, "response is missing `id`")
            })?,
            owner: value
                .get("owner")
                .and_then(|owner| owner.get("login"))
                .and_then(Value::as_str)
                .unwrap_or(owner)
                .to_owned(),
            name: require_string(&endpoint, &value, "name")?,
            default_branch: require_string(&endpoint, &value, "default_branch")?,
            visibility: field_string(&value, "visibility").unwrap_or_else(|| {
                if field_bool(&value, "private") {
                    "private".to_owned()
                } else {
                    "public".to_owned()
                }
            }),
            description: field_string(&value, "description"),
            license_spdx: value
                .get("license")
                .and_then(|license| license.get("spdx_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            allow_merge_commit: field_bool(&value, "allow_merge_commit"),
            allow_squash_merge: field_bool(&value, "allow_squash_merge"),
            allow_rebase_merge: field_bool(&value, "allow_rebase_merge"),
            delete_branch_on_merge: field_bool(&value, "delete_branch_on_merge"),
            has_wiki: field_bool(&value, "has_wiki"),
            has_projects: field_bool(&value, "has_projects"),
            has_discussions: field_bool(&value, "has_discussions"),
            has_issues: field_bool(&value, "has_issues"),
            observed_at: raw.headers.get("date").cloned(),
        })
    }

    async fn topics(&self, owner: &str, repo: &str) -> ApiResult<Vec<String>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/topics");
        let path = format!(
            "/repos/{}/{}/topics",
            encode_segment(owner),
            encode_segment(repo)
        );
        let (value, _) = self.get_json(&endpoint, &path).await?;
        let names = value
            .get("names")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ApiError::local(
                    ErrorCause::Malformed,
                    &endpoint,
                    "response is missing `names`",
                )
            })?
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
        Ok(names)
    }

    async fn resolve_commit(&self, owner: &str, repo: &str, reference: &str) -> ApiResult<String> {
        let endpoint = format!("GET /repos/{owner}/{repo}/commits/{reference}");
        let path = format!(
            "/repos/{}/{}/commits/{}",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(reference)
        );
        let (value, _) = self.get_json(&endpoint, &path).await?;
        require_string(&endpoint, &value, "sha")
    }

    async fn tree(&self, owner: &str, repo: &str, commit: &str) -> ApiResult<Tree> {
        let endpoint = format!("GET /repos/{owner}/{repo}/git/trees/{commit}");
        let path = format!(
            "/repos/{}/{}/git/trees/{}?recursive=1",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(commit)
        );
        let (value, _) = self.get_json(&endpoint, &path).await?;
        let entries = value
            .get("tree")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ApiError::local(
                    ErrorCause::Malformed,
                    &endpoint,
                    "response is missing `tree`",
                )
            })?
            .iter()
            .filter_map(|entry| {
                let mode = field_string(entry, "mode")?;
                Some(TreeEntry {
                    path: field_string(entry, "path")?,
                    kind: EntryKind::from_mode(&mode)?,
                    mode,
                    sha: field_string(entry, "sha")?,
                    size: entry.get("size").and_then(Value::as_u64),
                })
            })
            .collect();
        Ok(Tree {
            entries,
            truncated: field_bool(&value, "truncated"),
        })
    }

    async fn blob(&self, owner: &str, repo: &str, sha: &str) -> ApiResult<Vec<u8>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/git/blobs/{sha}");
        let path = format!(
            "/repos/{}/{}/git/blobs/{}",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(sha)
        );
        let (value, _) = self.get_json(&endpoint, &path).await?;
        let encoding = field_string(&value, "encoding").unwrap_or_default();
        let content = require_string(&endpoint, &value, "content")?;
        match encoding.as_str() {
            "base64" => {
                let stripped: String = content
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                base64::engine::general_purpose::STANDARD
                    .decode(stripped)
                    .map_err(|error| {
                        ApiError::local(
                            ErrorCause::Malformed,
                            &endpoint,
                            format!("blob content was not base64: {error}"),
                        )
                    })
            }
            "utf-8" | "" => Ok(content.into_bytes()),
            other => Err(ApiError::local(
                ErrorCause::Malformed,
                &endpoint,
                format!("unsupported blob encoding `{other}`"),
            )),
        }
    }

    async fn tags(&self, owner: &str, repo: &str) -> ApiResult<Vec<TagRef>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/git/refs/tags");
        let path = format!(
            "/repos/{}/{}/git/refs/tags?per_page=100",
            encode_segment(owner),
            encode_segment(repo)
        );
        let (items, _) = match self.get_paged(&endpoint, &path).await {
            Ok(pages) => pages,
            // A repository with no tags answers 404 on this endpoint, which is
            // a legitimate empty answer rather than a failure.
            Err(error) if error.cause == ErrorCause::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        Ok(items
            .iter()
            .filter_map(|item| {
                let reference = field_string(item, "ref")?;
                Some(TagRef {
                    name: reference.strip_prefix("refs/tags/")?.to_owned(),
                    sha: item
                        .get("object")
                        .and_then(|object| object.get("sha"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
            })
            .collect())
    }

    async fn history(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
        max_commits: usize,
    ) -> ApiResult<(Vec<CommitSummary>, bool)> {
        let endpoint = format!("GET /repos/{owner}/{repo}/commits");
        let path = format!(
            "/repos/{}/{}/commits?sha={}&per_page=100",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(commit)
        );
        let (items, pages_truncated) = self.get_paged(&endpoint, &path).await?;
        let mut commits: Vec<CommitSummary> = items
            .iter()
            .filter_map(|item| {
                Some(CommitSummary {
                    sha: field_string(item, "sha")?,
                    parents: item
                        .get("parents")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or_default(),
                })
            })
            .collect();
        let over_budget = commits.len() > max_commits;
        commits.truncate(max_commits);
        Ok((commits, pages_truncated || over_budget))
    }

    async fn rulesets(&self, owner: &str, repo: &str) -> ApiResult<Vec<Ruleset>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/rulesets");
        let path = format!(
            "/repos/{}/{}/rulesets?includes_parents=true&per_page=100",
            encode_segment(owner),
            encode_segment(repo)
        );
        let (items, _) = self.get_paged(&endpoint, &path).await?;
        Ok(items
            .iter()
            .filter_map(|item| {
                Some(Ruleset {
                    id: item.get("id").and_then(Value::as_u64).unwrap_or_default(),
                    name: field_string(item, "name")?,
                    target: field_string(item, "target"),
                    source_type: field_string(item, "source_type"),
                    source: field_string(item, "source"),
                    enforcement: field_string(item, "enforcement"),
                })
            })
            .collect())
    }

    async fn branch_rules(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ApiResult<Vec<BranchRule>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/rules/branches/{branch}");
        let path = format!(
            "/repos/{}/{}/rules/branches/{}?per_page=100",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(branch)
        );
        let (items, _) = self.get_paged(&endpoint, &path).await?;
        Ok(items
            .iter()
            .filter_map(|item| {
                Some(BranchRule {
                    rule_type: field_string(item, "type")?,
                    source_type: field_string(item, "source_type"),
                    parameters: item.get("parameters").cloned().unwrap_or(Value::Null),
                })
            })
            .collect())
    }

    async fn user_installations(&self) -> ApiResult<Vec<Installation>> {
        let endpoint = "GET /user/installations".to_owned();
        let mut url = format!("{}/user/installations?per_page=100", self.config.base_url);
        let mut installations = Vec::new();
        for page in 0..self.config.max_pages {
            let raw = self.get(&endpoint, &url).await?;
            let value = parse_json(&endpoint, &raw.body)?;
            let items = value
                .get("installations")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ApiError::local(
                        ErrorCause::Malformed,
                        &endpoint,
                        "response is missing `installations`",
                    )
                })?;
            for item in items {
                installations.push(Installation {
                    id: item.get("id").and_then(Value::as_u64).unwrap_or_default(),
                    app_id: item
                        .get("app_id")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    app_slug: field_string(item, "app_slug").unwrap_or_default(),
                    account: item
                        .get("account")
                        .and_then(|account| account.get("login"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    permissions: item
                        .get("permissions")
                        .and_then(Value::as_object)
                        .map(|map| {
                            map.iter()
                                .map(|(name, level)| {
                                    (name.clone(), level.as_str().unwrap_or("unknown").to_owned())
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                });
            }
            match next_link(&raw) {
                Some(next) => url = next,
                None => return Ok(installations),
            }
            if page + 1 == self.config.max_pages {
                // A token whose installation list cannot be walked to the end
                // cannot be positively enumerated, so this is a refusal rather
                // than a partial answer.
                return Err(ApiError::local(
                    ErrorCause::Budget,
                    &endpoint,
                    format!(
                        "installation list exceeds the {} page budget",
                        self.config.max_pages
                    ),
                ));
            }
        }
        Ok(installations)
    }

    async fn authenticated_user(&self) -> ApiResult<AuthenticatedUser> {
        let endpoint = "GET /user".to_owned();
        let (value, raw) = self.get_json(&endpoint, "/user").await?;
        Ok(AuthenticatedUser {
            login: require_string(&endpoint, &value, "login")?,
            oauth_scopes: raw.headers.get("x-oauth-scopes").cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(encode_segment("main"), "main");
        assert_eq!(encode_segment("release/1.0"), "release%2F1.0");
        assert_eq!(encode_segment("weird name"), "weird%20name");
        assert_eq!(encode_segment("../../etc"), "..%2F..%2Fetc");
    }

    #[test]
    fn next_link_is_read_from_the_link_header() {
        let raw = RawResponse {
            status: 200,
            headers: [(
                "link".to_owned(),
                "<https://api.github.com/x?page=2>; rel=\"next\", \
                 <https://api.github.com/x?page=9>; rel=\"last\""
                    .to_owned(),
            )]
            .into_iter()
            .collect(),
            body: String::new(),
        };
        assert_eq!(
            next_link(&raw).as_deref(),
            Some("https://api.github.com/x?page=2")
        );
    }

    #[test]
    fn a_last_page_has_no_next_link() {
        let raw = RawResponse {
            status: 200,
            headers: [(
                "link".to_owned(),
                "<https://api.github.com/x?page=1>; rel=\"prev\"".to_owned(),
            )]
            .into_iter()
            .collect(),
            body: String::new(),
        };
        assert_eq!(next_link(&raw), None);
    }

    #[test]
    fn debug_output_never_carries_the_token() {
        let client = RestClient::new("ghu_supersecretvalue", RestClientConfig::default()).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("supersecret"));
    }
}
