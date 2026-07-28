//! The REST implementation of [`GitHub`].

// `ApiError` is deliberately wide: it carries the status, GitHub's message and
// documentation link, the accepted-permissions header, and the request id,
// because a failure that cannot be reproduced with GitHub support is a failure
// that wastes someone's afternoon. Boxing it would trade that clarity for a
// pointer chase on a path that has just done network I/O.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::Value;

use super::classify::{self, all_headers, single_header, ErrorCause, Headers, Response};
use super::{
    ApiError, ApiResult, AuthenticatedUser, BranchRule, CommitSummary, EntryKind, GitHub,
    Installation, OAuthScopeHeader, Paged, Repository, Ruleset, TagRef, Tree, TreeEntry,
};
use crate::limits::Limits;

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
pub(crate) fn encode_segment(segment: &str) -> String {
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
    /// Largest number of tree entries airlock will accept in one response.
    pub max_tree_entries: usize,
    /// Largest response body airlock will read, in bytes.
    pub max_response_bytes: usize,
    /// How long to wait to open a connection.
    pub connect_timeout: Duration,
    /// How long to wait for one request to complete.
    pub request_timeout: Duration,
    /// The wall-clock budget for everything this client does.
    pub audit_budget: Duration,
    /// How many times a rate-limited request may be retried.
    pub max_rate_limit_retries: usize,
    /// The longest airlock will wait for a rate limit to reset, in seconds.
    pub max_rate_limit_wait_seconds: u64,
}

impl Default for RestClientConfig {
    fn default() -> Self {
        Self::from_limits(Limits::default())
    }
}

impl RestClientConfig {
    /// Build a client configuration from the audit's budgets.
    ///
    /// The client and the checks share one set of limits: a page budget the
    /// client invents privately is a budget nothing reports and nothing tunes.
    #[must_use]
    pub fn from_limits(limits: Limits) -> Self {
        Self {
            base_url: "https://api.github.com".to_owned(),
            user_agent: concat!("airlock/", env!("CARGO_PKG_VERSION")).to_owned(),
            max_pages: limits.max_pages,
            max_tree_entries: limits.max_tree_entries,
            max_response_bytes: limits.max_response_bytes,
            connect_timeout: limits.connect_timeout,
            request_timeout: limits.request_timeout,
            audit_budget: limits.audit_budget,
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
    deadline: Instant,
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
    headers: Headers,
    body: String,
}

impl RawResponse {
    fn single(&self, name: &str) -> Option<&str> {
        single_header(&self.headers, name)
    }

    fn all(&self, name: &str) -> &[String] {
        all_headers(&self.headers, name)
    }

    fn response(&self) -> Response {
        Response {
            status: self.status,
            headers: self.headers.clone(),
            message: None,
            documentation_url: None,
        }
    }
}

impl RestClient {
    /// Build a client for `token`.
    ///
    /// The wall-clock budget starts here, so verification and the audit that
    /// follows share one deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying HTTP stack cannot be built.
    pub fn new(token: impl Into<String>, config: RestClientConfig) -> ApiResult<Self> {
        let http = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            // Without these, a server that accepts a connection and never
            // finishes the body hangs the audit forever.
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|error| ApiError::local(ErrorCause::Transport, "client", error.to_string()))?;
        let deadline = Instant::now() + config.audit_budget;
        Ok(Self {
            http,
            token: token.into(),
            config,
            deadline,
        })
    }

    /// How long is left of the wall-clock budget.
    #[must_use]
    pub fn remaining_budget(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn check_deadline(&self, endpoint: &str) -> ApiResult<()> {
        if Instant::now() >= self.deadline {
            return Err(ApiError::local(
                ErrorCause::Budget,
                endpoint,
                format!(
                    "the {} second audit budget was exhausted before this request completed",
                    self.config.audit_budget.as_secs()
                ),
            ));
        }
        Ok(())
    }

    async fn send(&self, endpoint: &str, url: &str) -> ApiResult<RawResponse> {
        self.check_deadline(endpoint)?;

        let response = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|error| transport_error(endpoint, &error))?;

        let status = response.status().as_u16();
        // Multi-valued, because HTTP lets a field repeat and a security
        // decision made from whichever repetition survived a map insert is not
        // a decision.
        let mut headers = Headers::new();
        for (name, value) in response.headers() {
            if let Ok(value) = value.to_str() {
                headers
                    .entry(name.as_str().to_lowercase())
                    .or_default()
                    .push(value.to_owned());
            }
        }

        let body = self.read_body(endpoint, response).await?;

        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }

    /// Read a response body under the byte budget.
    ///
    /// Chunked rather than buffered whole, so an endless or enormous body is
    /// abandoned at the limit instead of being materialised first.
    async fn read_body(
        &self,
        endpoint: &str,
        mut response: reqwest::Response,
    ) -> ApiResult<String> {
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            self.check_deadline(endpoint)?;
            let chunk = response
                .chunk()
                .await
                .map_err(|error| transport_error(endpoint, &error))?;
            let Some(chunk) = chunk else { break };
            if bytes.len() + chunk.len() > self.config.max_response_bytes {
                return Err(ApiError::local(
                    ErrorCause::Budget,
                    endpoint,
                    format!(
                        "the response exceeded the {} byte limit and was abandoned",
                        self.config.max_response_bytes
                    ),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes)
            .map_err(|error| ApiError::local(ErrorCause::Malformed, endpoint, error.to_string()))
    }

    /// Perform one GET, retrying a rate-limited response within budget.
    async fn get(&self, endpoint: &str, url: &str) -> ApiResult<RawResponse> {
        let mut attempt = 0;
        loop {
            let raw = self.send(endpoint, url).await?;
            if (200..300).contains(&raw.status) {
                return Ok(raw);
            }

            let summary = summarise(&raw);
            let cause = classify::classify(&summary);
            let wait = classify::retry_delay_seconds(&summary, now_epoch_seconds()).unwrap_or(1);
            let error = self.to_error(endpoint, &raw, cause, summary);
            if error.cause != ErrorCause::RateLimit || attempt >= self.config.max_rate_limit_retries
            {
                return Err(error);
            }

            // Waiting past the audit deadline achieves nothing but a later
            // failure, so the budget wins over the retry.
            if wait > self.config.max_rate_limit_wait_seconds
                || Duration::from_secs(wait) >= self.remaining_budget()
            {
                return Err(error);
            }
            tokio::time::sleep(Duration::from_secs(wait)).await;
            attempt += 1;
        }
    }

    fn to_error(
        &self,
        endpoint: &str,
        raw: &RawResponse,
        cause: ErrorCause,
        summary: Response,
    ) -> ApiError {
        ApiError {
            cause,
            endpoint: endpoint.to_owned(),
            status: Some(raw.status),
            message: summary.message,
            documentation_url: summary.documentation_url,
            // A repeated accepted-permissions header has no single answer, so
            // every value is reported rather than one arbitrary member.
            accepted_permissions: match raw.all("x-accepted-github-permissions") {
                [] => None,
                values => Some(values.join(" | ")),
            },
            request_id: raw.single("x-github-request-id").map(ToOwned::to_owned),
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
    /// The returned flag is true when the walk stopped at the page budget
    /// rather than at the last page. It is the caller's job to decide whether
    /// a prefix can answer its question; it is this function's job never to
    /// hide that a prefix was all it saw.
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
            match next_link(endpoint, &raw)? {
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

fn transport_error(endpoint: &str, error: &reqwest::Error) -> ApiError {
    // A timeout is a budget failure, not a network failure: airlock chose the
    // deadline, and the distinction changes the remediation.
    let cause = if error.is_timeout() {
        ErrorCause::Budget
    } else {
        ErrorCause::Transport
    };
    ApiError::local(cause, endpoint, error.to_string())
}

fn summarise(raw: &RawResponse) -> Response {
    let body: Option<Value> = serde_json::from_str(&raw.body).ok();
    let mut response = raw.response();
    response.message = body
        .as_ref()
        .and_then(|body| body.get("message"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    response.documentation_url = body
        .as_ref()
        .and_then(|body| body.get("documentation_url"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    response
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

fn next_link(endpoint: &str, raw: &RawResponse) -> ApiResult<Option<String>> {
    let link = match raw.all("link") {
        [] => return Ok(None),
        [only] => only,
        _ => {
            return Err(ApiError::local(
                ErrorCause::Malformed,
                endpoint,
                "the response carried more than one Link header, so pagination has no \
                 unambiguous next page",
            ))
        }
    };

    for part in link.split(',') {
        let Some((target, relation)) = part.split_once(';') else {
            continue;
        };
        if relation.trim().trim_end_matches(';') == "rel=\"next\"" {
            let target = target.trim().trim_start_matches('<').trim_end_matches('>');
            return Ok(Some(target.to_owned()));
        }
    }
    Ok(None)
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Strict decoding
// ---------------------------------------------------------------------------
//
// Every collection member is decoded strictly. A member airlock cannot read is
// a malformed response, never one fewer item: a tree entry that vanishes makes
// a forbidden path look absent, a commit that vanishes shortens the history a
// merge could hide in, and a ruleset that vanishes makes a branch look
// unprotected. All three are conclusions drawn from data airlock never saw.

fn malformed(endpoint: &str, detail: impl Into<String>) -> ApiError {
    ApiError::local(ErrorCause::Malformed, endpoint, detail)
}

fn field_bool(value: &Value, name: &str) -> bool {
    value.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn optional_string(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn require_string(endpoint: &str, value: &Value, name: &str) -> ApiResult<String> {
    match value.get(name) {
        Some(Value::String(found)) => Ok(found.clone()),
        Some(other) => Err(malformed(
            endpoint,
            format!("`{name}` should be a string, found {other}"),
        )),
        None => Err(malformed(
            endpoint,
            format!("the response is missing the string field `{name}`"),
        )),
    }
}

fn require_u64(endpoint: &str, value: &Value, name: &str) -> ApiResult<u64> {
    match value.get(name) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| malformed(endpoint, format!("`{name}` is not a non-negative integer"))),
        Some(other) => Err(malformed(
            endpoint,
            format!("`{name}` should be a number, found {other}"),
        )),
        None => Err(malformed(
            endpoint,
            format!("the response is missing the numeric field `{name}`"),
        )),
    }
}

fn require_array<'a>(endpoint: &str, value: &'a Value, name: &str) -> ApiResult<&'a Vec<Value>> {
    match value.get(name) {
        Some(Value::Array(items)) => Ok(items),
        Some(other) => Err(malformed(
            endpoint,
            format!("`{name}` should be an array, found {other}"),
        )),
        None => Err(malformed(
            endpoint,
            format!("the response is missing the array field `{name}`"),
        )),
    }
}

fn decode_tree_entry(endpoint: &str, entry: &Value) -> ApiResult<TreeEntry> {
    let path = require_string(endpoint, entry, "path")?;
    let mode = require_string(endpoint, entry, "mode")?;
    let kind = EntryKind::from_mode(&mode).ok_or_else(|| {
        malformed(
            endpoint,
            format!("tree entry `{path}` carries the unrecognised mode `{mode}`"),
        )
    })?;
    let sha = require_string(endpoint, entry, "sha")?;
    let size = match entry.get("size") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => Some(number.as_u64().ok_or_else(|| {
            malformed(endpoint, format!("tree entry `{path}` has a negative size"))
        })?),
        Some(other) => {
            return Err(malformed(
                endpoint,
                format!("tree entry `{path}` has a non-numeric size {other}"),
            ))
        }
    };
    Ok(TreeEntry {
        path,
        kind,
        mode,
        sha,
        size,
    })
}

fn decode_tag(endpoint: &str, item: &Value) -> ApiResult<TagRef> {
    let reference = require_string(endpoint, item, "ref")?;
    // The endpoint airlock asks is the `refs/tags` matching-ref collection, so
    // every member of the response is a tag. A `refs/heads/*`, a `refs/pull/*`,
    // a truncated `refs/tag/*`, or anything else is malformed API data — and
    // treating it as "simply not a tag" is how a whole tag listing becomes
    // silently empty and "no tag carries a `v` prefix" passes.
    let Some(name) = reference.strip_prefix("refs/tags/") else {
        return Err(malformed(
            endpoint,
            format!("`{reference}` is not a tag ref, and this endpoint returns only tag refs"),
        ));
    };
    if name.is_empty() {
        return Err(malformed(endpoint, "a tag ref carries no name"));
    }
    let object = item
        .get("object")
        .ok_or_else(|| malformed(endpoint, format!("tag `{name}` carries no object")))?;
    Ok(TagRef {
        name: name.to_owned(),
        sha: require_string(endpoint, object, "sha")?,
    })
}

fn decode_commit(endpoint: &str, item: &Value) -> ApiResult<CommitSummary> {
    let sha = require_string(endpoint, item, "sha")?;
    let parents = require_array(endpoint, item, "parents")?;
    Ok(CommitSummary {
        sha,
        parents: parents.len(),
    })
}

fn decode_ruleset(endpoint: &str, item: &Value) -> ApiResult<Ruleset> {
    Ok(Ruleset {
        id: require_u64(endpoint, item, "id")?,
        name: require_string(endpoint, item, "name")?,
        target: optional_string(item, "target"),
        source_type: optional_string(item, "source_type"),
        source: optional_string(item, "source"),
        enforcement: optional_string(item, "enforcement"),
    })
}

fn decode_branch_rule(endpoint: &str, item: &Value) -> ApiResult<BranchRule> {
    Ok(BranchRule {
        rule_type: require_string(endpoint, item, "type")?,
        source_type: optional_string(item, "source_type"),
        parameters: item.get("parameters").cloned().unwrap_or(Value::Null),
    })
}

fn decode_installation(endpoint: &str, item: &Value) -> ApiResult<Installation> {
    let id = require_u64(endpoint, item, "id")?;
    // The app id is the immutable half of the issuer attestation, so a
    // response without one cannot be used to accept a token.
    let app_id = require_u64(endpoint, item, "app_id")?;
    let app_slug = require_string(endpoint, item, "app_slug")?;

    let Some(Value::Object(map)) = item.get("permissions") else {
        return Err(malformed(
            endpoint,
            format!("installation {id} carries no permission map"),
        ));
    };
    let mut permissions = BTreeMap::new();
    for (name, level) in map {
        let Value::String(level) = level else {
            return Err(malformed(
                endpoint,
                format!("installation {id} permission `{name}` is not a string"),
            ));
        };
        permissions.insert(name.clone(), level.clone());
    }

    Ok(Installation {
        id,
        app_id,
        app_slug,
        account: item
            .get("account")
            .and_then(|account| account.get("login"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        permissions,
    })
}

impl GitHub for RestClient {
    async fn repository(&self, owner: &str, repo: &str) -> ApiResult<Repository> {
        let endpoint = format!("GET /repos/{owner}/{repo}");
        let path = format!("/repos/{}/{}", encode_segment(owner), encode_segment(repo));
        let (value, raw) = self.get_json(&endpoint, &path).await?;
        Ok(Repository {
            full_name: require_string(&endpoint, &value, "full_name")?,
            id: require_u64(&endpoint, &value, "id")?,
            owner: value
                .get("owner")
                .and_then(|owner| owner.get("login"))
                .and_then(Value::as_str)
                .unwrap_or(owner)
                .to_owned(),
            name: require_string(&endpoint, &value, "name")?,
            default_branch: require_string(&endpoint, &value, "default_branch")?,
            visibility: optional_string(&value, "visibility").unwrap_or_else(|| {
                if field_bool(&value, "private") {
                    "private".to_owned()
                } else {
                    "public".to_owned()
                }
            }),
            description: optional_string(&value, "description"),
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
            observed_at: raw.single("date").map(ToOwned::to_owned),
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
        require_array(&endpoint, &value, "names")?
            .iter()
            .map(|name| {
                name.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| malformed(&endpoint, "a declared topic is not a string"))
            })
            .collect()
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
        let raw_entries = require_array(&endpoint, &value, "tree")?;

        if raw_entries.len() > self.config.max_tree_entries {
            return Err(ApiError::local(
                ErrorCause::Budget,
                &endpoint,
                format!(
                    "the tree carries {} entries, over the {} entry limit",
                    raw_entries.len(),
                    self.config.max_tree_entries
                ),
            ));
        }

        Ok(Tree {
            entries: raw_entries
                .iter()
                .map(|entry| decode_tree_entry(&endpoint, entry))
                .collect::<ApiResult<Vec<TreeEntry>>>()?,
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
        let encoding = optional_string(&value, "encoding").unwrap_or_default();
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
                        malformed(&endpoint, format!("blob content was not base64: {error}"))
                    })
            }
            "utf-8" | "" => Ok(content.into_bytes()),
            other => Err(malformed(
                &endpoint,
                format!("unsupported blob encoding `{other}`"),
            )),
        }
    }

    async fn tags(&self, owner: &str, repo: &str) -> ApiResult<Paged<TagRef>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/git/refs/tags");
        let path = format!(
            "/repos/{}/{}/git/refs/tags?per_page=100",
            encode_segment(owner),
            encode_segment(repo)
        );
        let (items, truncated) = match self.get_paged(&endpoint, &path).await {
            Ok(pages) => pages,
            // A repository with no tags answers 404 on this endpoint, which is
            // a legitimate empty answer rather than a failure.
            Err(error) if error.cause == ErrorCause::NotFound => {
                return Ok(Paged::complete(Vec::new()))
            }
            Err(error) => return Err(error),
        };
        Ok(Paged {
            items: items
                .iter()
                .map(|item| decode_tag(&endpoint, item))
                .collect::<ApiResult<Vec<TagRef>>>()?,
            truncated,
        })
    }

    async fn history(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
        max_commits: usize,
    ) -> ApiResult<Paged<CommitSummary>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/commits");
        let path = format!(
            "/repos/{}/{}/commits?sha={}&per_page=100",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(commit)
        );
        let (items, pages_truncated) = self.get_paged(&endpoint, &path).await?;
        let mut commits = items
            .iter()
            .map(|item| decode_commit(&endpoint, item))
            .collect::<ApiResult<Vec<CommitSummary>>>()?;
        let over_budget = commits.len() > max_commits;
        commits.truncate(max_commits);
        Ok(Paged {
            items: commits,
            truncated: pages_truncated || over_budget,
        })
    }

    async fn rulesets(&self, owner: &str, repo: &str) -> ApiResult<Paged<Ruleset>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/rulesets");
        let path = format!(
            "/repos/{}/{}/rulesets?includes_parents=true&per_page=100",
            encode_segment(owner),
            encode_segment(repo)
        );
        let (items, truncated) = self.get_paged(&endpoint, &path).await?;
        Ok(Paged {
            items: items
                .iter()
                .map(|item| decode_ruleset(&endpoint, item))
                .collect::<ApiResult<Vec<Ruleset>>>()?,
            truncated,
        })
    }

    async fn branch_rules(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ApiResult<Paged<BranchRule>> {
        let endpoint = format!("GET /repos/{owner}/{repo}/rules/branches/{branch}");
        let path = format!(
            "/repos/{}/{}/rules/branches/{}?per_page=100",
            encode_segment(owner),
            encode_segment(repo),
            encode_segment(branch)
        );
        let (items, truncated) = self.get_paged(&endpoint, &path).await?;
        Ok(Paged {
            items: items
                .iter()
                .map(|item| decode_branch_rule(&endpoint, item))
                .collect::<ApiResult<Vec<BranchRule>>>()?,
            truncated,
        })
    }

    async fn user_installations(&self) -> ApiResult<Vec<Installation>> {
        let endpoint = "GET /user/installations".to_owned();
        let mut url = format!("{}/user/installations?per_page=100", self.config.base_url);
        let mut installations = Vec::new();
        for page in 0..self.config.max_pages {
            let raw = self.get(&endpoint, &url).await?;
            let value = parse_json(&endpoint, &raw.body)?;
            for item in require_array(&endpoint, &value, "installations")? {
                installations.push(decode_installation(&endpoint, item)?);
            }
            match next_link(&endpoint, &raw)? {
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
            oauth_scopes: OAuthScopeHeader::from_values(raw.all("x-oauth-scopes")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(headers: &[(&str, &str)]) -> RawResponse {
        let mut map = Headers::new();
        for (name, value) in headers {
            map.entry((*name).to_owned())
                .or_default()
                .push((*value).to_owned());
        }
        RawResponse {
            status: 200,
            headers: map,
            body: String::new(),
        }
    }

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(encode_segment("main"), "main");
        assert_eq!(encode_segment("release/1.0"), "release%2F1.0");
        assert_eq!(encode_segment("weird name"), "weird%20name");
        assert_eq!(encode_segment("../../etc"), "..%2F..%2Fetc");
    }

    #[test]
    fn next_link_is_read_from_the_link_header() {
        let raw = raw(&[(
            "link",
            "<https://api.github.com/x?page=2>; rel=\"next\", \
             <https://api.github.com/x?page=9>; rel=\"last\"",
        )]);
        assert_eq!(
            next_link("GET /x", &raw).unwrap().as_deref(),
            Some("https://api.github.com/x?page=2")
        );
    }

    #[test]
    fn a_last_page_has_no_next_link() {
        let raw = raw(&[("link", "<https://api.github.com/x?page=1>; rel=\"prev\"")]);
        assert_eq!(next_link("GET /x", &raw).unwrap(), None);
    }

    #[test]
    fn two_link_headers_are_malformed_rather_than_one_of_them() {
        let raw = raw(&[
            ("link", "<https://api.github.com/x?page=2>; rel=\"next\""),
            ("link", "<https://elsewhere.example/x>; rel=\"next\""),
        ]);
        assert_eq!(
            next_link("GET /x", &raw).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn an_absent_scope_header_is_distinguished_from_an_empty_one() {
        // The whole security decision hangs on these being different: one is
        // "airlock could not read the grant", the other is GitHub stating the
        // grant is empty.
        assert_eq!(
            OAuthScopeHeader::from_values(raw(&[]).all("x-oauth-scopes")),
            OAuthScopeHeader::Absent
        );
        assert_eq!(
            OAuthScopeHeader::from_values(raw(&[("x-oauth-scopes", "")]).all("x-oauth-scopes")),
            OAuthScopeHeader::Single(String::new())
        );
        assert_eq!(
            OAuthScopeHeader::from_values(
                raw(&[("x-oauth-scopes", "read:org")]).all("x-oauth-scopes")
            ),
            OAuthScopeHeader::Single("read:org".to_owned())
        );
        assert_eq!(
            OAuthScopeHeader::from_values(
                raw(&[("x-oauth-scopes", "read:org"), ("x-oauth-scopes", "repo")])
                    .all("x-oauth-scopes")
            ),
            OAuthScopeHeader::Repeated(vec!["read:org".to_owned(), "repo".to_owned()])
        );
    }

    #[test]
    fn a_repeated_header_has_no_single_value() {
        let raw = raw(&[("x-oauth-scopes", "read:org"), ("x-oauth-scopes", "repo")]);
        assert_eq!(raw.single("x-oauth-scopes"), None);
        assert_eq!(raw.all("x-oauth-scopes").len(), 2);
    }

    #[test]
    fn debug_output_never_carries_the_token() {
        let client = RestClient::new("ghu_supersecretvalue", RestClientConfig::default()).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("supersecret"));
    }

    #[test]
    fn the_client_configuration_comes_from_the_audit_limits() {
        let limits = Limits {
            max_pages: 3,
            max_tree_entries: 7,
            max_response_bytes: 11,
            ..Limits::default()
        };
        let config = RestClientConfig::from_limits(limits);
        assert_eq!(config.max_pages, 3);
        assert_eq!(config.max_tree_entries, 7);
        assert_eq!(config.max_response_bytes, 11);
        assert_eq!(config.request_timeout, limits.request_timeout);
        assert_eq!(config.connect_timeout, limits.connect_timeout);
    }

    #[test]
    fn an_exhausted_wall_clock_budget_refuses_before_the_request() {
        let client = RestClient::new(
            "ghu_example",
            RestClientConfig {
                audit_budget: Duration::from_secs(0),
                ..RestClientConfig::default()
            },
        )
        .unwrap();
        let error = client.check_deadline("GET /user").unwrap_err();
        assert_eq!(error.cause, ErrorCause::Budget);
        assert!(error.to_string().contains("audit budget"));
    }

    #[test]
    fn a_tree_entry_with_an_unrecognised_mode_is_malformed_not_dropped() {
        let entry = serde_json::json!({
            "path": ".claude/settings.json",
            "mode": "123456",
            "sha": "abc"
        });
        let error = decode_tree_entry("GET /tree", &entry).unwrap_err();
        assert_eq!(error.cause, ErrorCause::Malformed);
        assert!(error.to_string().contains(".claude/settings.json"));
    }

    #[test]
    fn a_tree_entry_without_a_path_is_malformed() {
        let entry = serde_json::json!({ "mode": "100644", "sha": "abc" });
        assert_eq!(
            decode_tree_entry("GET /tree", &entry).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn a_commit_without_a_sha_is_malformed_not_dropped() {
        let commit = serde_json::json!({ "parents": [] });
        assert_eq!(
            decode_commit("GET /commits", &commit).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn a_commit_without_a_parents_array_is_malformed() {
        // A commit with no parents array is not a root commit; it is a
        // response airlock cannot count parents in.
        let commit = serde_json::json!({ "sha": "abc" });
        assert_eq!(
            decode_commit("GET /commits", &commit).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn a_ruleset_without_a_name_is_malformed_not_dropped() {
        let ruleset = serde_json::json!({ "id": 1, "source_type": "Organization" });
        assert_eq!(
            decode_ruleset("GET /rulesets", &ruleset).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn a_branch_rule_without_a_type_is_malformed_not_dropped() {
        let rule = serde_json::json!({ "parameters": {} });
        assert_eq!(
            decode_branch_rule("GET /rules", &rule).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn only_an_exact_tag_ref_decodes_as_a_tag() {
        let tag = serde_json::json!({ "ref": "refs/tags/1.0.0", "object": { "sha": "a" } });
        assert_eq!(decode_tag("GET /refs", &tag).unwrap().name, "1.0.0");
    }

    #[test]
    fn a_ref_outside_the_tag_namespace_is_malformed_not_skipped() {
        // Every one of these would previously have been dropped as "not a
        // tag", which is how an entire tag listing becomes silently empty.
        for reference in [
            "refs/heads/main",
            "refs/pull/1/head",
            "refs/tag/1.0.0",
            "refs/tags",
            "1.0.0",
            "",
        ] {
            let item = serde_json::json!({ "ref": reference, "object": { "sha": "a" } });
            let error = decode_tag("GET /refs", &item).unwrap_err();
            assert_eq!(error.cause, ErrorCause::Malformed, "`{reference}`");
        }
    }

    #[test]
    fn an_empty_tag_name_is_malformed() {
        let item = serde_json::json!({ "ref": "refs/tags/", "object": { "sha": "a" } });
        assert_eq!(
            decode_tag("GET /refs", &item).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn a_tag_without_an_object_is_malformed() {
        let broken = serde_json::json!({ "ref": "refs/tags/1.0.0" });
        assert_eq!(
            decode_tag("GET /refs", &broken).unwrap_err().cause,
            ErrorCause::Malformed
        );
    }

    #[test]
    fn an_installation_without_an_app_id_is_malformed() {
        let installation = serde_json::json!({
            "id": 1,
            "app_slug": "airlock-safe",
            "permissions": { "metadata": "read" }
        });
        let error = decode_installation("GET /user/installations", &installation).unwrap_err();
        assert_eq!(error.cause, ErrorCause::Malformed);
        assert!(error.to_string().contains("app_id"));
    }

    #[test]
    fn an_installation_without_a_permission_map_is_malformed() {
        let installation = serde_json::json!({
            "id": 1,
            "app_id": 1,
            "app_slug": "airlock-safe"
        });
        assert_eq!(
            decode_installation("GET /user/installations", &installation)
                .unwrap_err()
                .cause,
            ErrorCause::Malformed
        );
    }
}
