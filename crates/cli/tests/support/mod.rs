//! A GitHub made of fixtures.
//!
//! Every integration test runs the real binary against this, never against
//! `api.github.com`. If a test ever reached the network it would fail, because
//! the binary is told where GitHub is and it is told this.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The commit every fixture repository is audited at.
pub const COMMIT: &str = "1111111111111111111111111111111111111111";

/// One repository's contents at [`COMMIT`].
pub struct FakeRepo {
    pub owner: String,
    pub name: String,
    pub files: Vec<(String, String)>,
    /// Whether GitHub reports the recursive tree as cut short.
    pub tree_truncated: bool,
    /// An extra, deliberately malformed tree entry.
    pub malformed_tree_entry: Option<Value>,
    pub settings: Value,
    pub topics: Vec<String>,
    pub custom_properties: Vec<(String, Value)>,
    pub rulesets: Response,
    pub branch_rules: Response,
    pub tags: Vec<String>,
    /// Commits, as `(sha, parent_count)`.
    pub history: Vec<(String, usize)>,
}

/// What an endpoint answers.
pub enum Response {
    Ok(Value),
    Status(u16, Value),
}

impl Response {
    fn template(&self) -> ResponseTemplate {
        match self {
            Response::Ok(body) => ResponseTemplate::new(200)
                .insert_header("x-ratelimit-remaining", "4999")
                .set_body_json(body),
            Response::Status(status, body) => ResponseTemplate::new(*status)
                .insert_header("x-ratelimit-remaining", "4999")
                .insert_header("x-github-request-id", "FIXT:0001")
                .set_body_json(body),
        }
    }
}

impl FakeRepo {
    /// A repository whose settings satisfy every live-settings rule.
    pub fn new(owner: &str, name: &str) -> Self {
        Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
            files: Vec::new(),
            tree_truncated: false,
            malformed_tree_entry: None,
            settings: json!({
                "id": 4242,
                "name": name,
                "full_name": format!("{owner}/{name}"),
                "owner": { "login": owner },
                "default_branch": "main",
                "visibility": "public",
                "description": "A repository used by the airlock test suite.",
                "license": { "spdx_id": "Apache-2.0" },
                "allow_merge_commit": false,
                "allow_squash_merge": true,
                "allow_rebase_merge": true,
                "delete_branch_on_merge": true,
                "has_wiki": false,
                "has_projects": false,
                "has_discussions": false,
                "has_issues": true
            }),
            topics: Vec::new(),
            custom_properties: Vec::new(),
            rulesets: Response::Ok(json!([])),
            branch_rules: Response::Ok(json!([])),
            tags: Vec::new(),
            history: vec![(COMMIT.to_owned(), 1)],
        }
    }

    /// Add a file at [`COMMIT`].
    #[must_use]
    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.push((path.to_owned(), content.to_owned()));
        self
    }

    #[must_use]
    pub fn with_custom_property(mut self, name: &str, value: &str) -> Self {
        self.custom_properties
            .push((name.to_owned(), Value::String(value.to_owned())));
        self
    }

    #[must_use]
    pub fn with_null_custom_property(mut self, name: &str) -> Self {
        self.custom_properties.push((name.to_owned(), Value::Null));
        self
    }

    #[must_use]
    pub fn with_multi_select_custom_property(mut self, name: &str, values: &[&str]) -> Self {
        self.custom_properties.push((
            name.to_owned(),
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::String((*value).to_owned()))
                    .collect(),
            ),
        ));
        self
    }

    /// Answer the repository endpoint the way GitHub answers a read-only
    /// token: the merge-behaviour fields are simply absent.
    ///
    /// GitHub discloses `allow_*_merge` and `delete_branch_on_merge` only to a
    /// credential with `contents: write`, and the headless audit proves its
    /// credential read-only before it runs. This is therefore the shape of
    /// every scheduled run, not an unusual one.
    #[must_use]
    pub fn with_undisclosed_merge_settings(mut self) -> Self {
        let object = self
            .settings
            .as_object_mut()
            .expect("settings are an object");
        for field in [
            "allow_merge_commit",
            "allow_squash_merge",
            "allow_rebase_merge",
            "delete_branch_on_merge",
        ] {
            object.remove(field);
        }
        self
    }

    /// Answer the ruleset endpoints the way a repository governed as the
    /// standards expect answers them: one active organisation branch ruleset,
    /// requiring pull requests, squash and rebase only, and linear history.
    #[must_use]
    pub fn with_conforming_org_ruleset(mut self) -> Self {
        self.rulesets = Response::Ok(json!([{
            "id": 1,
            "name": "default-branch",
            "target": "branch",
            "source_type": "Organization",
            "source": self.owner.clone(),
            "enforcement": "active"
        }]));
        self.branch_rules = Response::Ok(json!([
            {
                "type": "pull_request",
                "source_type": "Organization",
                "parameters": { "allowed_merge_methods": ["squash", "rebase"] }
            },
            { "type": "required_linear_history", "source_type": "Organization" }
        ]));
        self
    }

    /// Replace the rulesets response, for the plan-limitation path.
    #[must_use]
    pub fn with_rulesets(mut self, response: Response) -> Self {
        self.rulesets = response;
        self
    }

    /// Report the recursive tree as truncated, as GitHub does for very large
    /// repositories.
    #[must_use]
    pub fn with_truncated_tree(mut self) -> Self {
        self.tree_truncated = true;
        self
    }

    /// Add a tree entry airlock cannot decode.
    #[must_use]
    pub fn with_malformed_tree_entry(mut self, path: &str) -> Self {
        self.malformed_tree_entry = Some(json!({
            "path": path,
            "mode": "999999",
            "type": "blob",
            "sha": "ffff"
        }));
        self
    }

    fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    async fn mount(&self, server: &MockServer) {
        let prefix = format!("/repos/{}", self.full_name());

        mount(server, &prefix, Response::Ok(self.settings.clone())).await;
        mount(
            server,
            &format!("{prefix}/topics"),
            Response::Ok(json!({ "names": self.topics })),
        )
        .await;
        mount(
            server,
            &format!("{prefix}/properties/values"),
            Response::Ok(Value::Array(
                self.custom_properties
                    .iter()
                    .map(|(property_name, value)| {
                        json!({"property_name": property_name, "value": value})
                    })
                    .collect(),
            )),
        )
        .await;
        for reference in ["main", "HEAD", COMMIT] {
            mount(
                server,
                &format!("{prefix}/commits/{reference}"),
                Response::Ok(json!({ "sha": COMMIT })),
            )
            .await;
        }

        let mut tree = Vec::new();
        let mut blobs: BTreeMap<String, String> = BTreeMap::new();
        let mut directories: Vec<String> = Vec::new();
        for (index, (file, content)) in self.files.iter().enumerate() {
            let sha = format!("{index:040x}");
            tree.push(json!({
                "path": file,
                "mode": "100644",
                "type": "blob",
                "sha": sha,
                "size": content.len()
            }));
            blobs.insert(sha, content.clone());

            // Parent directories are real tree entries on GitHub, and some
            // rules ask about directories rather than files.
            let mut parts: Vec<&str> = file.split('/').collect();
            parts.pop();
            let mut prefix_path = String::new();
            for part in parts {
                if !prefix_path.is_empty() {
                    prefix_path.push('/');
                }
                prefix_path.push_str(part);
                if !directories.contains(&prefix_path) {
                    directories.push(prefix_path.clone());
                }
            }
        }
        for (index, directory) in directories.iter().enumerate() {
            tree.push(json!({
                "path": directory,
                "mode": "040000",
                "type": "tree",
                "sha": format!("d{index:039x}")
            }));
        }

        if let Some(entry) = &self.malformed_tree_entry {
            tree.push(entry.clone());
        }

        mount(
            server,
            &format!("{prefix}/git/trees/{COMMIT}"),
            Response::Ok(json!({
                "sha": COMMIT,
                "truncated": self.tree_truncated,
                "tree": tree
            })),
        )
        .await;

        for (sha, content) in &blobs {
            mount(
                server,
                &format!("{prefix}/git/blobs/{sha}"),
                Response::Ok(json!({
                    "sha": sha,
                    "encoding": "base64",
                    "content": base64(content)
                })),
            )
            .await;
        }

        let tags: Vec<Value> = self
            .tags
            .iter()
            .map(|tag| json!({ "ref": format!("refs/tags/{tag}"), "object": { "sha": COMMIT } }))
            .collect();
        mount(
            server,
            &format!("{prefix}/git/matching-refs/tags/"),
            Response::Ok(Value::Array(tags)),
        )
        .await;

        let commits: Vec<Value> = self
            .history
            .iter()
            .map(|(sha, parents)| {
                json!({ "sha": sha, "parents": vec![json!({"sha": "0"}); *parents] })
            })
            .collect();
        mount(
            server,
            &format!("{prefix}/commits"),
            Response::Ok(Value::Array(commits)),
        )
        .await;

        mount_response(server, &format!("{prefix}/rulesets"), &self.rulesets).await;
        mount_response(
            server,
            &format!("{prefix}/rules/branches/main"),
            &self.branch_rules,
        )
        .await;
    }
}

async fn mount(server: &MockServer, route: &str, response: Response) {
    mount_response(server, route, &response).await;
}

async fn mount_response(server: &MockServer, route: &str, response: &Response) {
    Mock::given(method("GET"))
        .and(path(route.to_owned()))
        .respond_with(response.template())
        .mount(server)
        .await;
}

fn base64(content: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(content)
}

/// Start a fake GitHub serving the given repositories, with a verified
/// read-only Airlock Safe credential.
pub async fn start(repos: &[FakeRepo]) -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user/installations"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-ratelimit-remaining", "4999")
                .set_body_json(json!({
                    "total_count": 1,
                    "installations": [{
                        "id": 1,
                        "app_id": 4_409_712,
                        "app_slug": "airlock-safe",
                        "account": { "login": "wyrd-company" },
                        "permissions": { "metadata": "read", "contents": "read" }
                    }]
                })),
        )
        .mount(&server)
        .await;

    for repo in repos {
        repo.mount(&server).await;
    }
    server
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn the_encoder_matches_the_known_vectors() {
        assert_eq!(base64(""), "");
        assert_eq!(base64("f"), "Zg==");
        assert_eq!(base64("fo"), "Zm8=");
        assert_eq!(base64("foo"), "Zm9v");
        assert_eq!(base64("foob"), "Zm9vYg==");
        assert_eq!(base64("hello world"), "aGVsbG8gd29ybGQ=");
    }
}
