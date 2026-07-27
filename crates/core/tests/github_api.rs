//! The GitHub client and credential verification, against simulated GitHub.
//!
//! Every response here is a fixture served by `wiremock`. Nothing in this file
//! reaches `api.github.com`.

use airlock_core::auth::{verify, TokenKind, AIRLOCK_SAFE_APP_SLUG};
use airlock_core::github::{ErrorCause, GitHub, RestClient, RestClientConfig};
use serde_json::json;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> RestClient {
    RestClient::new(
        "ghu_fixture_token",
        RestClientConfig {
            base_url: server.uri(),
            max_rate_limit_retries: 0,
            ..RestClientConfig::default()
        },
    )
    .expect("the client builds")
}

fn quota_headers(template: ResponseTemplate) -> ResponseTemplate {
    template
        .insert_header("x-ratelimit-remaining", "4999")
        .insert_header("x-github-request-id", "FIXT:0001")
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_permission_403_names_the_permission_the_endpoint_wanted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/rulesets"))
        .respond_with(
            quota_headers(ResponseTemplate::new(403))
                .insert_header("x-accepted-github-permissions", "administration=read")
                .set_body_json(json!({
                    "message": "Resource not accessible by integration",
                    "documentation_url": "https://docs.github.com/rest/repos/rules"
                })),
        )
        .mount(&server)
        .await;

    let error = client(&server)
        .rulesets("owner", "name")
        .await
        .expect_err("a 403 is a failure");
    assert_eq!(error.cause, ErrorCause::Permission);
    assert_eq!(
        error.accepted_permissions.as_deref(),
        Some("administration=read")
    );
    assert_eq!(error.request_id.as_deref(), Some("FIXT:0001"));
    assert_eq!(
        error.documentation_url.as_deref(),
        Some("https://docs.github.com/rest/repos/rules")
    );
}

#[tokio::test]
async fn a_plan_limitation_403_is_not_mistaken_for_a_permission_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/rulesets"))
        .respond_with(quota_headers(ResponseTemplate::new(403)).set_body_json(json!({
            "message": "Upgrade to GitHub Pro or make this repository public to enable this feature.",
            "documentation_url": "https://docs.github.com/rest/branches/branch-protection"
        })))
        .mount(&server)
        .await;

    let error = client(&server).rulesets("owner", "name").await.unwrap_err();
    assert_eq!(error.cause, ErrorCause::PlanLimitation);
}

#[tokio::test]
async fn an_unknown_403_is_never_guessed_into_a_known_class() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/rulesets"))
        .respond_with(quota_headers(ResponseTemplate::new(403)).set_body_json(json!({
            "message": "Your organization has a policy that airlock has never seen"
        })))
        .mount(&server)
        .await;

    let error = client(&server).rulesets("owner", "name").await.unwrap_err();
    assert_eq!(error.cause, ErrorCause::UnknownAccess);
}

#[tokio::test]
async fn a_repository_404_is_reported_as_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(
            quota_headers(ResponseTemplate::new(404))
                .set_body_json(json!({ "message": "Not Found" })),
        )
        .mount(&server)
        .await;

    let error = client(&server).repository("owner", "name").await.unwrap_err();
    assert_eq!(error.cause, ErrorCause::NotFound);
    assert_eq!(error.endpoint, "GET /repos/owner/name");
}

#[tokio::test]
async fn a_feature_off_404_is_still_a_not_found_for_the_check_to_interpret() {
    // Secret scanning answers 404 when the feature is off. The client does not
    // pretend to know which; the check that called it does.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/rules/branches/main"))
        .respond_with(quota_headers(ResponseTemplate::new(404)).set_body_json(json!({
            "message": "Repository is public or secret scanning is disabled for the repository"
        })))
        .mount(&server)
        .await;

    let error = client(&server)
        .branch_rules("owner", "name", "main")
        .await
        .unwrap_err();
    assert_eq!(error.cause, ErrorCause::NotFound);
}

#[tokio::test]
async fn an_exhausted_rate_limit_is_classified_from_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("x-ratelimit-reset", "99999999999")
                .set_body_json(json!({ "message": "API rate limit exceeded" })),
        )
        .mount(&server)
        .await;

    let error = client(&server).repository("owner", "name").await.unwrap_err();
    assert_eq!(error.cause, ErrorCause::RateLimit);
}

#[tokio::test]
async fn a_401_is_an_authentication_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Bad credentials"
        })))
        .mount(&server)
        .await;

    let error = client(&server).authenticated_user().await.unwrap_err();
    assert_eq!(error.cause, ErrorCause::Unauthenticated);
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_repository_snapshot_reads_settings_and_the_observation_time() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200))
                .insert_header("date", "Mon, 27 Jul 2026 12:00:00 GMT")
                .set_body_json(json!({
                    "id": 42,
                    "name": "name",
                    "full_name": "owner/name",
                    "owner": { "login": "owner" },
                    "default_branch": "main",
                    "visibility": "public",
                    "description": "A thing that does a thing.",
                    "license": { "spdx_id": "Apache-2.0" },
                    "allow_merge_commit": false,
                    "allow_squash_merge": true,
                    "allow_rebase_merge": true,
                    "delete_branch_on_merge": true,
                    "has_wiki": false,
                    "has_projects": false,
                    "has_discussions": false,
                    "has_issues": true
                })),
        )
        .mount(&server)
        .await;

    let repository = client(&server).repository("owner", "name").await.unwrap();
    assert_eq!(repository.id, 42);
    assert_eq!(repository.default_branch, "main");
    assert_eq!(repository.license_spdx.as_deref(), Some("Apache-2.0"));
    assert!(!repository.allow_merge_commit);
    assert_eq!(
        repository.observed_at.as_deref(),
        Some("Mon, 27 Jul 2026 12:00:00 GMT")
    );
}

#[tokio::test]
async fn a_tree_distinguishes_blobs_symlinks_trees_and_submodules() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/trees/abc"))
        .and(query_param("recursive", "1"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200)).set_body_json(json!({
                "sha": "abc",
                "truncated": false,
                "tree": [
                    { "path": "README.md", "mode": "100644", "type": "blob", "sha": "1", "size": 12 },
                    { "path": "CLAUDE.md", "mode": "120000", "type": "blob", "sha": "2", "size": 9 },
                    { "path": "docs", "mode": "040000", "type": "tree", "sha": "3" },
                    { "path": "vendor/thing", "mode": "160000", "type": "commit", "sha": "4" },
                    { "path": "script.sh", "mode": "100755", "type": "blob", "sha": "5", "size": 3 }
                ]
            })),
        )
        .mount(&server)
        .await;

    let tree = client(&server).tree("owner", "name", "abc").await.unwrap();
    assert_eq!(tree.entries.len(), 5);
    assert!(!tree.truncated);
    let kinds: Vec<&str> = tree
        .entries
        .iter()
        .map(|entry| match entry.kind {
            airlock_core::github::EntryKind::Blob => "blob",
            airlock_core::github::EntryKind::ExecutableBlob => "exec",
            airlock_core::github::EntryKind::Symlink => "symlink",
            airlock_core::github::EntryKind::Tree => "tree",
            airlock_core::github::EntryKind::Submodule => "submodule",
        })
        .collect();
    assert_eq!(kinds, vec!["blob", "symlink", "tree", "submodule", "exec"]);
}

#[tokio::test]
async fn a_blob_is_decoded_from_base64() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/blobs/1"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200)).set_body_json(json!({
                "sha": "1",
                "encoding": "base64",
                // GitHub wraps base64 at 60 columns; the newline must not break decoding.
                "content": "QUdFTlRT\nLm1k\n"
            })),
        )
        .mount(&server)
        .await;

    let blob = client(&server).blob("owner", "name", "1").await.unwrap();
    assert_eq!(String::from_utf8(blob).unwrap(), "AGENTS.md");
}

#[tokio::test]
async fn a_repository_without_tags_answers_an_empty_list_rather_than_failing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/refs/tags"))
        .respond_with(
            quota_headers(ResponseTemplate::new(404))
                .set_body_json(json!({ "message": "Not Found" })),
        )
        .mount(&server)
        .await;

    assert!(client(&server).tags("owner", "name").await.unwrap().is_empty());
}

#[tokio::test]
async fn history_reports_when_the_walk_stopped_at_the_budget() {
    let server = MockServer::start().await;
    let commits: Vec<_> = (0..10)
        .map(|index| json!({ "sha": format!("{index:040}"), "parents": [ { "sha": "x" } ] }))
        .collect();
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/commits"))
        .respond_with(quota_headers(ResponseTemplate::new(200)).set_body_json(commits))
        .mount(&server)
        .await;

    let (walked, truncated) = client(&server)
        .history("owner", "name", "abc", 4)
        .await
        .unwrap();
    assert_eq!(walked.len(), 4);
    assert!(truncated, "a walk stopped by the budget must say so");
}

// ---------------------------------------------------------------------------
// Credential verification
// ---------------------------------------------------------------------------

fn installation(id: u64, slug: &str, permissions: &[(&str, &str)]) -> serde_json::Value {
    json!({
        "id": id,
        "app_id": 1,
        "app_slug": slug,
        "account": { "login": format!("account-{id}") },
        "permissions": permissions
            .iter()
            .map(|(name, level)| ((*name).to_owned(), json!(level)))
            .collect::<serde_json::Map<_, _>>()
    })
}

async fn mount_installations(server: &MockServer, page: &str, body: serde_json::Value) {
    let mut template = quota_headers(ResponseTemplate::new(200)).set_body_json(body);
    if page == "1" {
        template = template.insert_header(
            "link",
            format!("<{}/user/installations?page=2>; rel=\"next\"", server.uri()).as_str(),
        );
    }
    let mock = Mock::given(method("GET")).and(path("/user/installations"));
    let mock = if page == "1" {
        mock.and(query_param_is_missing("page"))
    } else {
        mock.and(query_param("page", page))
    };
    mock.respond_with(template).mount(server).await;
}

#[tokio::test]
async fn an_airlock_safe_token_with_only_read_permissions_verifies() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/installations"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200)).set_body_json(json!({
                "total_count": 1,
                "installations": [installation(1, AIRLOCK_SAFE_APP_SLUG, &[("metadata", "read"), ("contents", "read")])]
            })),
        )
        .mount(&server)
        .await;

    let grant = verify("ghu_fixture_token", &client(&server)).await.unwrap();
    assert_eq!(grant.kind, TokenKind::AppUser);
    assert_eq!(grant.issuer.as_deref(), Some(AIRLOCK_SAFE_APP_SLUG));
    assert_eq!(grant.visible_accounts(), vec!["account-1".to_owned()]);
}

#[tokio::test]
async fn a_token_with_zero_installations_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/installations"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200))
                .set_body_json(json!({ "total_count": 0, "installations": [] })),
        )
        .mount(&server)
        .await;

    let refusal = verify("ghu_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "no_installations");
}

#[tokio::test]
async fn a_token_from_another_app_is_refused_as_unverifiable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/installations"))
        .respond_with(
            quota_headers(ResponseTemplate::new(200)).set_body_json(json!({
                "total_count": 1,
                "installations": [installation(1, "some-other-app", &[("metadata", "read")])]
            })),
        )
        .mount(&server)
        .await;

    let refusal = verify("ghu_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "foreign_issuer");
}

#[tokio::test]
async fn a_write_bearing_installation_on_the_second_page_is_still_caught() {
    let server = MockServer::start().await;
    mount_installations(
        &server,
        "1",
        json!({
            "total_count": 2,
            "installations": [installation(1, AIRLOCK_SAFE_APP_SLUG, &[("metadata", "read")])]
        }),
    )
    .await;
    mount_installations(
        &server,
        "2",
        json!({
            "total_count": 2,
            "installations": [installation(2, AIRLOCK_SAFE_APP_SLUG, &[("metadata", "read"), ("checks", "write")])]
        }),
    )
    .await;

    let refusal = verify("ghu_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "write_permission");
    assert!(refusal.detail.contains("checks=write"));
}

#[tokio::test]
async fn more_than_a_hundred_installations_are_all_walked() {
    let server = MockServer::start().await;
    let first: Vec<_> = (1..=100)
        .map(|id| installation(id, AIRLOCK_SAFE_APP_SLUG, &[("metadata", "read")]))
        .collect();
    mount_installations(
        &server,
        "1",
        json!({ "total_count": 101, "installations": first }),
    )
    .await;
    mount_installations(
        &server,
        "2",
        json!({
            "total_count": 101,
            "installations": [installation(101, AIRLOCK_SAFE_APP_SLUG, &[("metadata", "read")])]
        }),
    )
    .await;

    let grant = verify("ghu_fixture_token", &client(&server)).await.unwrap();
    assert_eq!(grant.installations.len(), 101);
}

async fn mount_user(server: &MockServer, scopes: Option<&str>) {
    let mut template = quota_headers(ResponseTemplate::new(200))
        .set_body_json(json!({ "login": "example-user", "id": 1 }));
    if let Some(scopes) = scopes {
        template = template.insert_header("x-oauth-scopes", scopes);
    }
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(template)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_classic_token_with_only_read_scopes_verifies() {
    let server = MockServer::start().await;
    mount_user(&server, Some("read:org, read:user")).await;

    let grant = verify("ghp_fixture_token", &client(&server)).await.unwrap();
    assert_eq!(grant.kind, TokenKind::ClassicPat);
    assert_eq!(grant.scopes, vec!["read:org", "read:user"]);
    assert_eq!(grant.login.as_deref(), Some("example-user"));
}

#[tokio::test]
async fn a_classic_token_with_a_write_scope_is_refused() {
    let server = MockServer::start().await;
    mount_user(&server, Some("read:org, public_repo")).await;

    let refusal = verify("ghp_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "non_read_scope");
    assert!(refusal.detail.contains("public_repo"));
}

#[tokio::test]
async fn a_classic_token_with_an_unknown_scope_is_refused() {
    let server = MockServer::start().await;
    mount_user(&server, Some("read:org, read:something_new")).await;

    let refusal = verify("gho_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "non_read_scope");
}

#[tokio::test]
async fn a_missing_scope_header_is_unverifiable_not_an_empty_grant() {
    let server = MockServer::start().await;
    mount_user(&server, None).await;

    let refusal = verify("ghp_fixture_token", &client(&server))
        .await
        .unwrap_err();
    assert_eq!(refusal.code, "missing_scope_header");
}

#[tokio::test]
async fn an_empty_scope_header_is_an_enumerated_empty_grant() {
    let server = MockServer::start().await;
    mount_user(&server, Some("")).await;

    let grant = verify("ghp_fixture_token", &client(&server)).await.unwrap();
    assert!(grant.scopes.is_empty());
}

#[tokio::test]
async fn unverifiable_token_kinds_are_refused_without_any_request() {
    let server = MockServer::start().await;
    // No mocks are mounted: a request would fail the test by 404-ing.
    for (token, code) in [
        ("github_pat_11ABCDE", "unverifiable_fine_grained_pat"),
        ("ghs_installationtoken", "unverifiable_installation_token"),
        ("ghr_refreshtoken", "refresh_token_supplied"),
        ("plain-old-string", "unverifiable_unknown_token"),
    ] {
        let refusal = verify(token, &client(&server)).await.unwrap_err();
        assert_eq!(refusal.code, code, "{token}");
    }
}
