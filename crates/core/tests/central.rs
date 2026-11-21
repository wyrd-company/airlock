//! Central mode's sign-in, against fake Entra ID, Key Vault and GitHub.
//!
//! One `wiremock` server plays all three, and the job's OpenID Connect
//! endpoint. Every credential it hands out is a distinct marker, so a test can
//! show that no message carries a token, an assertion or a signature.

use std::sync::Arc;

use airlock_core::audit::AuditOptions;
use airlock_core::auth::{TokenKind, AIRLOCK_SAFE_APP_ID};
use airlock_core::central::{
    jwt_signing_input, sign_in, CentralConfig, CentralError, CentralInputs, Endpoints, OidcRequest,
    Step,
};
use airlock_core::findings::AuditResult;
use airlock_core::github::RestClientConfig;
use airlock_core::limits::Limits;
use airlock_core::policy::PolicySource;
use airlock_core::rules::CredentialCapability;
use airlock_core::transport::{ReqwestTransport, Transport};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const OIDC_REQUEST_TOKEN: &str = "oidc-request-token-MARKER1";
const ASSERTION: &str = "eyJassertionMARKER2";
const VAULT_TOKEN: &str = "vault-access-token-MARKER3";
const SIGNATURE: &[u8] = b"rs256-signature-bytes-MARKER4";
const MINTED: &str = "ghs_minted_MARKER5";
const TENANT: &str = "11111111-2222-3333-4444-555555555555";
const CLIENT: &str = "66666666-7777-8888-9999-000000000000";
const INSTALLATION: u64 = 77;

fn signature() -> String {
    URL_SAFE_NO_PAD.encode(SIGNATURE)
}

/// Every value no output may contain.
fn secrets() -> Vec<String> {
    vec![
        OIDC_REQUEST_TOKEN.to_owned(),
        ASSERTION.to_owned(),
        VAULT_TOKEN.to_owned(),
        signature(),
        MINTED.to_owned(),
    ]
}

fn assert_carries_no_secret(error: &CentralError) {
    let rendered = format!("{error} {error:?}");
    for secret in secrets() {
        assert!(!rendered.contains(&secret), "{rendered} leaks {secret}");
    }
}

/// Matches a request whose bearer is a JSON Web Token Key Vault signed.
struct SignedByKeyVault;

impl Match for SignedByKeyVault {
    fn matches(&self, request: &Request) -> bool {
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.ends_with(&format!(".{}", signature())))
    }
}

/// Mount the happy path at a low priority, so a test overrides one step by
/// mounting its own answer at the default priority.
async fn fake() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oidc"))
        .and(query_param("audience", "api://AzureADTokenExchange"))
        .and(header(
            "authorization",
            format!("Bearer {OIDC_REQUEST_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": ASSERTION })))
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/{TENANT}/oauth2/v2.0/token")))
        .and(body_string_contains(format!(
            "client_assertion={ASSERTION}"
        )))
        .and(body_string_contains(format!("client_id={CLIENT}")))
        .and(body_string_contains(
            "scope=https%3A%2F%2Fvault.azure.net%2F.default",
        ))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "access_token": VAULT_TOKEN
        })))
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/keys/airlock-safe//sign"))
        .and(query_param("api-version", "7.4"))
        .and(header(
            "authorization",
            format!("Bearer {VAULT_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": "https://vault/keys/airlock-safe/0123",
            "value": signature()
        })))
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/app"))
        .and(SignedByKeyVault)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": AIRLOCK_SAFE_APP_ID,
            "slug": "airlock-safe",
            "permissions": {
                "metadata": "read",
                "contents": "read",
                "administration": "read",
                "organization_administration": "read"
            }
        })))
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/wyrd-company/installation"))
        .and(SignedByKeyVault)
        .respond_with(ResponseTemplate::new(200).set_body_json(installation("all")))
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .and(SignedByKeyVault)
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(minted(&[("metadata", "read"), ("contents", "read")])),
        )
        .with_priority(10)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/installation/token"))
        .and(header("authorization", format!("Bearer {MINTED}").as_str()))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(10)
        .mount(&server)
        .await;

    server
}

fn installation(selection: &str) -> Value {
    json!({
        "id": INSTALLATION,
        "app_id": AIRLOCK_SAFE_APP_ID,
        "app_slug": "airlock-safe",
        "account": { "login": "wyrd-company", "type": "Organization" },
        "repository_selection": selection,
        "permissions": { "metadata": "read", "contents": "read" }
    })
}

fn minted(permissions: &[(&str, &str)]) -> Value {
    let permissions: serde_json::Map<String, Value> = permissions
        .iter()
        .map(|(name, level)| ((*name).to_owned(), Value::String((*level).to_owned())))
        .collect();
    json!({
        "token": MINTED,
        "expires_at": "2026-11-17T18:00:00Z",
        "permissions": permissions,
        "repository_selection": "all"
    })
}

fn config(server: &MockServer) -> CentralConfig {
    CentralConfig::parse(
        "wyrd-company",
        &CentralInputs {
            app_id: AIRLOCK_SAFE_APP_ID.to_string(),
            key_name: "airlock-safe".to_owned(),
            installation_repositories: "wyrd-company/*".to_owned(),
            vault_url: server.uri(),
            azure_tenant_id: TENANT.to_owned(),
            azure_client_id: CLIENT.to_owned(),
        },
    )
    .expect("the fixture inputs validate")
}

fn oidc(server: &MockServer) -> OidcRequest {
    let url = format!("{}/oidc", server.uri());
    OidcRequest::from_lookup(|name| match name {
        "ACTIONS_ID_TOKEN_REQUEST_URL" => Some(url.clone()),
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN" => Some(OIDC_REQUEST_TOKEN.to_owned()),
        _ => None,
    })
    .expect("the job can request a token")
}

fn native() -> Arc<dyn Transport> {
    Arc::new(
        ReqwestTransport::new(Limits::default().connect_timeout).expect("the transport builds"),
    )
}

fn endpoints(server: &MockServer) -> Endpoints {
    Endpoints {
        github_api: server.uri(),
        azure_login: server.uri(),
    }
}

async fn refused(server: &MockServer) -> CentralError {
    let error = sign_in(
        &config(server),
        &oidc(server),
        &endpoints(server),
        Limits::default(),
        native(),
    )
    .await
    .expect_err("the sign-in is refused");
    assert_carries_no_secret(&error);
    error
}

async fn requests_to(server: &MockServer, verb: &str, route: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.method.as_str() == verb && request.url.path() == route)
        .collect()
}

#[tokio::test]
async fn central_mode_signs_in_as_airlock_safe_and_mints_a_read_only_token() {
    let server = fake().await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the sign-in succeeds");

    assert_eq!(session.token(), MINTED);
    assert_eq!(session.installation_id, INSTALLATION);
    assert_eq!(session.grant.kind, TokenKind::Installation);
    assert_eq!(session.grant.issuer.as_deref(), Some("airlock-safe"));
    assert_eq!(
        session.grant.installations[0].permissions,
        vec!["contents=read", "metadata=read"]
    );
    assert_eq!(session.grant.capability(), CredentialCapability::ReadOnly);
    assert!(!format!("{session:?}").contains(MINTED));

    // Key Vault signed the SHA-256 of exactly the signing input GitHub was
    // shown, and the JSON Web Token is that input and Key Vault's signature.
    let sign = requests_to(&server, "POST", "/keys/airlock-safe//sign").await;
    assert_eq!(sign.len(), 1);
    let sign_body: Value = serde_json::from_slice(&sign[0].body).unwrap();
    assert_eq!(sign_body["alg"], "RS256");
    let app = requests_to(&server, "GET", "/app").await;
    let bearer = app[0].headers["authorization"].to_str().unwrap();
    let jwt = bearer.strip_prefix("Bearer ").unwrap();
    let (signing_input, signed) = jwt.rsplit_once('.').unwrap();
    assert_eq!(signed, signature());
    assert_eq!(
        sign_body["value"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(signing_input.as_bytes()))
    );
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signing_input.split_once('.').unwrap().1)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iss"], "4409712");
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
    let reference = jwt_signing_input(AIRLOCK_SAFE_APP_ID, claims["iat"].as_u64().unwrap() + 60);
    assert_eq!(signing_input, reference);

    // The token was minted for the whole installation, with no narrowing.
    let mint = requests_to(
        &server,
        "POST",
        &format!("/app/installations/{INSTALLATION}/access_tokens"),
    )
    .await;
    assert_eq!(mint.len(), 1);

    session.revoke().await.expect("the token is revoked");
    assert_eq!(
        requests_to(&server, "DELETE", "/installation/token")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn a_user_owner_is_found_on_its_own_route() {
    let server = fake().await;
    Mock::given(method("GET"))
        .and(path("/orgs/wyrd-company/installation"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/wyrd-company/installation"))
        .and(SignedByKeyVault)
        .respond_with(ResponseTemplate::new(200).set_body_json(installation("all")))
        .mount(&server)
        .await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the user installation is found");
    assert_eq!(session.installation_id, INSTALLATION);
}

#[tokio::test]
async fn a_refused_oidc_request_stops_at_azure_sign_in() {
    let server = fake().await;
    Mock::given(method("GET"))
        .and(path("/oidc"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::AzureSignIn);
    assert_eq!(error.status, Some(403));
}

#[tokio::test]
async fn a_job_without_a_federated_credential_stops_at_azure_sign_in() {
    let server = fake().await;
    Mock::given(method("POST"))
        .and(path(format!("/{TENANT}/oauth2/v2.0/token")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client",
            "error_description": format!("AADSTS70021: No matching federated identity record for {ASSERTION}")
        })))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::AzureSignIn);
    assert_eq!(error.status, Some(400));
    assert_eq!(error.code.as_deref(), Some("invalid_client"));
}

#[tokio::test]
async fn a_key_vault_refusal_stops_at_key_vault_sign() {
    let server = fake().await;
    Mock::given(method("POST"))
        .and(path("/keys/airlock-safe//sign"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": "Forbidden", "message": "Caller is not authorized" }
        })))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::KeyVaultSign);
    assert_eq!(error.status, Some(403));
    assert_eq!(error.code.as_deref(), Some("Forbidden"));
    assert!(requests_to(&server, "GET", "/app").await.is_empty());
}

async fn app_answers(app: Value) -> CentralError {
    let server = fake().await;
    Mock::given(method("GET"))
        .and(path("/app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(app))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert!(
        requests_to(&server, "GET", "/orgs/wyrd-company/installation")
            .await
            .is_empty(),
        "nothing after the App check"
    );
    error
}

#[tokio::test]
async fn a_key_that_signs_for_another_app_stops_at_app_identity() {
    let another_id = app_answers(json!({
        "id": 4_409_767, "slug": "airlock-safe", "permissions": {"metadata": "read"}
    }))
    .await;
    assert_eq!(another_id.step, Step::AppIdentity);

    let another_slug = app_answers(json!({
        "id": AIRLOCK_SAFE_APP_ID, "slug": "airlock-admin", "permissions": {"metadata": "read"}
    }))
    .await;
    assert_eq!(another_slug.step, Step::AppIdentity);
}

#[tokio::test]
async fn an_app_registered_with_a_write_permission_stops_at_app_identity() {
    let error = app_answers(json!({
        "id": AIRLOCK_SAFE_APP_ID,
        "slug": "airlock-safe",
        "permissions": {"metadata": "read", "contents": "write"}
    }))
    .await;
    assert_eq!(error.step, Step::AppIdentity);
    assert!(error.detail.contains("contents=write"), "{error}");

    let unread = app_answers(json!({ "id": AIRLOCK_SAFE_APP_ID, "slug": "airlock-safe" })).await;
    assert_eq!(unread.step, Step::AppIdentity);
}

#[tokio::test]
async fn an_owner_without_the_installation_stops_at_installation_lookup() {
    let server = fake().await;
    for route in [
        "/orgs/wyrd-company/installation",
        "/users/wyrd-company/installation",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "Not Found"})))
            .mount(&server)
            .await;
    }
    let error = refused(&server).await;
    assert_eq!(error.step, Step::InstallationLookup);
    assert_eq!(error.status, Some(404));
}

#[tokio::test]
async fn an_installation_on_selected_repositories_stops_at_installation_scope() {
    let server = fake().await;
    Mock::given(method("GET"))
        .and(path("/orgs/wyrd-company/installation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(installation("selected")))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::InstallationScope);
    assert!(
        requests_to(
            &server,
            "POST",
            &format!("/app/installations/{INSTALLATION}/access_tokens")
        )
        .await
        .is_empty(),
        "no token is minted"
    );
}

#[tokio::test]
async fn installation_repositories_other_than_the_owner_stop_at_installation_scope() {
    let server = fake().await;
    let config = CentralConfig::parse(
        "wyrd-company",
        &CentralInputs {
            app_id: AIRLOCK_SAFE_APP_ID.to_string(),
            key_name: "airlock-safe".to_owned(),
            installation_repositories: "wyrd-company/organization-audit".to_owned(),
            vault_url: server.uri(),
            azure_tenant_id: TENANT.to_owned(),
            azure_client_id: CLIENT.to_owned(),
        },
    )
    .unwrap();
    let error = sign_in(
        &config,
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.step, Step::InstallationScope);
    assert_carries_no_secret(&error);
}

#[tokio::test]
async fn a_refused_token_request_stops_at_token_request() {
    let server = fake().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": "The permissions requested are not granted to this installation."
        })))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::TokenRequest);
    assert_eq!(error.status, Some(422));
}

#[tokio::test]
async fn a_minted_token_with_a_write_permission_is_refused_and_revoked() {
    let server = fake().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(minted(&[("metadata", "read"), ("issues", "write")])),
        )
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::TokenRequest);
    assert!(error.detail.contains("issues=write"), "{error}");
    assert!(error.detail.contains("revoked"), "{error}");
    assert_eq!(
        requests_to(&server, "DELETE", "/installation/token")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn a_minted_token_listing_no_permissions_is_refused() {
    let server = fake().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(minted(&[])))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::TokenRequest);
}

#[tokio::test]
async fn an_installation_of_another_app_stops_at_installation_lookup() {
    let server = fake().await;
    let mut foreign = installation("all");
    foreign["app_id"] = json!(4_409_767);
    Mock::given(method("GET"))
        .and(path("/orgs/wyrd-company/installation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(foreign))
        .mount(&server)
        .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::InstallationLookup);
}

#[tokio::test]
async fn a_listing_cut_short_makes_the_central_run_incomplete() {
    let server = fake().await;
    // One page that links to a second: with a one-page budget the walk stops
    // there, so a repository the installation reaches is never seen.
    Mock::given(method("GET"))
        .and(path("/installation/repositories"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    format!(
                        "<{}/installation/repositories?page=2>; rel=\"next\"",
                        server.uri()
                    )
                    .as_str(),
                )
                .set_body_json(json!({ "total_count": 1, "repositories": [] })),
        )
        .mount(&server)
        .await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the sign-in succeeds");

    let policies = tempfile::tempdir().unwrap();
    let policy = policies.path().join("policy.yml");
    std::fs::write(&policy, "version: 0.6.0\n").unwrap();
    let limits = Limits {
        max_pages: 1,
        ..Limits::default()
    };
    let report = airlock_core::central_audit::run(
        &session,
        "wyrd-company",
        &RestClientConfig {
            base_url: server.uri(),
            max_rate_limit_retries: 0,
            ..RestClientConfig::from_limits(limits)
        },
        Some(PolicySource::parse(&policy.display().to_string()).unwrap()),
        &AuditOptions {
            limits,
            version: "0.0.0".to_owned(),
            ..AuditOptions::default()
        },
    )
    .await
    .expect("the run reports");
    assert_eq!(report.outcome, AuditResult::Incomplete);
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
    assert!(report.run_errors[0].contains("page budget"), "{report:?}");
}

// ---------------------------------------------------------------------------
// Echoes: a service that repeats the credentials it was sent
// ---------------------------------------------------------------------------
//
// Every credential here is a synthetic placeholder. Each fake puts all of
// them in every free-form field it answers with; no message may carry one.

fn echo() -> String {
    format!(
        "Bearer {OIDC_REQUEST_TOKEN} {ASSERTION} {VAULT_TOKEN} {} {MINTED}",
        signature()
    )
}

async fn answer(server: &MockServer, verb: &str, route: &str, response: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(route.to_owned()))
        .respond_with(response)
        .mount(server)
        .await;
}

#[tokio::test]
async fn entra_id_text_is_never_repeated_and_only_its_vetted_codes_are() {
    let server = fake().await;
    answer(
        &server,
        "POST",
        &format!("/{TENANT}/oauth2/v2.0/token"),
        ResponseTemplate::new(400).set_body_json(json!({
            "error": echo(),
            "error_description": echo(),
            "error_codes": [70021],
            "trace_id": echo()
        })),
    )
    .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::AzureSignIn);
    assert_eq!(error.code.as_deref(), Some("AADSTS70021"));

    let server = fake().await;
    answer(
        &server,
        "POST",
        &format!("/{TENANT}/oauth2/v2.0/token"),
        ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": echo(),
            "error_codes": [700213]
        })),
    )
    .await;
    assert_eq!(
        refused(&server).await.code.as_deref(),
        Some("invalid_client, AADSTS700213")
    );
}

#[tokio::test]
async fn key_vault_text_is_never_repeated_and_only_its_vetted_codes_are() {
    let server = fake().await;
    answer(
        &server,
        "POST",
        "/keys/airlock-safe//sign",
        ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": echo(), "message": echo() }
        })),
    )
    .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::KeyVaultSign);
    assert_eq!(error.code, None);
}

#[tokio::test]
async fn github_refusal_text_is_never_repeated_at_any_step() {
    for (verb, route, status, step) in [
        ("GET", "/app".to_owned(), 401, Step::AppIdentity),
        (
            "GET",
            "/orgs/wyrd-company/installation".to_owned(),
            403,
            Step::InstallationLookup,
        ),
        (
            "POST",
            format!("/app/installations/{INSTALLATION}/access_tokens"),
            422,
            Step::TokenRequest,
        ),
    ] {
        let server = fake().await;
        answer(
            &server,
            verb,
            &route,
            ResponseTemplate::new(status)
                .insert_header("x-github-request-id", echo().as_str())
                .set_body_json(json!({
                    "message": echo(),
                    "documentation_url": echo()
                })),
        )
        .await;
        let error = refused(&server).await;
        assert_eq!(error.step, step, "{route}");
        assert_eq!(error.status, Some(status));
        assert_eq!(error.code, None);
    }
}

#[tokio::test]
async fn app_and_installation_fields_are_checked_without_being_repeated() {
    let mut slug = json!({
        "id": AIRLOCK_SAFE_APP_ID, "slug": echo(), "permissions": {"metadata": "read"}
    });
    assert_eq!(app_answers(slug.take()).await.step, Step::AppIdentity);

    let mut named = json!({
        "id": AIRLOCK_SAFE_APP_ID, "slug": "airlock-safe",
        "permissions": {"metadata": "read"}
    });
    // Short enough to pass the length bound, so the name's own shape is
    // what refuses it.
    named["permissions"][MINTED] = json!("read");
    let error = app_answers(named).await;
    assert_eq!(error.step, Step::AppIdentity);
    assert!(
        error.detail.contains("no readable permission map"),
        "{error}"
    );

    let mut leveled = json!({
        "id": AIRLOCK_SAFE_APP_ID, "slug": "airlock-safe",
        "permissions": {"metadata": "read"}
    });
    leveled["permissions"]["contents"] = json!(echo());
    assert_eq!(app_answers(leveled).await.step, Step::AppIdentity);

    let server = fake().await;
    let mut selection = installation("all");
    selection["repository_selection"] = json!(echo());
    selection["account"]["login"] = json!(echo());
    answer(
        &server,
        "GET",
        "/orgs/wyrd-company/installation",
        ResponseTemplate::new(200).set_body_json(selection),
    )
    .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::InstallationScope);
    assert!(
        error.detail.contains("an unrecognised selection"),
        "{error}"
    );
}

#[tokio::test]
async fn a_minted_permission_that_is_not_a_permission_is_refused_unrepeated_and_revoked() {
    let server = fake().await;
    let mut response = minted(&[("metadata", "read")]);
    response["permissions"][MINTED] = json!("read");
    answer(
        &server,
        "POST",
        &format!("/app/installations/{INSTALLATION}/access_tokens"),
        ResponseTemplate::new(201).set_body_json(response),
    )
    .await;
    let error = refused(&server).await;
    assert_eq!(error.step, Step::TokenRequest);
    assert!(
        error.detail.contains("unreadable permission map"),
        "{error}"
    );
    assert_eq!(
        requests_to(&server, "DELETE", "/installation/token")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn a_failed_revocation_repeats_nothing_github_said() {
    let server = fake().await;
    answer(
        &server,
        "DELETE",
        "/installation/token",
        ResponseTemplate::new(500).set_body_json(json!({ "message": echo() })),
    )
    .await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the sign-in succeeds");
    let error = session.revoke().await.unwrap_err();
    assert_eq!(error.step, Step::TokenRevoke);
    assert_carries_no_secret(&error);
}

#[tokio::test]
async fn an_expiry_that_is_not_a_timestamp_is_not_kept() {
    let server = fake().await;
    let mut response = minted(&[("metadata", "read")]);
    response["expires_at"] = json!(echo());
    answer(
        &server,
        "POST",
        &format!("/app/installations/{INSTALLATION}/access_tokens"),
        ResponseTemplate::new(201).set_body_json(response),
    )
    .await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the sign-in succeeds");
    assert_eq!(session.expires_at, None);
}

#[tokio::test]
async fn the_session_redacts_its_token_from_any_text() {
    let server = fake().await;
    let session = sign_in(
        &config(&server),
        &oidc(&server),
        &endpoints(&server),
        Limits::default(),
        native(),
    )
    .await
    .expect("the sign-in succeeds");
    assert_eq!(
        session.redact(&format!("a {MINTED} b {MINTED}")),
        "a [redacted] b [redacted]"
    );
}
