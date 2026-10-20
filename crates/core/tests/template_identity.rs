//! Template identity audit through the REST transport and report boundary.
//
// relationships:
//   implements: release-process-conformance

use airlock_core::{
    audit, auth,
    github::{RestClient, RestClientConfig},
    limits::Limits,
    policy,
};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SOURCE: &str = "gh:example-org/catalog#bundle";
const ID: &str = "https://wyrd.foo/toha/schemas/applied-record/1";
fn record() -> String {
    json!({"$schema":ID,"applications":[{"target":".","template":"gh:example-org/catalog@main#bundle","source":SOURCE,"commit":"a".repeat(40),"generated":"toha/1","parts":["alpha"],"answers":{},"context":{},"paths":{}}]}).to_string()
}

struct Fixture {
    server: MockServer,
    record: Option<String>,
    truncated: bool,
    mode: &'static str,
    max_blob: usize,
    ref_status: u16,
    blob_status: u16,
    minimum_status: u16,
    compare_status: u16,
    reachability: &'static str,
    minimum: &'static str,
    record_path: &'static str,
    release_config: &'static str,
    organization_waiver: bool,
    organization_scope: bool,
}
impl Fixture {
    async fn new() -> Self {
        Self {
            server: MockServer::start().await,
            record: Some(record()),
            truncated: false,
            mode: "100644",
            max_blob: 1_000_000,
            ref_status: 200,
            blob_status: 200,
            minimum_status: 200,
            compare_status: 200,
            reachability: "ahead",
            minimum: "ahead",
            record_path: ".toha.json",
            release_config: "release-units: {sample: {path: .}}",
            organization_waiver: false,
            organization_scope: false,
        }
    }
    async fn run(&self, credential: bool) -> airlock_core::findings::Report {
        let config = self.release_config;
        let mut entries = vec![
            json!({"path":".intentional/config.yml","mode":"100644","sha":"config-blob","size":config.len()}),
        ];
        if let Some(record) = &self.record {
            entries.push(json!({"path":self.record_path,"mode":self.mode,"sha":"record-blob","size":record.len()}));
        }
        for (route, body) in [
            (
                "/repos/owner/name",
                json!({"id":1,"name":"name","full_name":"owner/name","default_branch":"main"}),
            ),
            (
                "/repos/owner/name/commits/main",
                json!({"sha":"captured-commit"}),
            ),
            ("/repos/owner/name/topics", json!({"names":[]})),
            (
                "/repos/owner/name/git/trees/captured-commit",
                json!({"tree":entries,"truncated":self.truncated}),
            ),
            (
                "/repos/owner/name/git/blobs/config-blob",
                json!({"encoding":"utf-8","content":config}),
            ),
            (
                "/repos/owner/name/git/blobs/record-blob",
                json!({"encoding":"utf-8","content":self.record}),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(
                    ResponseTemplate::new(if route.ends_with("/record-blob") {
                        self.blob_status
                    } else {
                        200
                    })
                    .set_body_json(body),
                )
                .mount(&self.server)
                .await;
        }
        for (reference, sha, status) in [
            ("accepted/branch", "b".repeat(40), self.ref_status),
            ("start", "c".repeat(40), self.minimum_status),
        ] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/repos/example-org/catalog/commits/{}",
                    reference.replace('/', "%2F")
                )))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({"sha":sha})))
                .mount(&self.server)
                .await;
        }
        for (base, head, status) in [
            ("a".repeat(40), "b".repeat(40), self.reachability),
            ("c".repeat(40), "a".repeat(40), self.minimum),
        ] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/repos/example-org/catalog/compare/{base}...{head}"
                )))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(self.compare_status).set_body_json(
                    json!({"status":status,"commits":[{"ignored":"only status is used"}]}),
                ))
                .mount(&self.server)
                .await;
        }
        let client = RestClient::new(
            "fixture",
            RestClientConfig {
                base_url: self.server.uri(),
                max_rate_limit_retries: 0,
                ..Default::default()
            },
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yml");
        let reason = if self.organization_waiver {
            "Organization waiver"
        } else {
            "Expected process"
        };
        let waiver = if self.organization_waiver {
            "    severity: none\n"
        } else {
            ""
        };
        let entry = format!("    reason: {reason}\n{waiver}    record-path: {}\n    templates: [{{source: '{}', ref: accepted/branch, minimum: start, parts: [alpha, beta]}}]\n",self.record_path,SOURCE);
        let entry = if self.organization_scope {
            let nested: String = entry.lines().map(|line| format!("    {line}\n")).collect();
            format!(
                "    reason: Repository convention\n    repositories:\n      owner/name:\n{nested}"
            )
        } else {
            entry
        };
        std::fs::write(
            &policy_path,
            format!("version: 0.6.0\nexceptions:\n  REPO-TPL-01:\n{entry}"),
        )
        .unwrap();

        let mut policy = policy::resolve(
            &client,
            &policy::PolicySource::Local(policy_path),
            &Limits::default(),
        )
        .await
        .unwrap();
        policy.rules.retain(|r| r.def.id == "REPO-TPL-01");
        let grant = auth::VerifiedGrant {
            kind: auth::TokenKind::ClassicPat,
            issuer: None,
            login: None,
            scopes: vec!["read:user".into()],
            installations: vec![],
        };
        audit::run(
            &client,
            "owner",
            "name",
            &policy,
            &audit::AuditOptions {
                limits: Limits {
                    max_blob_bytes: self.max_blob,
                    ..Default::default()
                },
                ..Default::default()
            },
            credential.then_some(&grant),
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn template_audit_reads_configured_record_at_captured_commit_and_compares_both_directions() {
    let mut fixture = Fixture::new().await;
    fixture.record_path = "state/applied.json";
    let report = fixture.run(true).await;
    assert_eq!(
        report.exit_code(),
        0,
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    assert_eq!(report.findings[0].status_code(), "met");
    let evidence = serde_json::to_value(&report.findings[0].evidence).unwrap();
    assert_eq!(
        evidence["template_identity"]["audited_commit"],
        "captured-commit"
    );
    assert_eq!(
        evidence["template_identity"]["items"][0]["revision"]["resolved_minimum"],
        "c".repeat(40)
    );
    let requests = fixture.server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path().contains("/compare/"))
            .count(),
        2
    );
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
    assert!(!requests.iter().any(|r| r.url.path().contains("snapshot")));
}

#[tokio::test]
async fn template_audit_loads_the_record_selected_by_organization_repository_scope() {
    let mut fixture = Fixture::new().await;
    fixture.organization_scope = true;
    fixture.record_path = "state/scoped.json";
    let report = fixture.run(true).await;
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.findings[0].status_code(), "met");
    assert_eq!(
        report.findings[0]
            .evidence
            .as_ref()
            .unwrap()
            .path
            .as_deref(),
        Some("state/scoped.json")
    );
}

#[tokio::test]
async fn template_audit_without_release_units_makes_no_template_repository_requests() {
    let mut fixture = Fixture::new().await;
    fixture.release_config = "release-units: {}";
    let report = fixture.run(true).await;
    assert_no_template_repository_requests(&fixture).await;
    assert_eq!(report.exit_code(), 0);
    assert!(
        report.findings.is_empty(),
        "no Met or Gap for an out-of-scope rule"
    );
    assert!(report.run_errors.is_empty());
    assert!(report.waived.is_empty());
    assert!(report.routed.is_empty());
    assert!(report.unbuilt.is_empty());
    assert_eq!(report.out_of_scope.len(), 1);
    assert_eq!(report.out_of_scope[0].rule, "REPO-TPL-01");
    assert_eq!(report.out_of_scope[0].status_code(), "out-of-scope");
}

#[tokio::test]
async fn template_audit_with_organization_waiver_makes_no_template_repository_requests() {
    let mut fixture = Fixture::new().await;
    // This generally audited path keeps the valid record readable under a waiver.
    // The file-loading severity guard must not mask the gather severity guard.
    fixture.record_path = "README.md";
    fixture.organization_waiver = true;
    let report = fixture.run(true).await;
    assert_no_template_repository_requests(&fixture).await;
    assert_eq!(report.exit_code(), 0);
    assert!(
        report.findings.is_empty(),
        "no Met or Gap for a waived rule"
    );
    assert!(report.run_errors.is_empty());
    assert!(report.out_of_scope.is_empty());
    assert!(report.routed.is_empty());
    assert!(report.unbuilt.is_empty());
    assert_eq!(report.waived.len(), 1);
    assert_eq!(report.waived[0].rule, "REPO-TPL-01");
    assert_eq!(report.waived[0].status_code(), "waived");
    assert_eq!(
        report.waived[0]
            .suppression
            .as_ref()
            .unwrap()
            .policy_reason
            .as_deref(),
        Some("Organization waiver")
    );
}

async fn assert_no_template_repository_requests(fixture: &Fixture) {
    // Observe every attempt at this repository, including ref/minimum resolution
    // and both ancestry comparisons, independently of mock matches or outcomes.
    let requests = fixture.server.received_requests().await.unwrap();
    let forbidden: Vec<_> = requests
        .iter()
        .filter(|request| {
            let path = request.url.path();
            path == "/repos/example-org/catalog" || path.starts_with("/repos/example-org/catalog/")
        })
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect();
    assert!(
        forbidden.is_empty(),
        "forbidden template repository requests: {forbidden:?}"
    );
}

#[tokio::test]
async fn template_audit_ref_minimum_and_compare_failures_are_run_errors() {
    for failure in ["ref", "minimum", "compare", "unknown-status"] {
        let mut fixture = Fixture::new().await;
        match failure {
            "ref" => fixture.ref_status = 404,
            "minimum" => fixture.minimum_status = 403,
            "compare" => fixture.compare_status = 404,
            _ => fixture.reachability = "unknown",
        }
        let report = fixture.run(true).await;
        assert_eq!(report.exit_code(), 2, "{failure}");
        assert!(report.findings.is_empty());
        assert_eq!(report.run_errors.len(), 1);
        assert!(report.run_errors[0]
            .error
            .as_ref()
            .unwrap()
            .endpoint
            .contains(if failure == "ref" || failure == "minimum" {
                "/commits/"
            } else {
                "/compare/"
            }));
    }
}

#[tokio::test]
async fn template_audit_truncation_and_budget_never_report_record_missing() {
    for truncated in [true, false] {
        let mut fixture = Fixture::new().await;
        if truncated {
            fixture.record = None;
            fixture.truncated = true;
        } else {
            fixture.max_blob = 100;
        }
        let report = fixture.run(true).await;
        assert_eq!(report.exit_code(), 2);
        assert!(report.findings.is_empty());
        assert_eq!(report.run_errors.len(), 1);
        let endpoint = &report.run_errors[0].error.as_ref().unwrap().endpoint;
        assert!(
            endpoint.contains(if truncated {
                "/git/trees/captured-commit?recursive=1"
            } else {
                "/git/blobs/record-blob"
            }),
            "{endpoint}"
        );
    }
}

#[tokio::test]
async fn template_audit_missing_record_is_blocking_gap_with_agent_fix() {
    let mut fixture = Fixture::new().await;
    fixture.record = None;
    let report = fixture.run(true).await;
    assert_eq!(report.exit_code(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.evidence.as_ref().unwrap().code, "record-missing");
    assert_eq!(finding.fix_class.fix_kind.as_deref(), Some("agent"));
}

#[tokio::test]
async fn template_audit_without_credential_routes_whole_rule_without_template_api_calls() {
    let fixture = Fixture::new().await;
    let report = fixture.run(false).await;
    assert_eq!(report.exit_code(), 0);
    assert!(report.findings.is_empty());
    assert!(report.run_errors.is_empty());
    assert_eq!(report.routed.len(), 1);
    assert_eq!(
        report.routed[0].routing.as_ref().unwrap().reason,
        "needs-github-api"
    );
    assert!(!fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path().starts_with("/repos/example-org/catalog")));
}

#[tokio::test]
async fn template_audit_present_record_remains_decidable_in_truncated_tree() {
    let mut fixture = Fixture::new().await;
    fixture.truncated = true;
    let report = fixture.run(true).await;
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.findings[0].status_code(), "met");
}

#[tokio::test]
async fn template_audit_schema_identity_is_not_a_fetch_destination() {
    let mut fixture = Fixture::new().await;
    let mut value: serde_json::Value =
        serde_json::from_str(fixture.record.as_ref().unwrap()).unwrap();
    value["$schema"] = json!(format!("{}/schemas/untrusted", fixture.server.uri()));
    fixture.record = Some(value.to_string());
    let report = fixture.run(true).await;
    assert_eq!(report.exit_code(), 1);
    assert_eq!(
        report.findings[0].evidence.as_ref().unwrap().code,
        "record-schema-not-supported"
    );
    assert!(!fixture
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|request| request.url.path().starts_with("/schemas/")));
}

#[tokio::test]
async fn template_audit_record_blob_failure_is_run_error() {
    let mut fixture = Fixture::new().await;
    fixture.blob_status = 404;
    let report = fixture.run(true).await;
    assert_eq!(report.exit_code(), 2);
    assert!(report.findings.is_empty());
    assert!(report.run_errors[0]
        .error
        .as_ref()
        .unwrap()
        .endpoint
        .ends_with("/git/blobs/record-blob"));
}
