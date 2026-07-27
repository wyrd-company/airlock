//! End-to-end runs of the `airlock` binary.
//!
//! Every run here talks to a fixture GitHub. The binary is pointed at it by
//! environment variable, so nothing in this file can reach the real API.

mod support;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use serde_json::Value;
use support::{FakeRepo, Response};
use tempfile::TempDir;
use wiremock::MockServer;

/// A policy over the licensing section only, which is small enough to reason
/// about and contains one blocking rule.
const LICENSING_POLICY: &str = "\
version: 1
name: test-policy
gate: blocking
capabilities:
  base: [licensing]
";

fn airlock(server: &MockServer, config: &TempDir) -> Command {
    let mut command = Command::cargo_bin("airlock").expect("the airlock binary builds");
    command
        .env("AIRLOCK_GITHUB_API_URL", server.uri())
        .env("AIRLOCK_GITHUB_LOGIN_URL", server.uri())
        .env("AIRLOCK_TOKEN", "ghu_fixture_token")
        .env("XDG_CONFIG_HOME", config.path())
        // Anything airlock must not read is set to something it would choke on
        // if it ever did.
        .env("GH_TOKEN", "ghp_this_must_never_be_read")
        .env("GITHUB_TOKEN", "ghp_this_must_never_be_read");
    command
}

fn policy_path(directory: &TempDir, body: &str) -> String {
    let path = directory.path().join("policy.yml");
    std::fs::write(&path, body).expect("the policy is written");
    path.display().to_string()
}

fn json_output(output: &[u8]) -> Value {
    serde_json::from_slice(output).expect("stdout is one json document")
}

fn finding<'a>(report: &'a Value, rule: &str) -> &'a Value {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .find(|finding| finding["rule"] == rule)
        .unwrap_or_else(|| panic!("{rule} has no finding"))
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

#[test]
fn bare_invocation_exits_two_and_says_why() {
    Command::cargo_bin("airlock")
        .unwrap()
        .assert()
        .code(2)
        .stderr(contains("TUI not yet available; use a subcommand."));
}

#[test]
fn help_lists_the_command_surface() {
    Command::cargo_bin("airlock")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("audit"))
        .stdout(contains("auth"));
}

#[test]
fn list_checks_reports_the_whole_registry_without_a_target() {
    let assertion = Command::cargo_bin("airlock")
        .unwrap()
        .args(["audit", "--list-checks", "--format", "json"])
        .assert()
        .success();
    let listing = json_output(&assertion.get_output().stdout);
    assert_eq!(listing["checks"].as_array().unwrap().len(), 109);
    assert!(listing["registry_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn list_checks_marks_manual_and_unimplemented_rules() {
    let assertion = Command::cargo_bin("airlock")
        .unwrap()
        .args(["audit", "--list-checks", "--format", "json"])
        .assert()
        .success();
    let listing = json_output(&assertion.get_output().stdout);
    let checks = listing["checks"].as_array().unwrap();
    let unimplemented: Vec<&str> = checks
        .iter()
        .filter(|check| check["evaluation"] == "unimplemented")
        .map(|check| check["id"].as_str().unwrap())
        .collect();
    assert!(unimplemented.contains(&"REPO-DOCS-05"));
    assert!(checks.iter().any(|check| check["evaluation"] == "manual"));
}

// ---------------------------------------------------------------------------
// Audit outcomes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_conformant_repository_exits_zero() {
    let repo = FakeRepo::new("wyrd-company", "example")
        .with_file("LICENSE", "Apache License 2.0")
        .with_file(
            "Cargo.toml",
            "[package]\nname = \"example\"\nlicense = \"Apache-2.0\"\n",
        );
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
            "--format",
            "json",
        ])
        .assert()
        .code(0);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(report["outcome"], "conformant");
    assert_eq!(report["complete"], true);
    assert_eq!(report["conformant"], true);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["repository"]["audited_commit"], support::COMMIT);
    assert_eq!(finding(&report, "REPO-LIC-01")["status"], "pass");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocking_failure_exits_one() {
    let repo = FakeRepo::new("wyrd-company", "example").with_file(
        "Cargo.toml",
        "[package]\nname = \"example\"\nlicense = \"Apache-2.0\"\n",
    );
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
            "--format",
            "json",
        ])
        .assert()
        .code(1);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(report["outcome"], "nonconformant");
    assert_eq!(report["complete"], true);
    let lic01 = finding(&report, "REPO-LIC-01");
    assert_eq!(lic01["status"], "fail");
    assert_eq!(lic01["evidence"]["code"], "file_missing");
    assert!(lic01["remediation"]["detail"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_enabled_unimplemented_rule_makes_the_audit_incomplete() {
    let repo = FakeRepo::new("wyrd-company", "example").with_file("README.md", "# example");
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    // REPO-DOCS-05 is registered but not built. Raising it to blocking is
    // exactly the case that must not be able to exit 0.
    let policy = "\
version: 1
name: test-policy
gate: blocking
capabilities:
  base: [docs]
checks:
  REPO-DOCS-05:
    severity: blocking
";

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, policy),
            "--format",
            "json",
        ])
        .assert()
        .code(2);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(report["outcome"], "incomplete");
    assert_eq!(report["complete"], false);
    assert_eq!(finding(&report, "REPO-DOCS-05")["status"], "unimplemented");
    assert_eq!(report["summary"]["unimplemented"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plan_limitation_makes_the_audit_incomplete_rather_than_passing() {
    let repo = FakeRepo::new("wyrd-company", "example").with_rulesets(Response::Status(
        403,
        serde_json::json!({
            "message": "Upgrade to GitHub Pro or make this repository public to enable this feature.",
            "documentation_url": "https://docs.github.com/rest/repos/rules"
        }),
    ));
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let policy = "\
version: 1
name: test-policy
gate: blocking
capabilities:
  base: [git]
";

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, policy),
            "--format",
            "json",
        ])
        .assert()
        .code(2);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(report["outcome"], "incomplete");
    let git02 = finding(&report, "REPO-GIT-02");
    assert_eq!(git02["status"], "error");
    assert_eq!(git02["error"]["cause"], "plan_limitation");
    assert_eq!(git02["error"]["status"], 403);
    assert_eq!(git02["error"]["request_id"], "FIXT:0001");
    assert_eq!(git02["remediation"]["code"], "plan_gate");
}

// ---------------------------------------------------------------------------
// Suppression authority
// ---------------------------------------------------------------------------

const SUPPRESSION_REQUEST: &str = "\
version: 1
suppress:
  - rule: REPO-LIC-01
    reason: \"the licence is being chosen\"
";

#[tokio::test(flavor = "multi_thread")]
async fn an_authorised_suppression_request_is_honoured() {
    let repo = FakeRepo::new("wyrd-company", "example")
        .with_file(".github/airlock.yml", SUPPRESSION_REQUEST);
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let policy = format!("{LICENSING_POLICY}suppressions:\n  allow-repo-requests: [REPO-LIC-01]\n");

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, &policy),
            "--format",
            "json",
        ])
        .assert()
        .code(0);

    let report = json_output(&assertion.get_output().stdout);
    let lic01 = finding(&report, "REPO-LIC-01");
    assert_eq!(lic01["status"], "suppressed");
    assert_eq!(lic01["suppression"]["source"], "repository_request");
    assert_eq!(
        lic01["suppression"]["requested_reason"],
        "the licence is being chosen"
    );
    assert!(lic01["suppression"]["authorized_by"]
        .as_str()
        .unwrap()
        .contains("allow-repo-requests"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unauthorised_suppression_request_changes_nothing() {
    let repo = FakeRepo::new("wyrd-company", "example")
        .with_file(".github/airlock.yml", SUPPRESSION_REQUEST);
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
            "--format",
            "json",
        ])
        .assert()
        .code(1);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(finding(&report, "REPO-LIC-01")["status"], "fail");
    let observations = report["policy_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["code"], "unauthorized_suppression_request");
    assert_eq!(observations[0]["rule"], "REPO-LIC-01");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_suppression_is_recorded_with_its_authority() {
    let repo = FakeRepo::new("wyrd-company", "example");
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let policy = format!(
        "{LICENSING_POLICY}suppressions:\n  direct:\n    - rule: REPO-LIC-01\n      repository: \
         wyrd-company/example\n      reason: \"the licence lands with the first release\"\n"
    );

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, &policy),
            "--format",
            "json",
        ])
        .assert()
        .code(0);

    let report = json_output(&assertion.get_output().stdout);
    let lic01 = finding(&report, "REPO-LIC-01");
    assert_eq!(lic01["status"], "suppressed");
    assert_eq!(lic01["suppression"]["source"], "policy");
    assert_eq!(
        lic01["suppression"]["policy_reason"],
        "the licence lands with the first release"
    );
}

// ---------------------------------------------------------------------------
// Policy resolution
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_default_policy_comes_from_the_owners_dot_github_repository() {
    let audited = FakeRepo::new("wyrd-company", "example").with_file("LICENSE", "Apache");
    let policy_repo =
        FakeRepo::new("wyrd-company", ".github").with_file("airlock/policy.yml", LICENSING_POLICY);
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args(["audit", "wyrd-company/example", "--format", "json"])
        .assert()
        .code(0);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(
        report["policy"]["source"],
        "wyrd-company/.github:airlock/policy.yml"
    );
    assert_eq!(report["policy"]["commit"], support::COMMIT);
    assert!(report["policy"]["bundle_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_default_policy_is_an_operational_error() {
    let audited = FakeRepo::new("wyrd-company", "example");
    let policy_repo = FakeRepo::new("wyrd-company", ".github");
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    airlock(&server, &config)
        .args(["audit", "wyrd-company/example", "--format", "json"])
        .assert()
        .code(2)
        .stderr(contains("Airlock ships no built-in policy"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_rule_in_the_policy_is_an_operational_error() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let policy = format!("{LICENSING_POLICY}checks:\n  REPO-NOPE-99:\n    enabled: false\n");

    airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, &policy),
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stderr(contains("REPO-NOPE-99"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_incompatible_registry_requirement_is_an_operational_error() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    let policy = format!("{LICENSING_POLICY}requires-registry: \">=9.0\"\n");

    airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, &policy),
        ])
        .assert()
        .code(2)
        .stderr(contains("requires-registry"));
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_adversarial_policy_is_refused_rather_than_parsed() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();

    let bomb = format!(
        "version: 1\nname: a\ngate: blocking\ncapabilities:\n  base: [licensing]\n{}",
        alias_bomb()
    );
    let cases: &[(&str, &str)] = &[
        (
            "duplicate keys",
            "version: 1\nname: a\nname: b\ngate: blocking\ncapabilities:\n  base: [licensing]\n",
        ),
        (
            "a custom tag",
            "version: 1\nname: !surprise a\ngate: blocking\ncapabilities:\n  base: [licensing]\n",
        ),
        ("an alias bomb", &bomb),
        (
            "a non-string key",
            "version: 1\nname: a\ngate: blocking\ncapabilities:\n  base: [licensing]\n1: two\n",
        ),
    ];

    for (description, body) in cases {
        let policies = TempDir::new().unwrap();
        airlock(&server, &config)
            .args([
                "audit",
                "wyrd-company/example",
                "--policy",
                &policy_path(&policies, body),
            ])
            .assert()
            .code(2)
            .stderr(contains("policy error"))
            .stderr(contains("panicked").not());
        eprintln!("refused: {description}");
    }
}

/// A billion-laughs shape sized to exhaust the node budget.
fn alias_bomb() -> String {
    let mut out = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
    for (anchor, previous) in [
        ('b', 'a'),
        ('c', 'b'),
        ('d', 'c'),
        ('e', 'd'),
        ('f', 'e'),
        ('g', 'f'),
    ] {
        out.push_str(&format!(
            "{anchor}: &{anchor} [{}]\n",
            vec![format!("*{previous}"); 9].join(", ")
        ));
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn an_adversarial_suppression_file_is_a_policy_error_not_a_crash() {
    let repo = FakeRepo::new("wyrd-company", "example").with_file(
        ".github/airlock.yml",
        "suppress:\n  - rule: A\n    rule: B\n",
    );
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
        ])
        .assert()
        .code(2)
        .stderr(contains("duplicate"));
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_fine_grained_token_is_refused_before_anything_is_audited() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    airlock(&server, &config)
        .env("AIRLOCK_TOKEN", "github_pat_11ABCDEFG")
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
        ])
        .assert()
        .code(2)
        .stderr(contains("airlock auth login"));
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_status_reports_the_source_and_the_enumerated_grant() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();

    airlock(&server, &config)
        .args(["auth", "status"])
        .assert()
        .code(0)
        .stdout(contains(
            "credential source: the AIRLOCK_TOKEN environment variable",
        ))
        .stdout(contains("verified: yes"))
        .stdout(contains("issuer: airlock-safe"))
        .stdout(contains("metadata=read"));
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_status_never_prints_the_token() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();

    let assertion = airlock(&server, &config).args(["auth", "status"]).assert();
    let output = assertion.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains("ghu_fixture_token"));
}

#[tokio::test(flavor = "multi_thread")]
async fn text_output_renders_the_same_conclusion_as_json() {
    let repo = FakeRepo::new("wyrd-company", "example");
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, LICENSING_POLICY),
            "--format",
            "text",
        ])
        .assert()
        .code(1)
        .stdout(contains("REPO-LIC-01 | A `LICENSE` file exists"))
        .stdout(contains("nonconformant"));
}
