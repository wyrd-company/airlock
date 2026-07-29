//! End-to-end runs of the `airlock` binary.
//!
//! Every run here talks to a fixture GitHub. The binary is pointed at it by
//! environment variable, so nothing in this file can reach the real API.

mod support;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;
use serde_json::Value;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
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

fn offline() -> Command {
    let mut command = Command::cargo_bin("airlock").expect("the airlock binary builds");
    command
        .env("AIRLOCK_GITHUB_API_URL", "http://127.0.0.1:9/offline-test")
        .env(
            "AIRLOCK_GITHUB_LOGIN_URL",
            "http://127.0.0.1:9/offline-test",
        )
        .env_remove("AIRLOCK_TOKEN")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN");
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

async fn audit_json(repo: FakeRepo, policy: &str, exit_code: i32) -> Value {
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();
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
        .code(exit_code);
    json_output(&assertion.get_output().stdout)
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

#[test]
fn bare_invocation_exits_two_and_says_why() {
    offline()
        .assert()
        .code(2)
        .stderr(contains("TUI not yet available; use a subcommand."));
}

#[test]
fn help_lists_the_command_surface() {
    offline()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("audit"))
        .stdout(contains("auth"));
}

#[test]
fn list_checks_reports_the_whole_registry_without_a_target() {
    let assertion = offline()
        .args(["audit", "--list-checks", "--format", "json"])
        .assert()
        .success();
    let listing = json_output(&assertion.get_output().stdout);
    let checks = listing["checks"].as_array().unwrap();
    assert!(checks.len() >= 109);
    for id in ["REPO-FILE-01", "REPO-CI-09", "REPO-PROP-04"] {
        assert!(checks.iter().any(|check| check["id"] == id), "{id}");
    }
    assert!(listing["registry_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn list_checks_reports_evaluation_modes_and_no_unimplemented_rules() {
    let assertion = offline()
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
    assert!(unimplemented.is_empty());
    assert!(checks
        .iter()
        .any(|check| check["id"] == "REPO-DOCS-05" && check["evaluation"] == "manual"));
    assert!(checks
        .iter()
        .any(|check| check["id"] == "REPO-README-06" && check["evaluation"] == "mechanical"));
    assert!(checks.iter().any(|check| check["evaluation"] == "manual"));
}

#[test]
fn a_closed_output_pipe_terminates_silently_with_sigpipe() {
    let (reader, writer) = UnixStream::pair().expect("the output pipe is created");
    drop(reader);
    let writer: OwnedFd = writer.into();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("airlock"))
        .args(["audit", "--list-checks", "--format", "json"])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .spawn()
        .expect("airlock starts")
        .wait_with_output()
        .expect("airlock exits");

    assert_eq!(output.status.signal(), Some(libc::SIGPIPE));
    assert_eq!(output.stderr, b"");
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
    let report = audit_json(repo, LICENSING_POLICY, 0).await;
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
    let report = audit_json(repo, LICENSING_POLICY, 1).await;
    assert_eq!(report["outcome"], "nonconformant");
    assert_eq!(report["complete"], true);
    let lic01 = finding(&report, "REPO-LIC-01");
    assert_eq!(lic01["status"], "fail");
    assert_eq!(lic01["evidence"]["code"], "file_missing");
    assert_eq!(lic01["remediation"]["action_group"], "add_file");
    assert!(lic01["remediation"].get("code").is_none());
    assert_eq!(
        lic01["remediation_class"]["code"], "add-license-file",
        "consumers join on the per-rule remediation class"
    );
    assert!(lic01["remediation"]["detail"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_enabled_manual_rule_does_not_make_the_audit_incomplete() {
    let repo = FakeRepo::new("wyrd-company", "example").with_file("README.md", "# example");

    // Manual judgment never gates, even when policy re-grades the rule.
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

    let report = audit_json(repo, policy, 0).await;
    assert_eq!(report["outcome"], "conformant");
    assert_eq!(report["complete"], true);
    assert_eq!(finding(&report, "REPO-DOCS-05")["status"], "manual");
    assert_eq!(report["summary"]["unimplemented"], 0);
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

    let policy = "\
version: 1
name: test-policy
gate: blocking
capabilities:
  base: [git]
";

    let report = audit_json(repo, policy, 2).await;
    assert_eq!(report["outcome"], "incomplete");
    let git02 = finding(&report, "REPO-GIT-02");
    assert_eq!(git02["status"], "error");
    assert_eq!(git02["error"]["cause"], "plan_limitation");
    assert_eq!(git02["error"]["status"], 403);
    assert_eq!(git02["error"]["request_id"], "FIXT:0001");
    assert_eq!(git02["remediation"]["action_group"], "plan_gate");
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
    let policy = format!("{LICENSING_POLICY}suppressions:\n  allow-repo-requests: [REPO-LIC-01]\n");
    let report = audit_json(repo, &policy, 0).await;
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
    let report = audit_json(repo, LICENSING_POLICY, 1).await;
    assert_eq!(finding(&report, "REPO-LIC-01")["status"], "fail");
    let observations = report["policy_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["code"], "unauthorized_suppression_request");
    assert_eq!(observations[0]["rule"], "REPO-LIC-01");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_suppression_is_recorded_with_its_authority() {
    let repo = FakeRepo::new("wyrd-company", "example");
    let policy = format!(
        "{LICENSING_POLICY}suppressions:\n  direct:\n    - rule: REPO-LIC-01\n      repository: \
         wyrd-company/example\n      reason: \"the licence lands with the first release\"\n"
    );

    let report = audit_json(repo, &policy, 0).await;
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

    // The bundle digest says the inputs changed; the sources say which one.
    let sources = report["policy"]["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["name"], "policy");
    assert_eq!(
        sources[0]["source"],
        "wyrd-company/.github:airlock/policy.yml"
    );
    assert_eq!(sources[0]["commit"], support::COMMIT);
    assert!(sources[0]["blob_sha"].is_string());
    assert!(sources[0]["content_digest"]
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
async fn auth_token_verifies_and_emits_only_the_stored_profile_token() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();
    let directory = config.path().join("airlock");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.toml");
    std::fs::write(
        &path,
        "[profiles.ci]\naccess_token = \"ghu_profile_token\"\nlogin = \"example-user\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    airlock(&server, &config)
        .args(["auth", "token", "--profile", "ci"])
        .assert()
        .code(0)
        .stdout("ghu_profile_token\n")
        .stderr("");
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_token_emits_nothing_when_the_stored_profile_is_refused() {
    let server = support::start(&[FakeRepo::new("wyrd-company", "example")]).await;
    let config = TempDir::new().unwrap();
    let directory = config.path().join("airlock");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.toml");
    let refused_token = "github_pat_11ABCDEFG";
    std::fs::write(
        &path,
        format!("[profiles.ci]\naccess_token = \"{refused_token}\"\nlogin = \"example-user\"\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let assertion = airlock(&server, &config)
        .args(["auth", "token", "--profile", "ci"])
        .assert()
        .failure()
        .stdout("");
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert!(!stderr.contains(refused_token));
    assert!(!stderr.contains("ghu_"));
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

// ---------------------------------------------------------------------------
// The candidate organisation policy
// ---------------------------------------------------------------------------

/// The policy in `docs/examples/` is the one the operator will move into
/// `wyrd-company/.github`. If it stops compiling against this binary's
/// registry, dogfooding breaks the moment it is moved — so it is compiled
/// here, against the fixture GitHub that serves its reference data.
#[tokio::test(flavor = "multi_thread")]
async fn the_candidate_organisation_policy_compiles_and_resolves_its_reference_data() {
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root is two levels above the cli crate")
        .to_path_buf();
    let policy = repository_root.join("docs/examples/wyrd-policy.yml");
    let topics = std::fs::read_to_string(repository_root.join("docs/examples/wyrd-topics.yml"))
        .expect("the candidate topic vocabulary is committed");

    let audited = FakeRepo::new("wyrd-company", "example")
        .with_file("LICENSE", "Apache License 2.0")
        .with_file("README.md", "# example");
    let policy_repo =
        FakeRepo::new("wyrd-company", ".github").with_file("airlock/topics.yml", &topics);
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy.display().to_string(),
            "--format",
            "json",
        ])
        .assert();

    let output = assertion.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("policy error"),
        "the candidate policy did not compile: {stderr}"
    );

    let report = json_output(&output.stdout);
    assert_eq!(report["policy"]["name"], "wyrd-company");
    // The reference data was pinned into the bundle, not merely mentioned.
    assert!(report["policy"]["bundle_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    // Release rules are skipped where nothing declares a release unit.
    assert_eq!(finding(&report, "REPO-REL-01")["status"], "skipped");
}

// ---------------------------------------------------------------------------
// Incomplete input must never look like a clean audit
// ---------------------------------------------------------------------------

/// A policy over the files section, whose rules include two negative
/// assertions — "no harness configuration" and "no CODEOWNERS" — that a
/// partial tree cannot support.
const FILES_POLICY: &str = "\
version: 1
name: test-policy
gate: required
capabilities:
  base: [files]
";

#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_tree_cannot_produce_a_clean_audit() {
    // Everything the policy asks for is present in the part of the tree
    // airlock received. Under a complete tree this is a clean run; under a
    // truncated one the negative assertions are unprovable.
    let repo = FakeRepo::new("wyrd-company", "example")
        .with_truncated_tree()
        .with_file("README.md", "# example")
        .with_file("CONTRIBUTING.md", "contribute")
        .with_file(".gitignore", "target")
        .with_file(".gitattributes", "* text=auto\n")
        .with_file(".editorconfig", "root = true")
        .with_file("taskfile.yml", "version: '3'\n")
        .with_file(".config/lefthook.yml", "pre-commit:\n  jobs: []\n")
        .with_file("AGENTS.md", "guidance")
        .with_file(".devcontainer/devcontainer.json", "{}")
        .with_file(".github/repo-settings.yml", "description: x\n")
        .with_file(
            ".github/renovate.json",
            "{\"extends\":[\"github>owner/.github\"]}",
        )
        .with_file(
            ".github/workflows/ci.yml",
            "on:\n  pull_request:\npermissions: {}\njobs: {}\n",
        )
        .with_file(
            ".github/workflows/reconcile-settings.yml",
            "on:\n  push:\n    branches: [main]\npermissions: {}\njobs: {}\n",
        );
    let report = audit_json(repo, FILES_POLICY, 2).await;
    assert_eq!(report["outcome"], "incomplete");
    assert_eq!(report["complete"], false);
    // The two negative assertions are exactly the ones a partial tree cannot
    // support, and they must not read as satisfied.
    for rule in ["REPO-FILE-13", "REPO-FILE-14"] {
        let finding = finding(&report, rule);
        assert_eq!(finding["status"], "inconclusive", "{rule}");
        assert_eq!(finding["evidence"]["code"], "tree_truncated", "{rule}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_tree_entry_stops_the_audit_rather_than_shrinking_it() {
    // Under lenient decoding this entry would vanish and REPO-FILE-13 would
    // report that no harness configuration is committed.
    let repo = FakeRepo::new("wyrd-company", "example")
        .with_file("README.md", "# example")
        .with_malformed_tree_entry(".claude/settings.json");
    let server = support::start(&[repo]).await;
    let config = TempDir::new().unwrap();
    let policies = TempDir::new().unwrap();

    airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &policy_path(&policies, FILES_POLICY),
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stderr(contains("malformed_response").or(contains(".claude/settings.json")));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_policy_reference_is_resolved_and_pinned_into_the_bundle() {
    // Two references that are each individually small, and together are not.
    let audited = FakeRepo::new("wyrd-company", "example").with_file("LICENSE", "Apache");
    let filler = "x".repeat(4096);
    let policy_repo = FakeRepo::new("wyrd-company", ".github")
        .with_file(
            "airlock/policy.yml",
            &format!(
                "{LICENSING_POLICY}reference-data:\n  \
                 first: wyrd-company/.github:airlock/first.yml\n  \
                 second: wyrd-company/.github:airlock/second.yml\n"
            ),
        )
        .with_file("airlock/first.yml", &format!("padding: {filler}\n"))
        .with_file("airlock/second.yml", &format!("padding: {filler}\n"));
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    // The aggregate byte budget itself is exercised in the core suite, where
    // it can be shrunk; this asserts the multi-reference path resolves and
    // pins end to end.
    let assertion = airlock(&server, &config)
        .args(["audit", "wyrd-company/example", "--format", "json"])
        .assert();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        !stderr.contains("panicked"),
        "resolution must not panic: {stderr}"
    );
    // Both references resolved and were pinned into the bundle, and both are
    // reported with the blob they pinned to.
    let report = json_output(&assertion.get_output().stdout);
    let sources = report["policy"]["sources"].as_array().unwrap();
    let names: Vec<&str> = sources
        .iter()
        .map(|source| source["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"policy"));
    assert!(names.contains(&"first"));
    assert!(names.contains(&"second"));
    for source in sources {
        assert!(source["content_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }
    // The two references are remote, so they pin to a commit and a blob.
    for name in ["first", "second"] {
        let source = sources
            .iter()
            .find(|source| source["name"] == name)
            .unwrap();
        assert_eq!(source["commit"], support::COMMIT);
        assert!(source["blob_sha"].is_string(), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_tree_cannot_skip_a_conditional_capability() {
    // The candidate organisation policy applies its release capability only
    // when .intentional/config.yml is present. A truncated tree never
    // established that it is absent, so skipping every release rule would
    // hide both the file and the checks it enables.
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root is two levels above the cli crate")
        .to_path_buf();
    let topics = std::fs::read_to_string(repository_root.join("docs/examples/wyrd-topics.yml"))
        .expect("the candidate topic vocabulary is committed");

    let audited = FakeRepo::new("wyrd-company", "example")
        .with_truncated_tree()
        .with_file("LICENSE", "Apache License 2.0")
        .with_file("README.md", "# example");
    let policy_repo =
        FakeRepo::new("wyrd-company", ".github").with_file("airlock/topics.yml", &topics);
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &repository_root
                .join("docs/examples/wyrd-policy.yml")
                .display()
                .to_string(),
            "--format",
            "json",
        ])
        .assert()
        .code(2);

    let report = json_output(&assertion.get_output().stdout);
    assert_eq!(report["outcome"], "incomplete");
    assert_eq!(report["complete"], false);
    assert_eq!(
        report["summary"]["skipped"], 0,
        "no rule may be skipped on a condition airlock could not evaluate"
    );
    for rule in [
        "REPO-REL-01",
        "REPO-REL-04",
        "REPO-REL-07",
        "REPO-GIT-09",
        "REPO-TASK-04",
        "REPO-LIC-04",
    ] {
        let finding = finding(&report, rule);
        assert_eq!(finding["status"], "inconclusive", "{rule}");
        assert_eq!(finding["evidence"]["code"], "condition_undecided", "{rule}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_complete_tree_still_skips_a_capability_whose_condition_is_absent() {
    // The other half of the contract: a condition airlock *can* evaluate and
    // that does not hold still skips its rules conclusively.
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root is two levels above the cli crate")
        .to_path_buf();
    let topics = std::fs::read_to_string(repository_root.join("docs/examples/wyrd-topics.yml"))
        .expect("the candidate topic vocabulary is committed");

    let audited = FakeRepo::new("wyrd-company", "example")
        .with_file("LICENSE", "Apache License 2.0")
        .with_file("README.md", "# example");
    let policy_repo =
        FakeRepo::new("wyrd-company", ".github").with_file("airlock/topics.yml", &topics);
    let server = support::start(&[audited, policy_repo]).await;
    let config = TempDir::new().unwrap();

    let assertion = airlock(&server, &config)
        .args([
            "audit",
            "wyrd-company/example",
            "--policy",
            &repository_root
                .join("docs/examples/wyrd-policy.yml")
                .display()
                .to_string(),
            "--format",
            "json",
        ])
        .assert();

    let report = json_output(&assertion.get_output().stdout);
    let rel01 = finding(&report, "REPO-REL-01");
    assert_eq!(rel01["status"], "skipped");
    assert_eq!(rel01["evidence"]["code"], "condition_not_met");
    for rule in ["REPO-GIT-09", "REPO-TASK-04", "REPO-LIC-04"] {
        let finding = finding(&report, rule);
        assert_eq!(finding["status"], "skipped", "{rule}");
        assert_eq!(finding["evidence"]["code"], "condition_not_met", "{rule}");
        assert!(
            finding["evidence"]["detail"]
                .as_str()
                .unwrap()
                .contains("release-units-declared"),
            "{rule}"
        );
    }
}
