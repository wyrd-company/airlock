//! Observe real Git history and replay those same objects through the API audit.
//
// relationships:
//   references: maturity

use std::{collections::BTreeMap, path::Path, process::Command};

use airlock_core::{
    audit, maturity,
    policy::{EffectiveRule, ResolvedPolicy},
    rules::{self, Lifecycle},
};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    std::fs::create_dir(dir.path().join(".intentional")).unwrap();
    std::fs::write(
        dir.path().join(".intentional/config.yml"),
        "release-units: {sample: {path: .}}\n",
    )
    .unwrap();
    git(dir.path(), &["add", ".intentional/config.yml"]);
    git(dir.path(), &["commit", "-qm", "fixture"]);
    dir
}

fn message(version: &str, baseline: bool) -> String {
    format!("intentional release record\n\ncontract: contract-1\ngenerator: intentional 0.2.0\nplan-digest: sha256:{}\ntag-id: release-unit/sample/primary\nversion: {version}\nbaseline: {baseline}\n", "a".repeat(64))
}

fn tag(root: &Path, name: &str, version: &str, baseline: bool) {
    git(
        root,
        &["tag", "-a", name, "-m", &message(version, baseline)],
    );
}

fn policy(ids: &[&str]) -> ResolvedPolicy {
    ResolvedPolicy {
        name: "fixture".into(),
        source: "fixture".into(),
        commit: None,
        bundle_digest: "fixture".into(),
        sources: Vec::new(),
        suppressions: Default::default(),
        accepted_version: airlock_core::policy::current_generation(),
        exceptions: BTreeMap::new(),
        rules: ids
            .iter()
            .map(|id| {
                let def = rules::find(id).unwrap();
                EffectiveRule {
                    def,
                    severity: def.severity,
                    params: BTreeMap::new(),
                    provenance: "fixture".into(),
                }
            })
            .collect(),
    }
}

#[test]
fn local_baseline_alone_enters_building_without_intents_or_more_commits() {
    let dir = repository();
    assert_eq!(
        maturity::read_local(dir.path(), 10).unwrap().rung,
        Lifecycle::Seeded
    );
    tag(dir.path(), "sample@4.0.0", "4.0.0", true);
    assert_eq!(
        maturity::read_local(dir.path(), 10).unwrap().rung,
        Lifecycle::Building
    );
}

#[test]
fn local_maturity_ignores_uncommitted_configuration_and_untracked_intents() {
    let dir = repository();
    tag(dir.path(), "sample@0.0.0", "0.0.0", true);
    git(
        dir.path(),
        &["commit", "--allow-empty", "-qm", "another commit"],
    );
    tag(dir.path(), "sample@1.0.0", "1.0.0", false);
    std::fs::write(
        dir.path().join(".intentional/config.yml"),
        "release-units: {}\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join(".intentional/intents")).unwrap();
    std::fs::write(
        dir.path().join(".intentional/intents/sample.yml"),
        "anything\n",
    )
    .unwrap();
    assert_eq!(
        maturity::read_local(dir.path(), 10).unwrap().rung,
        Lifecycle::Stable
    );
}

#[test]
fn local_lightweight_tags_and_other_branch_records_do_not_raise_maturity() {
    let dir = repository();
    git(dir.path(), &["tag", "9.0.0"]);
    git(dir.path(), &["checkout", "-qb", "other"]);
    git(
        dir.path(),
        &["commit", "--allow-empty", "-qm", "other branch"],
    );
    tag(dir.path(), "sample@2.0.0", "2.0.0", true);
    git(dir.path(), &["checkout", "-q", "main"]);
    assert_eq!(
        maturity::read_local(dir.path(), 10).unwrap().rung,
        Lifecycle::Seeded
    );
}

#[test]
fn local_shallow_or_budget_exhausted_history_is_unobserved() {
    let dir = repository();
    tag(dir.path(), "sample@0.0.0", "0.0.0", true);
    git(dir.path(), &["commit", "--allow-empty", "-qm", "next"]);
    assert!(maturity::read_local(dir.path(), 1).is_err());
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    std::fs::write(dir.path().join(".git/shallow"), format!("{head}\n")).unwrap();
    assert!(maturity::read_local(dir.path(), 10).is_err());
}

#[test]
fn local_audit_applies_maturity_before_missing_api_routing() {
    let dir = repository();
    let mut policy = policy(&["REPO-TPL-01", "REPO-REL-08"]);
    policy.rules[0].params.insert(
        "templates".into(),
        serde_json::json!([{"source":"gh:example-org/catalog#bundle","ref":"main"}]),
    );
    let options = audit::AuditOptions::default();
    let seeded = audit::run_local(&policy, &options, dir.path()).unwrap();
    assert_eq!(seeded.out_of_scope.len(), 2);
    assert!(seeded.findings.is_empty() && seeded.routed.is_empty());
    assert_eq!(seeded.exit_code(), 0);
    tag(dir.path(), "sample@0.0.0", "0.0.0", true);
    let building = audit::run_local(&policy, &options, dir.path()).unwrap();
    assert_eq!(building.out_of_scope.len(), 1);
    assert_eq!(building.out_of_scope[0].rule, "REPO-REL-08");
    assert_eq!(building.routed[0].rule, "REPO-TPL-01");
    assert_eq!(
        building.maturity.unwrap().observed.unwrap().rung,
        Lifecycle::Building
    );
}

#[test]
fn prospective_assessments_exclude_a_committed_authorized_waiver() {
    let dir = repository();
    std::fs::create_dir(dir.path().join(".github")).unwrap();
    std::fs::write(
        dir.path().join(".github/airlock.yml"),
        "version: 0.6.0\nexceptions:\n  REPO-REL-08:\n    reason: Fixture exception\n    severity: none\n",
    )
    .unwrap();
    git(dir.path(), &["add", ".github/airlock.yml"]);
    git(dir.path(), &["commit", "-qm", "fixture exception"]);
    let mut policy = policy(&["REPO-REL-08"]);
    policy
        .suppressions
        .allow_repo_requests
        .insert("REPO-REL-08".into());
    let report = audit::run_local(&policy, &audit::AuditOptions::default(), dir.path()).unwrap();
    assert_eq!(report.waived.len(), 1);
    assert!(report
        .maturity
        .unwrap()
        .transitions
        .iter()
        .all(|transition| transition.adds == 0));
}

#[tokio::test]
async fn captured_api_objects_and_local_git_observe_the_same_maturity() {
    use airlock_core::github::{RestClient, RestClientConfig};
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    let dir = repository();
    tag(dir.path(), "sample@0.0.0", "0.0.0", true);
    let baseline = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["commit", "--allow-empty", "-qm", "next"]);
    tag(dir.path(), "sample@1.0.0", "1.0.0", false);
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    let server = MockServer::start().await;
    let config = std::fs::read_to_string(dir.path().join(".intentional/config.yml")).unwrap();
    let mut routes = vec![
        (
            "/repos/owner/name".into(),
            json!({"id":1,"name":"name","full_name":"owner/name","default_branch":"main"}),
        ),
        ("/repos/owner/name/commits/main".into(), json!({"sha":head})),
        ("/repos/owner/name/topics".into(), json!({"names":[]})),
        (
            format!("/repos/owner/name/git/trees/{head}"),
            json!({"tree":[{"path":".intentional/config.yml","mode":"100644","sha":"config","size":config.len()}],"truncated":false}),
        ),
        (
            "/repos/owner/name/git/blobs/config".into(),
            json!({"encoding":"utf-8","content":config}),
        ),
        (
            "/repos/owner/name/commits".into(),
            json!([{"sha":head,"parents":[{"sha":baseline}]},{"sha":baseline,"parents":[]}]),
        ),
    ];
    let mut refs = Vec::new();
    for (name, commit, version, is_baseline) in [
        ("sample@0.0.0", &baseline, "0.0.0", true),
        ("sample@1.0.0", &head, "1.0.0", false),
    ] {
        let sha = git(dir.path(), &["rev-parse", name]);
        refs.push(json!({"ref":format!("refs/tags/{name}"),"object":{"type":"tag","sha":sha}}));
        routes.push((format!("/repos/owner/name/git/tags/{sha}"), json!({"message":message(version,is_baseline),"tagger":{"name":"fixture","email":"fixture@example.invalid"},"object":{"type":"commit","sha":commit}})));
    }
    routes.push((
        "/repos/owner/name/git/matching-refs/tags/".into(),
        json!(refs),
    ));
    for (route, body) in routes {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    let client = RestClient::new(
        "fixture",
        RestClientConfig {
            base_url: server.uri(),
            ..RestClientConfig::default()
        },
    )
    .unwrap();
    let policy = policy(&["REPO-GIT-15"]);
    let options = audit::AuditOptions::default();
    let api = audit::run(&client, "owner", "name", &policy, &options, None)
        .await
        .unwrap();
    let local = audit::run_local(&policy, &options, dir.path()).unwrap();
    assert_eq!(api.maturity, local.maturity);
    assert_eq!(
        api.maturity
            .as_ref()
            .unwrap()
            .observed
            .as_ref()
            .unwrap()
            .rung,
        Lifecycle::Stable
    );
    assert_eq!(api.findings[0].status, local.findings[0].status);
}

#[tokio::test]
async fn mixed_audit_maturity_stays_at_captured_head_when_local_head_moves() {
    use airlock_core::github::{RestClient, RestClientConfig};
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    let dir = repository();
    tag(dir.path(), "sample@0.0.0", "0.0.0", true);
    let captured = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["checkout", "-qb", "next"]);
    git(dir.path(), &["commit", "--allow-empty", "-qm", "next"]);
    tag(dir.path(), "sample@1.0.0", "1.0.0", false);
    let later = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["checkout", "-q", "main"]);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/owner/name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"id":1,"name":"name","full_name":"owner/name","default_branch":"main"}),
        ))
        .mount(&server)
        .await;
    let root = dir.path().to_owned();
    Mock::given(method("GET"))
        .and(path("/repos/owner/name/git/matching-refs/tags/"))
        .respond_with(move |_: &wiremock::Request| {
            git(&root, &["checkout", "-q", "next"]);
            ResponseTemplate::new(200).set_body_json(json!([]))
        })
        .mount(&server)
        .await;
    let client = RestClient::new(
        "fixture",
        RestClientConfig {
            base_url: server.uri(),
            ..Default::default()
        },
    )
    .unwrap();
    let options = audit::AuditOptions {
        working_tree: Some(dir.path().to_owned()),
        ..Default::default()
    };
    let report = audit::run(
        &client,
        "owner",
        "name",
        &policy(&["REPO-GIT-15"]),
        &options,
        None,
    )
    .await
    .unwrap();
    assert_eq!(git(dir.path(), &["rev-parse", "HEAD"]), later);
    assert_eq!(report.repository.audited_commit, captured);
    assert_eq!(
        report.maturity.unwrap().observed.unwrap().rung,
        Lifecycle::Building
    );
}
