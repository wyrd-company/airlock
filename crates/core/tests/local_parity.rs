//! Parity between the two observation sources.
//!
//! For a clean checkout at the audited commit, local and API evaluation must
//! agree on every file-level rule. Divergence is a bug in one of them, and
//! this test is what catches it.
//!
//! Test-only note: the shipped binary never shells out, but these tests use
//! the `git` binary to build real repositories to observe.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use airlock_core::audit::{self, AuditOptions};
use airlock_core::findings::{Report, Status};
use airlock_core::github::{
    ApiError, ApiResult, AuthenticatedUser, BranchRule, CommitSummary, EntryKind, ErrorCause,
    GitHub, Installation, InstallationRepositories, Paged, Repository, Ruleset, TagRef, Tree,
    TreeEntry,
};
use airlock_core::limits::Limits;
use airlock_core::policy::{EffectiveRule, ResolvedPolicy};
use airlock_core::rules::{self, Observation};

/// One fixture file: path, content, and whether it is a symlink target
/// instead of regular content.
enum Fixture {
    File(&'static str, &'static str),
    Symlink(&'static str, &'static str),
}

use Fixture::{File, Symlink};

/// A small but realistic repository: some rules pass, some fail, and one
/// path is a symlink. Parity is about agreement, not about conformance.
const FIXTURES: &[Fixture] = &[
    File("README.md", "# widget\n\nA thing that widgets.\n"),
    File("LICENSE", "Apache License\nVersion 2.0, January 2004\n"),
    File("CONTRIBUTING.md", "Run `task check`.\n"),
    File(".gitignore", "target/\nsecret-*.txt\n"),
    File(".gitattributes", "* text=auto\n"),
    File(".editorconfig", "root = true\n"),
    File(
        "taskfile.yml",
        "version: '3'\ntasks:\n  test: {cmds: [echo test]}\n  lint: {cmds: [echo lint]}\n  format: {cmds: [echo format]}\n  check: {cmds: [echo check]}\n",
    ),
    File("AGENTS.md", "Widget conventions.\n"),
    Symlink("CLAUDE.md", "AGENTS.md"),
    File(
        ".github/repo-settings.yml",
        "description: A thing that widgets.\ntopics: [cli, rust-crate, widgets]\nmerge:\n  squash: true\n  rebase: true\n  merge-commit: false\n  delete-branch-on-merge: true\n",
    ),
    File(
        ".github/workflows/ci.yml",
        "on:\n  pull_request:\npermissions: {}\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\njobs:\n  check:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: task check\n",
    ),
    File(
        ".intentional/config.yml",
        "release-units:\n  widget:\n    path: .\n",
    ),
    File("CHANGELOG.md", "# Changelog\n"),
    File(
        "Cargo.toml",
        "[package]\nname = \"widget\"\nlicense = \"Apache-2.0\"\n",
    ),
    // A deliberate failure both sources must agree on.
    File("CODEOWNERS", "* @acme/widgets\n"),
];

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Materialise the fixtures as a committed git repository.
fn committed_repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    for fixture in FIXTURES {
        match fixture {
            File(path, content) => {
                let on_disk = root.join(path);
                std::fs::create_dir_all(on_disk.parent().expect("a parent")).expect("mkdir");
                std::fs::write(on_disk, content).expect("write");
            }
            Symlink(path, target) => {
                std::os::unix::fs::symlink(target, root.join(path)).expect("symlink");
            }
        }
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "fixture"]);
    dir
}

/// The same fixtures, served as a fake GitHub API.
struct FakeGitHub {
    tree: Tree,
    blobs: BTreeMap<String, Vec<u8>>,
    disclose_merge_settings: bool,
}

impl FakeGitHub {
    fn new() -> Self {
        let mut entries = Vec::new();
        let mut blobs = BTreeMap::new();
        for (index, fixture) in FIXTURES.iter().enumerate() {
            let sha = format!("{index:040x}");
            let (path, kind, mode, bytes) = match fixture {
                File(path, content) => (*path, EntryKind::Blob, "100644", content.as_bytes()),
                Symlink(path, target) => (*path, EntryKind::Symlink, "120000", target.as_bytes()),
            };
            entries.push(TreeEntry {
                path: path.to_owned(),
                kind,
                mode: mode.to_owned(),
                sha: sha.clone(),
                size: Some(bytes.len() as u64),
            });
            blobs.insert(sha, bytes.to_vec());
        }
        Self {
            tree: Tree {
                entries,
                truncated: false,
            },
            blobs,
            disclose_merge_settings: true,
        }
    }
}

impl GitHub for FakeGitHub {
    async fn repository(&self, _owner: &str, _repo: &str) -> ApiResult<Repository> {
        Ok(Repository {
            full_name: "acme/widget".to_owned(),
            id: 7,
            owner: "acme".to_owned(),
            name: "widget".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "public".to_owned(),
            description: Some("A thing that widgets.".to_owned()),
            license_spdx: Some("Apache-2.0".to_owned()),
            allow_merge_commit: self.disclose_merge_settings.then_some(false),
            allow_squash_merge: Some(true),
            allow_rebase_merge: Some(true),
            delete_branch_on_merge: Some(true),
            has_wiki: false,
            has_projects: false,
            has_discussions: false,
            has_issues: true,
            observed_at: None,
        })
    }

    async fn topics(&self, _owner: &str, _repo: &str) -> ApiResult<Vec<String>> {
        Ok(vec![
            "cli".to_owned(),
            "rust-crate".to_owned(),
            "widgets".to_owned(),
        ])
    }

    async fn resolve_commit(
        &self,
        _owner: &str,
        _repo: &str,
        _reference: &str,
    ) -> ApiResult<String> {
        Ok("c".repeat(40))
    }

    async fn tree(&self, _owner: &str, _repo: &str, _commit: &str) -> ApiResult<Tree> {
        Ok(self.tree.clone())
    }

    async fn blob(&self, _owner: &str, _repo: &str, sha: &str) -> ApiResult<Vec<u8>> {
        self.blobs.get(sha).cloned().ok_or_else(|| {
            ApiError::local(ErrorCause::NotFound, format!("blob {sha}"), "no such blob")
        })
    }

    async fn tags(&self, _owner: &str, _repo: &str) -> ApiResult<Paged<TagRef>> {
        Ok(Paged::complete(Vec::new()))
    }

    async fn history(
        &self,
        _owner: &str,
        _repo: &str,
        _commit: &str,
        _max_commits: usize,
    ) -> ApiResult<Paged<CommitSummary>> {
        Ok(Paged::complete(Vec::new()))
    }

    async fn rulesets(&self, _owner: &str, _repo: &str) -> ApiResult<Paged<Ruleset>> {
        Ok(Paged::complete(Vec::new()))
    }

    async fn branch_rules(
        &self,
        _owner: &str,
        _repo: &str,
        _branch: &str,
    ) -> ApiResult<Paged<BranchRule>> {
        Ok(Paged::complete(Vec::new()))
    }

    async fn user_installations(&self) -> ApiResult<Vec<Installation>> {
        Ok(Vec::new())
    }

    async fn installation_repositories(
        &self,
        _installation_id: u64,
    ) -> ApiResult<InstallationRepositories> {
        Ok(InstallationRepositories {
            repositories: Vec::new(),
            total_count: 0,
            truncated: false,
        })
    }

    async fn authenticated_user(&self) -> ApiResult<AuthenticatedUser> {
        Err(ApiError::local(
            ErrorCause::Unauthenticated,
            "local://fake",
            "not needed",
        ))
    }
}

/// A policy enabling every registered rule at its registered severity.
fn full_policy() -> ResolvedPolicy {
    ResolvedPolicy {
        name: "parity".to_owned(),
        source: "./policy.yml".to_owned(),
        commit: None,
        bundle_digest: "sha256:0".to_owned(),
        sources: Vec::new(),
        rules: rules::RULES
            .iter()
            .map(|def| EffectiveRule {
                def,
                severity: def.severity,
                params: BTreeMap::new(),
                provenance: "parity".to_owned(),
            })
            .collect(),
        suppressions: Default::default(),
        reference_data: BTreeMap::new(),
        capabilities: Vec::new(),
    }
}

fn options() -> AuditOptions {
    AuditOptions {
        reference: None,
        limits: Limits::default(),
        version: "0.0.0-test".to_owned(),
        working_tree: None,
    }
}

/// The comparable shape of one finding: status and evidence code.
fn file_rule_outcomes(report: &Report) -> BTreeMap<String, (String, Option<String>)> {
    report
        .findings
        .iter()
        .filter(|finding| {
            let def = rules::find(&finding.rule).expect("a registered rule");
            def.observation() == Observation::FileTree && !def.needs_github_api()
        })
        .map(|finding| {
            (
                finding.rule.clone(),
                (
                    finding.status_code().to_owned(),
                    finding
                        .evidence
                        .as_ref()
                        .map(|evidence| evidence.code.clone()),
                ),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_clean_checkout_agrees_with_the_api_on_every_file_level_rule() {
    let repo = committed_repository();
    // Both sources observe the same repository identity as well as file bytes.
    git(
        repo.path(),
        &["remote", "add", "origin", "git@github.com:acme/widget.git"],
    );
    let policy = full_policy();

    let api_report = audit::run(
        &FakeGitHub::new(),
        "acme",
        "widget",
        &policy,
        &options(),
        None,
    )
    .await
    .expect("the API audit runs");

    let local_report =
        audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");

    let api = file_rule_outcomes(&api_report);
    let local = file_rule_outcomes(&local_report);
    assert!(!api.is_empty());
    for (rule, api_outcome) in &api {
        assert_eq!(
            local.get(rule),
            Some(api_outcome),
            "{rule} diverged between the API and the working tree"
        );
    }
    assert_eq!(api.len(), local.len());
}

#[tokio::test]
async fn every_finding_names_the_source_that_decided_it() {
    let repo = committed_repository();
    let policy = full_policy();

    let api_report = audit::run(
        &FakeGitHub::new(),
        "acme",
        "widget",
        &policy,
        &options(),
        None,
    )
    .await
    .expect("the API audit runs");
    for finding in &api_report.findings {
        assert_eq!(finding.source.as_deref(), Some("api"), "{}", finding.rule);
    }
    assert_eq!(api_report.observation.file_source, "api");
    assert_eq!(
        api_report.observation.platform_source.as_deref(),
        Some("api")
    );
    assert!(api_report.observation.working_tree.is_none());

    let local_report =
        audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    for finding in &local_report.findings {
        assert_eq!(
            finding.source.as_deref(),
            Some("working-tree"),
            "{}",
            finding.rule
        );
    }
}

#[tokio::test]
async fn an_unobserved_platform_rule_is_routed_and_never_met() {
    let repo = committed_repository();
    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");

    let mut gated = 0;
    for finding in report.entries() {
        let def = rules::find(&finding.rule).expect("registered");
        if def.observation() == Observation::Platform {
            gated += 1;
            assert_eq!(
                finding.routing.as_ref().map(|r| r.reason.as_str()),
                Some("needs-github-api"),
                "{}",
                finding.rule
            );
        }
    }
    assert!(gated > 0, "the fixture policy enables platform rules");
    assert_eq!(report.observation.platform_source, None);
    assert!(report.routed.iter().all(|f| f.status.is_none()));
}

#[tokio::test]
async fn the_local_observation_states_its_terms() {
    let repo = committed_repository();
    // Dirty the tree: uncommitted content is part of what is observed.
    std::fs::write(repo.path().join("NOTES.md"), "untracked\n").expect("write");

    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");

    let observed = report
        .observation
        .working_tree
        .as_ref()
        .expect("a working-tree observation");
    assert_eq!(observed.dirty, Some(true), "a dirty tree is reported dirty");
    assert!(observed.includes_uncommitted);
    assert!(observed.ignored_files_excluded);
    assert_eq!(observed.head_commit.len(), 40);
    assert_eq!(report.repository.audited_commit, observed.head_commit);
    assert_eq!(report.repository.id, None);
}

#[tokio::test]
async fn a_clean_tree_is_reported_clean() {
    let repo = committed_repository();
    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let observed = report.observation.working_tree.as_ref().expect("observed");
    assert_eq!(observed.dirty, Some(false));
}

#[tokio::test]
async fn an_ignored_untracked_file_satisfies_no_rule() {
    let repo = committed_repository();
    // .gitignore excludes secret-*.txt; an ignored AGENTS.md replacement
    // cannot happen, so use a path a rule wants: remove the tracked
    // .editorconfig, commit, then recreate it as an ignored file.
    git(repo.path(), &["rm", "-q", ".editorconfig"]);
    git(repo.path(), &["commit", "-q", "-m", "drop editorconfig"]);
    std::fs::write(repo.path().join(".gitignore"), "target/\n.editorconfig\n").expect("write");
    std::fs::write(repo.path().join(".editorconfig"), "root = true\n").expect("write");

    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule == "REPO-FILE-05")
        .expect("REPO-FILE-05 is enabled");
    assert_eq!(
        finding.status,
        Some(Status::Gap),
        "an ignored file is not destined for the repository, so it satisfies nothing"
    );
}

#[tokio::test]
async fn an_untracked_file_is_observed_as_it_stands() {
    let repo = committed_repository();
    git(repo.path(), &["rm", "-q", "CONTRIBUTING.md"]);
    git(repo.path(), &["commit", "-q", "-m", "drop contributing"]);
    // Recreated but not committed: the agent just wrote it, and that is what
    // it is asking about.
    std::fs::write(repo.path().join("CONTRIBUTING.md"), "Run `task check`.\n").expect("write");

    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule == "REPO-FILE-02")
        .expect("REPO-FILE-02 is enabled");
    assert_eq!(finding.status, Some(Status::Met));
    let observed = report.observation.working_tree.as_ref().expect("observed");
    assert_eq!(observed.dirty, Some(true));
}

#[tokio::test]
async fn a_working_tree_without_git_is_refused_not_guessed_at() {
    let dir = tempfile::tempdir().expect("a temp dir");
    std::fs::write(dir.path().join("README.md"), "# thing\n").expect("write");
    let policy = full_policy();
    let error = audit::run_local(&policy, &options(), dir.path())
        .expect_err("a bare directory is not an observation source");
    assert!(
        error.to_string().contains("working tree"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn an_uncommitted_suppression_request_suppresses_nothing() {
    let repo = committed_repository();
    let mut policy = full_policy();
    policy.suppressions.allow_repo_requests = std::iter::once("REPO-FILE-14".to_owned()).collect();

    // The request exists only in the working tree, never committed.
    std::fs::write(
        repo.path().join(".github/airlock.yml"),
        "version: 1\nsuppress:\n  - rule: REPO-FILE-14\n    reason: we like CODEOWNERS\n",
    )
    .expect("write");

    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule == "REPO-FILE-14")
        .expect("REPO-FILE-14 is enabled");
    assert_eq!(
        finding.status,
        Some(Status::Gap),
        "authorization comes from committed content, not the tree as it stands"
    );

    // Committed, the same request is honoured.
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "request suppression"]);
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let finding = report
        .waived
        .iter()
        .find(|finding| finding.rule == "REPO-FILE-14")
        .expect("REPO-FILE-14 is enabled");
    assert_eq!(finding.status, None);
}

/// Captured by running the same API corpus at the integration base 7708ddd.
/// Only the old compiled pass/fail results are authoritative for this agreement.
#[tokio::test]
async fn decided_outcomes_match_the_integration_base() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/outcomes-7708ddd.json")).unwrap();
    for (name, empty) in [("populated", false), ("empty", true)] {
        let mut api = FakeGitHub::new();
        if empty {
            api.tree.entries.clear();
            api.blobs.clear();
        }
        let report = audit::run(&api, "acme", "widget", &full_policy(), &options(), None)
            .await
            .unwrap();
        assert_eq!(
            report.exit_code(),
            1,
            "{name}: a previously complete audit must stay complete"
        );
        assert!(
            report.run_errors.is_empty(),
            "{name}: {:?}",
            report.run_errors
        );
        let expected = expected[name].as_object().unwrap();
        assert!(!expected.is_empty());
        for (id, base) in expected {
            // Absent required configuration is now an authorized waiver, even
            // when the base checked repository inputs first and reported a Gap.
            if matches!(id.as_str(), "REPO-META-07" | "REPO-META-09") {
                assert_eq!(
                    base["status"], "gap",
                    "only the ruled absent-configuration Gaps change"
                );
                let waiver = report
                    .waived
                    .iter()
                    .find(|entry| &entry.rule == id)
                    .unwrap();
                assert!(waiver.status.is_none() && waiver.evidence.is_none());
                assert_eq!(
                    waiver
                        .suppression
                        .as_ref()
                        .unwrap()
                        .policy_reason
                        .as_deref(),
                    Some("no reference data configured")
                );
                continue;
            }
            let finding = report
                .findings
                .iter()
                .find(|f| &f.rule == id)
                .unwrap_or_else(|| {
                    panic!("{name}: previously decided {id} no longer has a compiled outcome")
                });
            assert_eq!(
                finding.status_code(),
                base["status"].as_str().unwrap(),
                "{name}: {id}"
            );
            assert_eq!(
                serde_json::to_value(finding.evidence.as_ref().map(|e| &e.code)).unwrap(),
                base["evidence"],
                "{name}: {id}"
            );
        }
    }
}

fn policy_with_one(id: &str, severity: airlock_core::rules::Severity) -> ResolvedPolicy {
    let mut policy = full_policy();
    policy.rules.retain(|rule| rule.def.id == id);
    assert_eq!(policy.rules.len(), 1);
    policy.rules[0].severity = severity;
    policy
}

#[test]
fn a_waived_rule_does_not_run_its_check() {
    let repo = committed_repository();
    std::fs::write(repo.path().join(".github/renovate.json"), "{").unwrap();
    let policy = policy_with_one("REPO-FILE-08", airlock_core::rules::Severity::None);
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(report.exit_code(), 0);
    assert!(report.findings.is_empty());
    assert!(report.run_errors.is_empty());
    assert_eq!(report.waived.len(), 1);
    assert_eq!(report.effective_policy[0].severity, "none");
    assert!(report.waived[0].status.is_none());
    assert!(
        report.waived[0].evidence.is_none(),
        "the waived check must not execute"
    );
    assert!(report.waived[0]
        .suppression
        .as_ref()
        .unwrap()
        .policy_reason
        .is_some());
}

#[test]
fn the_api_gate_routes_a_whole_file_tree_rule() {
    let repo = committed_repository();
    for id in ["REPO-CD-03", "REPO-REL-07", "REPO-REL-08"] {
        let policy = policy_with_one(id, airlock_core::rules::Severity::Blocking);
        assert!(policy.rules[0].def.needs_github_api(), "{id}");
        let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
        assert_eq!(report.exit_code(), 0);
        assert!(report.findings.is_empty());
        assert!(report.unbuilt.is_empty());
        assert!(report.run_errors.is_empty());
        assert_eq!(report.routed.len(), 1);
        let route = report.routed[0].routing.as_ref().unwrap();
        assert_eq!(route.reason, "needs-github-api");
        assert!(route.settling_surface.contains("API-tree"));
    }
}

#[tokio::test]
async fn disclosure_routing_and_a_missing_input_without_a_gate_are_distinct() {
    let policy = policy_with_one("REPO-GIT-04", airlock_core::rules::Severity::Blocking);
    let mut api = FakeGitHub::new();
    api.disclose_merge_settings = false;
    let report = audit::run(&api, "acme", "widget", &policy, &options(), None)
        .await
        .unwrap();
    assert_eq!(report.exit_code(), 0);
    assert!(report.findings.is_empty());
    assert_eq!(report.routed.len(), 1);
    assert!(report.routed[0]
        .routing
        .as_ref()
        .unwrap()
        .settling_surface
        .contains("interactive"));

    let repo = committed_repository();
    // No manifest can tell this check whether a registry package exists.
    std::fs::remove_file(repo.path().join("Cargo.toml")).unwrap();
    let policy = policy_with_one("REPO-LIC-04", airlock_core::rules::Severity::Advisory);
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(report.exit_code(), 2);
    assert!(report.findings.is_empty());
    assert!(report.routed.is_empty());
    assert_eq!(report.run_errors.len(), 1);
    assert!(report.run_errors[0].error.is_some());
}

#[test]
fn unbuilt_branches_preserve_decided_outcomes() {
    let repo = committed_repository();
    let policy = policy_with_one("REPO-FILE-03", airlock_core::rules::Severity::Blocking);
    let unbuilt = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(unbuilt.exit_code(), 0);
    assert_eq!(unbuilt.unbuilt.len(), 1);
    assert!(unbuilt.findings.is_empty());
    assert_eq!(
        unbuilt.unbuilt[0].routing.as_ref().unwrap().reason,
        "unbuilt"
    );
    std::fs::remove_file(repo.path().join(".gitignore")).unwrap();
    let gap = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(gap.exit_code(), 1);
    assert_eq!(gap.findings[0].status, Some(Status::Gap));
    assert!(gap.unbuilt.is_empty());
}

#[test]
fn missing_renovate_file_is_a_gap_before_the_owner_gate() {
    let repo = committed_repository();
    let policy = policy_with_one("REPO-FILE-08", airlock_core::rules::Severity::Blocking);
    let gap = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(gap.findings[0].status, Some(Status::Gap));
    assert_eq!(gap.exit_code(), 1);
    std::fs::write(
        repo.path().join(".github/renovate.json"),
        "{\"extends\":[\"config:recommended\"]}",
    )
    .unwrap();
    let routed = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(routed.exit_code(), 0);
    assert!(routed.findings.is_empty());
    assert_eq!(
        routed.routed[0].routing.as_ref().unwrap().reason,
        "needs-repository-owner"
    );
}

#[test]
fn severity_alone_controls_the_gap_exit_code() {
    let repo = committed_repository();
    std::fs::remove_file(repo.path().join("LICENSE")).unwrap();
    for (severity, expected) in [
        (airlock_core::rules::Severity::Advisory, 0),
        (airlock_core::rules::Severity::Blocking, 1),
    ] {
        let policy = policy_with_one("REPO-LIC-01", severity);
        let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
        assert_eq!(report.findings[0].status, Some(Status::Gap));
        assert_eq!(report.exit_code(), expected);
        assert_eq!(report.schema_version, 2);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["status"], "gap");
        assert!(json["policy"].get("gate").is_none());
        for list in ["waived", "routed", "unbuilt", "run_errors"] {
            assert!(json[list].as_array().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn no_release_units_are_listed_out_of_scope_without_run_errors() {
    let mut api = FakeGitHub::new();
    api.tree.entries.clear();
    api.blobs.clear();
    let report = audit::run(&api, "acme", "widget", &full_policy(), &options(), None)
        .await
        .unwrap();
    let ids: Vec<_> = report
        .out_of_scope
        .iter()
        .map(|entry| entry.rule.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "REPO-GIT-09",
            "REPO-LIC-04",
            "REPO-REL-02",
            "REPO-REL-03",
            "REPO-TASK-04"
        ]
    );
    assert_eq!(report.exit_code(), 1);
    assert!(report.complete && report.run_errors.is_empty());
    assert_eq!(report.summary.out_of_scope, 5);
    for entry in &report.out_of_scope {
        assert!(entry.status.is_none() && entry.error.is_none());
        assert_eq!(entry.status_code(), "out-of-scope");
        assert_eq!(entry.routing.as_ref().unwrap().reason, "out-of-scope");
        assert_eq!(
            entry.evidence.as_ref().unwrap().code,
            "no_release_units_declared"
        );
    }
    let list = airlock_core::worklist::AgentWorkList::from_report(&report);
    assert_eq!(list.out_of_scope.count, 5);
    assert!(list.out_of_scope.items.iter().all(|entry| !entry.gating));
    let json = serde_json::to_value(&list).unwrap();
    assert_eq!(json["out_of_scope"]["count"], 5);
    let text = airlock_core::render::agent_work_list_text(&list);
    assert!(
        text.contains("out-of-scope (exit code unchanged) (5)"),
        "{text}"
    );
    let text = airlock_core::render::report_text(&report);
    assert!(text.contains("out-of-scope: 5"), "{text}");
    let text = airlock_core::render::plan_text(&report);
    assert!(text.contains("out-of-scope (5)"), "{text}");
    assert!(!text.contains("Every rule was evaluated"));
}

#[test]
fn release_unit_scope_distinguishes_absence_from_malformed_input() {
    let repo = committed_repository();
    for input in [None, Some("release-units: {}\n"), Some("settings: {}\n")] {
        let path = repo.path().join(".intentional/config.yml");
        if let Some(text) = input {
            std::fs::write(&path, text).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        for id in [
            "REPO-GIT-09",
            "REPO-LIC-04",
            "REPO-REL-02",
            "REPO-REL-03",
            "REPO-TASK-04",
        ] {
            let policy = policy_with_one(id, airlock_core::rules::Severity::Blocking);
            let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
            assert_eq!(report.exit_code(), 0, "{id}: {input:?}");
            assert_eq!(report.out_of_scope.len(), 1, "{id}: {input:?}");
            assert!(
                report.findings.is_empty() && report.routed.is_empty() && report.unbuilt.is_empty()
            );
            assert_eq!(report.effective_policy[0].severity, "blocking");
        }
    }
    for input in ["release-units: [sample]\n", "{invalid"] {
        std::fs::write(repo.path().join(".intentional/config.yml"), input).unwrap();
        for id in [
            "REPO-GIT-09",
            "REPO-LIC-04",
            "REPO-REL-02",
            "REPO-REL-03",
            "REPO-TASK-04",
        ] {
            let policy = policy_with_one(id, airlock_core::rules::Severity::Advisory);
            let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
            assert_eq!(report.exit_code(), 2, "{id}: {input:?}");
            assert_eq!(report.run_errors.len(), 1, "{id}");
            assert!(report.out_of_scope.is_empty(), "{id}");
        }
    }
}

#[test]
fn include_namespaces_only_reach_the_scope_gate_when_a_comparison_is_needed() {
    let repo = committed_repository();
    std::fs::remove_file(repo.path().join(".intentional/config.yml")).unwrap();
    let policy = policy_with_one("REPO-TASK-06", airlock_core::rules::Severity::Blocking);
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(report.findings[0].status, Some(Status::Met));
    std::fs::write(
        repo.path().join("taskfile.yml"),
        "version: '3'\nincludes:\n  sample: ./sample/taskfile.yml\n",
    )
    .unwrap();
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.out_of_scope.len(), 1);
    assert!(report.findings.is_empty());
}

fn topic_policy() -> ResolvedPolicy {
    let mut policy = full_policy();
    policy
        .rules
        .retain(|rule| matches!(rule.def.id, "REPO-META-07" | "REPO-META-09"));
    for rule in &mut policy.rules {
        rule.severity = airlock_core::rules::Severity::Blocking;
    }
    policy
}

#[test]
fn absent_topic_configuration_waives_checks_before_reading_repository_inputs() {
    let repo = committed_repository();
    std::fs::write(repo.path().join(".github/repo-settings.yml"), "{invalid").unwrap();
    let policy = topic_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(report.exit_code(), 0);
    assert!(report.findings.is_empty() && report.run_errors.is_empty());
    assert_eq!(report.waived.len(), 2);
    for entry in &report.waived {
        assert!(entry.status.is_none() && entry.evidence.is_none());
        assert_eq!(entry.severity, "none");
        assert_eq!(
            entry.suppression.as_ref().unwrap().policy_reason.as_deref(),
            Some("no reference data configured")
        );
    }
    assert!(report
        .effective_policy
        .iter()
        .all(|rule| rule.severity == "none"));
}

#[test]
fn partial_topic_configuration_names_missing_categories_before_reading_repository_inputs() {
    let repo = committed_repository();
    std::fs::write(repo.path().join(".github/repo-settings.yml"), "{invalid").unwrap();
    for (topics, reason) in [
        (
            "artifact-type: [cli]\n",
            "missing required topic categories: ecosystem",
        ),
        (
            "ecosystem: [rust-crate]\n",
            "missing required topic categories: artifact-type",
        ),
        (
            "other: [widgets]\n",
            "missing required topic categories: artifact-type, ecosystem",
        ),
        (
            "{}",
            "missing required topic categories: artifact-type, ecosystem",
        ),
    ] {
        let mut policy = topic_policy();
        policy.rules.retain(|rule| rule.def.id == "REPO-META-07");
        policy.reference_data.insert(
            "topics".to_owned(),
            airlock_core::yaml::parse_mapping(topics, Limits::default().yaml).unwrap(),
        );
        let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
        assert_eq!(report.exit_code(), 0, "{topics}");
        assert!(report.findings.is_empty() && report.run_errors.is_empty());
        assert_eq!(report.waived.len(), 1);
        let entry = &report.waived[0];
        assert_eq!(entry.rule, "REPO-META-07");
        assert!(entry.status.is_none() && entry.evidence.is_none());
        assert_eq!(entry.severity, "none");
        assert_eq!(
            entry.suppression.as_ref().unwrap().policy_reason.as_deref(),
            Some(reason)
        );
        assert_eq!(report.effective_policy[0].severity, "none");
    }
}

#[test]
fn configured_topics_evaluate_and_malformed_configuration_is_a_run_error() {
    let repo = committed_repository();
    let mut policy = topic_policy();
    policy.reference_data.insert(
        "topics".to_owned(),
        airlock_core::yaml::parse_mapping(
            "artifact-type: [cli]\necosystem: [rust-crate]\nother: [widgets]\n",
            Limits::default().yaml,
        )
        .unwrap(),
    );
    let met = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(met.exit_code(), 0);
    assert_eq!(met.summary.met, 2);
    assert!(met.waived.is_empty());

    policy.reference_data.insert(
        "topics".to_owned(),
        airlock_core::yaml::parse_mapping(
            "artifact-type: [cli]\necosystem: [other]\n",
            Limits::default().yaml,
        )
        .unwrap(),
    );
    let gaps = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(gaps.exit_code(), 1);
    assert_eq!(gaps.summary.gap, 2);

    policy.reference_data.insert(
        "topics".to_owned(),
        airlock_core::yaml::parse_mapping(
            "artifact-type: [42]\necosystem: []\n",
            Limits::default().yaml,
        )
        .unwrap(),
    );
    let malformed = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(malformed.exit_code(), 2);
    assert_eq!(malformed.run_errors.len(), 2);
    assert!(malformed.waived.is_empty());

    for malformed in [
        airlock_core::yaml::Yaml::Null,
        airlock_core::yaml::Yaml::Seq(Vec::new()),
    ] {
        policy.reference_data.insert("topics".to_owned(), malformed);
        let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.run_errors.len(), 2);
        assert!(report.waived.is_empty());
    }

    policy.reference_data.insert(
        "topics".to_owned(),
        airlock_core::yaml::parse_mapping("artifact-type: [cli]\n", Limits::default().yaml)
            .unwrap(),
    );
    let partial = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(partial.waived.len(), 1);
    assert_eq!(partial.waived[0].rule, "REPO-META-07");
    assert_eq!(partial.findings[0].rule, "REPO-META-09");
}

#[test]
fn release_record_model_gap_fix_is_agent_reasoning_while_missing_record_is_operator() {
    use airlock_core::findings::{Evidence, FixClass};
    for reason in [
        "release-model-missing",
        "release-model-not-a-file",
        "release-model-unreadable",
        "release-model-schema-not-supported",
    ] {
        let class =
            FixClass::for_observation("REPO-REL-08", Some(&Evidence::new(reason, "fixture")));
        assert_eq!(class.fix_kind.as_deref(), Some("agent"), "{reason}");
        assert_eq!(class.code.as_deref(), Some("regenerate-release-model"));
    }
    let class = FixClass::for_observation(
        "REPO-REL-08",
        Some(&Evidence::new("release-record-missing", "fixture")),
    );
    assert_eq!(class.fix_kind.as_deref(), Some("operator"));
}

#[test]
fn template_identity_routes_locally_and_lists_empty_configuration_as_waived() {
    let repo = committed_repository();
    let mut policy = policy_with_one("REPO-TPL-01", airlock_core::rules::Severity::Blocking);
    let empty = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(empty.exit_code(), 0);
    assert_eq!(empty.waived.len(), 1);
    assert_eq!(empty.effective_policy[0].severity, "none");
    assert_eq!(
        empty.waived[0]
            .suppression
            .as_ref()
            .unwrap()
            .policy_reason
            .as_deref(),
        Some("no templates configured")
    );
    policy.rules[0].params.insert(
        "templates".into(),
        serde_json::json!([{"source":"gh:example-org/catalog#bundle","ref":"main"}]),
    );
    let routed = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert_eq!(routed.exit_code(), 0);
    assert!(routed.findings.is_empty());
    assert_eq!(
        routed.routed[0].routing.as_ref().unwrap().reason,
        "needs-github-api"
    );
}

#[tokio::test]
async fn template_identity_credentialed_working_tree_reads_the_configured_local_record() {
    let repo = committed_repository();
    std::fs::create_dir(repo.path().join("state")).unwrap();
    std::fs::write(repo.path().join("state/applied.json"), "invalid JSON").unwrap();
    let mut policy = policy_with_one("REPO-TPL-01", airlock_core::rules::Severity::Blocking);
    policy.rules[0].params.insert(
        "templates".into(),
        serde_json::json!([{"source":"gh:example-org/catalog#bundle","ref":"main"}]),
    );
    policy.rules[0].params.insert(
        "record-path".into(),
        serde_json::json!("state/applied.json"),
    );
    let grant = airlock_core::auth::VerifiedGrant {
        kind: airlock_core::auth::TokenKind::ClassicPat,
        issuer: None,
        login: None,
        scopes: vec!["read:user".into()],
        installations: Vec::new(),
    };
    let mut audit_options = options();
    audit_options.working_tree = Some(repo.path().to_path_buf());
    let report = audit::run(
        &FakeGitHub::new(),
        "owner",
        "name",
        &policy,
        &audit_options,
        Some(&grant),
    )
    .await
    .unwrap();
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.findings[0].source.as_deref(), Some("working-tree"));
    assert_eq!(
        report.findings[0].evidence.as_ref().unwrap().code,
        "record-unreadable"
    );
    assert_eq!(
        report.findings[0]
            .evidence
            .as_ref()
            .unwrap()
            .path
            .as_deref(),
        Some("state/applied.json")
    );
}

#[test]
fn template_identity_repository_request_cannot_override_the_compiled_rule() {
    let repo = committed_repository();
    std::fs::write(
        repo.path().join(".github/airlock.yml"),
        "version: 1\nsuppress:\n  - rule: REPO-TPL-01\n    reason: Fixture request\n",
    )
    .unwrap();
    git(repo.path(), &["add", ".github/airlock.yml"]);
    git(repo.path(), &["commit", "-q", "-m", "fixture request"]);
    let mut policy = policy_with_one("REPO-TPL-01", airlock_core::rules::Severity::Blocking);
    policy.rules[0].params.insert(
        "templates".into(),
        serde_json::json!([{"source":"gh:example-org/catalog#bundle","ref":"main"}]),
    );
    // Exercise the runtime boundary even if a library caller bypasses policy compilation.
    policy
        .suppressions
        .allow_repo_requests
        .insert("REPO-TPL-01".into());
    let report = audit::run_local(&policy, &options(), repo.path()).unwrap();
    assert!(report.waived.is_empty());
    assert_eq!(report.routed.len(), 1);
    assert!(report
        .policy_observations
        .iter()
        .any(|observation| observation.rule.as_deref() == Some("REPO-TPL-01")));
}
