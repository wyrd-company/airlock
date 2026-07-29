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
    GitHub, Installation, Paged, Repository, Ruleset, TagRef, Tree, TreeEntry,
};
use airlock_core::limits::Limits;
use airlock_core::policy::{Condition, ResolvedPolicy, RuleInstance};
use airlock_core::registry::{self, Evaluation, Observation};

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
            allow_merge_commit: false,
            allow_squash_merge: true,
            allow_rebase_merge: true,
            delete_branch_on_merge: true,
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
        gate: airlock_core::findings::Gate::Blocking,
        rules: registry::CHECKS
            .iter()
            .map(|def| RuleInstance {
                def,
                severity: def.severity,
                params: BTreeMap::new(),
                provenance: "parity".to_owned(),
                condition: Condition::Always,
            })
            .collect(),
        suppressions: Default::default(),
        reference_data: BTreeMap::new(),
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
            let def = registry::find(&finding.rule).expect("a registered rule");
            def.observation() == Observation::FileTree && def.evaluation == Evaluation::Mechanical
        })
        .map(|finding| {
            (
                finding.rule.clone(),
                (
                    finding.status.code().to_owned(),
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
        let def = registry::find(&finding.rule).expect("registered");
        match def.evaluation {
            Evaluation::Mechanical => {
                assert_eq!(finding.source.as_deref(), Some("api"), "{}", finding.rule);
            }
            _ => assert_eq!(finding.source, None, "{}", finding.rule),
        }
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
        let def = registry::find(&finding.rule).expect("registered");
        match (def.evaluation, def.observation()) {
            (Evaluation::Mechanical, Observation::FileTree) => {
                assert_eq!(
                    finding.source.as_deref(),
                    Some("working-tree"),
                    "{}",
                    finding.rule
                );
            }
            _ => assert_eq!(finding.source, None, "{}", finding.rule),
        }
    }
}

#[tokio::test]
async fn an_unobserved_platform_rule_is_inconclusive_and_never_passes() {
    let repo = committed_repository();
    let policy = full_policy();
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");

    let mut gated = 0;
    for finding in &report.findings {
        let def = registry::find(&finding.rule).expect("registered");
        if def.observation() == Observation::Platform && def.evaluation == Evaluation::Mechanical {
            gated += 1;
            assert_eq!(finding.status, Status::Inconclusive, "{}", finding.rule);
            assert_eq!(
                finding.evidence.as_ref().expect("evidence").code,
                "not_observed",
                "{}",
                finding.rule
            );
        }
    }
    assert!(gated > 0, "the fixture policy enables platform rules");
    assert_eq!(report.observation.platform_source, None);
    // An audit that could not observe its platform half is incomplete.
    assert!(!report.complete);
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
        Status::Fail,
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
    assert_eq!(finding.status, Status::Pass);
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
        Status::Fail,
        "authorization comes from committed content, not the tree as it stands"
    );

    // Committed, the same request is honoured.
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "request suppression"]);
    let report = audit::run_local(&policy, &options(), repo.path()).expect("the local audit runs");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule == "REPO-FILE-14")
        .expect("REPO-FILE-14 is enabled");
    assert_eq!(finding.status, Status::Suppressed);
}
