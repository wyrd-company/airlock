//! Automation: taskfiles, CI, CD, and hooks.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::yaml::Yaml;

use super::{AuditContext, ParsedFile, Verdict, Workflow};

mod delivery;
mod hooks;
mod taskfile;
mod workflows;

use delivery::*;
use hooks::*;
use taskfile::*;
use workflows::*;

/// The task verbs every repository must define.
pub(super) const REQUIRED_TASKS: &[&str] = &["test", "lint", "format", "check"];

/// The default tag pattern a versioned-artifact CD workflow triggers on.
pub(super) const DEFAULT_TAG_PATTERN: &str = "[0-9]*.[0-9]*.[0-9]*";

pub(crate) fn run(id: &str, rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-TASK-01" => required_tasks(context),
        "REPO-TASK-04" => per_unit_taskfiles(context),
        "REPO-TASK-05" => includes_set_dir(context),
        "REPO-TASK-06" => include_namespaces(context),
        "REPO-CI-01" => ci_on_pull_request(context),
        "REPO-CI-02" => workflow_permissions_empty(context),
        "REPO-CI-03" => jobs_declare_permissions(context),
        "REPO-CI-04" => actions_pinned(context),
        "REPO-CI-05" => no_pull_request_target(context),
        "REPO-CI-06" => concurrency_covers_pull_requests(context),
        "REPO-CI-07" => jobs_invoke_tasks(context),
        "REPO-CI-08" => pull_request_title_check(context),
        "REPO-CI-09" => reconcile_token_is_scoped(context),
        "REPO-CD-01" => cd_present(context),
        "REPO-CD-02" => cd_on_tags(rule, context),
        "REPO-CD-03" => cd_on_default_branch(context),
        "REPO-CD-04" => cd_concurrency(context),
        "REPO-CD-07" => release_and_delivery_separate(context),
        "REPO-HOOK-01" => pre_commit_hook(context),
        "REPO-HOOK-02" => commit_msg_hook(context),
        "REPO-HOOK-03" => pre_push_hook(context),
        "REPO-HOOK-04" => hooks_invoke_tasks(context),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use super::decided;
    use crate::findings::Status;
    use serde_json::json;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        evaluate(&rule(id), &context).status
    }

    const TASKFILE: &str = "\
version: '3'
tasks:
  test:
    cmds: [cargo test]
  lint:
    cmds: [cargo clippy]
  format:
    cmds: [cargo fmt]
  check:
    cmds: [cargo test]
";

    const CI: &str = "\
on:
  pull_request:
permissions: {}
concurrency:
  group: ci
  cancel-in-progress: true
jobs:
  test:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - run: task test
";

    #[test]
    fn required_task_verbs_must_all_exist() {
        assert_eq!(
            verdict("REPO-TASK-01", &[("taskfile.yml", TASKFILE)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-TASK-01",
                &[(
                    "taskfile.yml",
                    "version: '3'\ntasks:\n  test:\n    cmds: []\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_missing_taskfile_fails_rather_than_passing_vacuously() {
        assert_eq!(verdict("REPO-TASK-01", &[]), Status::Fail);
    }

    #[test]
    fn includes_must_set_dir() {
        let with_dir = "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n    dir: ./core\n";
        let without = "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n";
        assert_eq!(
            verdict("REPO-TASK-05", &[("taskfile.yml", with_dir)]),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-TASK-05", &[("taskfile.yml", without)]),
            Status::Fail
        );
    }

    #[test]
    fn include_namespaces_must_name_release_units() {
        let files = [
            (
                "taskfile.yml",
                "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n    dir: ./core\n",
            ),
            (
                ".intentional/config.yml",
                "release-units:\n  core:\n    path: core\n  cli:\n    path: cli\n",
            ),
        ];
        assert_eq!(verdict("REPO-TASK-06", &files), Status::Pass);

        let mismatched = [
            (
                "taskfile.yml",
                "version: '3'\nincludes:\n  other:\n    taskfile: ./x\n    dir: ./x\n",
            ),
            files[1],
        ];
        assert_eq!(verdict("REPO-TASK-06", &mismatched), Status::Fail);
    }

    #[test]
    fn ci_must_trigger_on_pull_request() {
        assert_eq!(
            verdict("REPO-CI-01", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-CI-01",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  push:\npermissions: {}\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn workflow_permissions_must_be_an_empty_map() {
        assert_eq!(
            verdict("REPO-CI-02", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-CI-02",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  pull_request:\npermissions:\n  contents: read\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict(
                "REPO-CI-02",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  pull_request:\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_job_without_permissions_fails() {
        assert_eq!(
            verdict(
                "REPO-CI-03",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  pull_request:\npermissions: {}\njobs:\n  a:\n    steps: []\n"
                )]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-CI-03", &[(".github/workflows/ci.yml", CI)]),
            Status::Manual
        );
    }

    #[test]
    fn actions_must_be_pinned_to_a_sha_with_a_comment() {
        assert_eq!(
            verdict("REPO-CI-04", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
        for unpinned in [
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout\n",
        ] {
            assert_eq!(
                verdict("REPO-CI-04", &[(".github/workflows/x.yml", unpinned)]),
                Status::Fail,
                "{unpinned}"
            );
        }
    }

    #[test]
    fn a_local_action_needs_no_sha() {
        assert_eq!(
            verdict(
                "REPO-CI-04",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/thing\n"
                )]
            ),
            Status::Pass
        );
    }

    #[test]
    fn pull_request_target_fails() {
        assert_eq!(
            verdict(
                "REPO-CI-05",
                &[(
                    ".github/workflows/x.yml",
                    "on:\n  pull_request_target:\npermissions: {}\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-CI-05", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
    }

    #[test]
    fn pull_request_workflows_need_a_cancelling_concurrency_group() {
        assert_eq!(
            verdict("REPO-CI-06", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-CI-06",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  pull_request:\npermissions: {}\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_raw_command_in_a_job_fails() {
        assert_eq!(
            verdict("REPO-CI-07", &[(".github/workflows/ci.yml", CI)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-CI-07",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - run: cargo test\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_multi_line_run_block_is_judged_by_its_first_command() {
        assert_eq!(
            verdict(
                "REPO-CI-07",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - run: |\n          set -e\n          task test\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_title_check_defers_the_ruleset_half_of_the_rule() {
        assert_eq!(
            verdict(
                "REPO-CI-08",
                &[(
                    ".github/workflows/pr.yml",
                    "on:\n  pull_request:\npermissions: {}\njobs:\n  t:\n    steps:\n      \
                     - env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n        \
                     run: task lint:commit-msg\n"
                )]
            ),
            Status::Manual
        );
        assert_eq!(
            verdict("REPO-CI-08", &[(".github/workflows/ci.yml", CI)]),
            Status::Fail
        );
    }

    #[test]
    fn the_reconcile_token_must_be_scoped() {
        let scoped = "\
on:
  push:
    branches: [main]
permissions: {}
jobs:
  reconcile:
    permissions:
      contents: read
    steps:
      - uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3
        with:
          repositories: name
";
        assert_eq!(
            verdict(
                "REPO-CI-09",
                &[(".github/workflows/reconcile-settings.yml", scoped)]
            ),
            Status::Pass
        );
        let unscoped = scoped.replace("          repositories: name\n", "");
        assert_eq!(
            verdict(
                "REPO-CI-09",
                &[(".github/workflows/reconcile-settings.yml", &unscoped)]
            ),
            Status::Fail
        );
    }

    #[test]
    fn delivery_rules_defer_when_there_is_no_cd_workflow() {
        for id in [
            "REPO-CD-01",
            "REPO-CD-02",
            "REPO-CD-03",
            "REPO-CD-04",
            "REPO-CD-07",
        ] {
            assert_eq!(verdict(id, &[]), Status::Manual, "{id}");
        }
    }

    #[test]
    fn cd_tag_triggers_are_compared_against_the_policy_pattern() {
        let cd = "on:\n  push:\n    tags: ['[0-9]*.[0-9]*.[0-9]*']\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict("REPO-CD-02", &[(".github/workflows/cd.yml", cd)]),
            Status::Pass
        );

        let snapshot = snapshot(&[(".github/workflows/cd.yml", cd)]);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        let custom = rule_with("REPO-CD-02", &[("tag-pattern", json!("release-*"))]);
        assert_eq!(evaluate(&custom, &context).status, Status::Fail);
    }

    #[test]
    fn cd_must_not_cancel_a_delivery_in_flight() {
        let cd = "on:\n  push:\n    tags: ['*']\nconcurrency:\n  group: cd\n  \
                  cancel-in-progress: false\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict("REPO-CD-04", &[(".github/workflows/cd.yml", cd)]),
            Status::Pass
        );
        let cancelling = cd.replace("cancel-in-progress: false", "cancel-in-progress: true");
        assert_eq!(
            verdict("REPO-CD-04", &[(".github/workflows/cd.yml", &cancelling)]),
            Status::Fail
        );
    }

    #[test]
    fn a_delivery_workflow_that_creates_releases_fails() {
        let cd = "on:\n  push:\n    tags: ['*']\npermissions: {}\njobs:\n  a:\n    steps:\n      \
                  - run: gh release create 1.0.0\n";
        assert_eq!(
            verdict("REPO-CD-07", &[(".github/workflows/cd.yml", cd)]),
            Status::Fail
        );
    }

    const LEFTHOOK: &str = "\
pre-commit:
  jobs:
    - name: format
      run: task format
    - name: lint
      run: task lint
commit-msg:
  jobs:
    - name: conventional
      run: task lint:commit-msg -- {1}
";

    #[test]
    fn hook_rules_read_the_lefthook_file() {
        assert_eq!(
            verdict("REPO-HOOK-01", &[(".config/lefthook.yml", LEFTHOOK)]),
            Status::Manual
        );
        assert_eq!(
            verdict("REPO-HOOK-02", &[(".config/lefthook.yml", LEFTHOOK)]),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-HOOK-03", &[(".config/lefthook.yml", LEFTHOOK)]),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-HOOK-04", &[(".config/lefthook.yml", LEFTHOOK)]),
            Status::Pass
        );
    }

    #[test]
    fn a_pre_commit_missing_lint_fails() {
        assert_eq!(
            verdict(
                "REPO-HOOK-01",
                &[(
                    ".config/lefthook.yml",
                    "pre-commit:\n  jobs:\n    - name: format\n      run: task format\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_heavy_pre_push_fails() {
        assert_eq!(
            verdict(
                "REPO-HOOK-03",
                &[(
                    ".config/lefthook.yml",
                    "pre-push:\n  jobs:\n    - name: test\n      run: task test\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_raw_command_in_a_hook_fails() {
        assert_eq!(
            verdict(
                "REPO-HOOK-04",
                &[(
                    ".config/lefthook.yml",
                    "pre-commit:\n  jobs:\n    - name: fmt\n      run: cargo fmt\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn an_unparseable_workflow_makes_workflow_rules_inconclusive_not_passing() {
        let snapshot = snapshot(&[(".github/workflows/x.yml", "a: 1\na: 2\n")]);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        let verdict = evaluate(&rule("REPO-CI-02"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert!(!decided(&verdict));
    }

    #[test]
    fn an_action_pin_needs_a_comment_that_names_a_version() {
        let sha = "11d5960a326750d5838078e36cf38b85af677262";
        let cases: &[(&str, Status)] = &[
            ("# v4", Status::Pass),
            ("# 1.2.3", Status::Pass),
            ("#v4", Status::Pass),
            // A bare hash is not a version comment.
            ("#", Status::Fail),
            ("#   ", Status::Fail),
            // Nor is a comment that names no version.
            ("# see the wiki", Status::Fail),
        ];
        for (comment, expected) in cases {
            let workflow = format!(
                "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha} {comment}\n"
            );
            assert_eq!(
                verdict("REPO-CI-04", &[(".github/workflows/x.yml", &workflow)]),
                *expected,
                "comment `{comment}`"
            );
        }
    }

    #[test]
    fn a_hash_inside_a_quoted_uses_value_is_not_a_version_comment() {
        let sha = "11d5960a326750d5838078e36cf38b85af677262";
        let workflow =
            format!("jobs:\n  a:\n    steps:\n      - uses: \"actions/checkout@{sha}#v4\"\n");
        // The `#` is inside the scalar, so the ref is `{sha}#v4` — neither a
        // bare sha nor a commented pin.
        assert_eq!(
            verdict("REPO-CI-04", &[(".github/workflows/x.yml", &workflow)]),
            Status::Fail
        );
    }

    #[test]
    fn a_quoted_uses_value_with_a_real_trailing_comment_passes() {
        let sha = "11d5960a326750d5838078e36cf38b85af677262";
        let workflow =
            format!("jobs:\n  a:\n    steps:\n      - uses: \"actions/checkout@{sha}\" # v4\n");
        assert_eq!(
            verdict("REPO-CI-04", &[(".github/workflows/x.yml", &workflow)]),
            Status::Pass
        );
    }

    #[test]
    fn the_uses_splitter_keeps_a_scalar_hash_out_of_the_comment() {
        let step = super::uses_step("      - uses: owner/action@abc#fragment").unwrap();
        assert_eq!(step.reference, "owner/action@abc#fragment");
        assert_eq!(step.comment, None);

        let commented = super::uses_step("      - uses: owner/action@abc # v4").unwrap();
        assert_eq!(commented.reference, "owner/action@abc");
        assert_eq!(commented.comment, Some(" v4"));

        let empty = super::uses_step("      - uses: owner/action@abc #").unwrap();
        assert_eq!(empty.comment, Some(""));
    }

    #[test]
    fn a_hook_job_without_a_readable_command_is_malformed_not_absent() {
        // A job declared with `script:` instead of `run:` used to vanish, so
        // "every hook invokes a task" passed over a command nobody read.
        let lefthook = "pre-commit:\n  jobs:\n    - name: format\n      script: format.sh\n";
        assert_eq!(
            verdict("REPO-HOOK-04", &[(".config/lefthook.yml", lefthook)]),
            Status::Inconclusive
        );
        assert_eq!(
            verdict("REPO-HOOK-01", &[(".config/lefthook.yml", lefthook)]),
            Status::Inconclusive
        );
    }

    #[test]
    fn a_malformed_cd_tag_list_is_not_read_as_no_tag_trigger() {
        let cd = "on:\n  push:\n    tags: ['1.0.0', 7]\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict("REPO-CD-02", &[(".github/workflows/cd.yml", cd)]),
            Status::Inconclusive
        );
    }

    #[test]
    fn a_malformed_trigger_list_makes_workflow_rules_inconclusive() {
        let workflow = "on: [pull_request, 3]\npermissions: {}\njobs: {}\n";
        for id in ["REPO-CI-01", "REPO-CI-05"] {
            assert_eq!(
                verdict(id, &[(".github/workflows/x.yml", workflow)]),
                Status::Inconclusive,
                "{id}"
            );
        }
    }
}
