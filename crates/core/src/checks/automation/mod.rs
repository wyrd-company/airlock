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
