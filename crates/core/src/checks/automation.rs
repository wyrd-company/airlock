//! Automation: taskfiles, CI, CD, and hooks.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::yaml::Yaml;

use super::{AuditContext, ParsedFile, Verdict, Workflow};

/// The task verbs every repository must define.
const REQUIRED_TASKS: &[&str] = &["test", "lint", "format", "check"];

/// The default tag pattern a versioned-artifact CD workflow triggers on.
const DEFAULT_TAG_PATTERN: &str = "[0-9]*.[0-9]*.[0-9]*";

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

// ---------------------------------------------------------------------------
// Taskfile
// ---------------------------------------------------------------------------

fn taskfile(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
    match context.yaml("taskfile.yml") {
        ParsedFile::Parsed(document) => Ok(document),
        ParsedFile::Undecided(verdict) => Err(verdict),
        ParsedFile::Missing | ParsedFile::NotAFile(_) => Err(Box::new(Verdict::fail_at(
            "file_missing",
            "taskfile.yml",
            "there is no taskfile.yml to read tasks from",
            Remediation::new("add_taskfile", "Add a taskfile.yml at the repository root."),
        ))),
    }
}

fn required_tasks(context: &AuditContext) -> Verdict {
    let taskfile = match taskfile(context) {
        Ok(taskfile) => taskfile,
        Err(verdict) => return *verdict,
    };
    let defined = taskfile.get("tasks").map(Yaml::keys).unwrap_or_default();

    let missing: Vec<&&str> = REQUIRED_TASKS
        .iter()
        .filter(|task| !defined.contains(&**task))
        .collect();

    if missing.is_empty() {
        Verdict::pass_at(
            "required_tasks_defined",
            "taskfile.yml",
            "test, lint, format, and check are all defined",
        )
    } else {
        Verdict::fail_at(
            "required_tasks_missing",
            "taskfile.yml",
            format!(
                "{} not defined",
                missing
                    .iter()
                    .map(|task| format!("`{task}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "define_tasks",
                "Define test, lint, format, and check in taskfile.yml.",
            ),
        )
    }
}

fn per_unit_taskfiles(context: &AuditContext) -> Verdict {
    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so per-unit taskfiles could not be checked",
        );
    };
    if units.len() <= 1 {
        return Verdict::pass(
            "single_release_unit",
            "the repository declares one release unit, so per-unit taskfiles do not apply",
        );
    }

    let missing: Vec<String> = units
        .iter()
        .map(|(_, path)| {
            if path == "." {
                "taskfile.yml".to_owned()
            } else {
                format!("{path}/taskfile.yml")
            }
        })
        .filter(|path| !context.has_file(path))
        .collect();

    if missing.is_empty() {
        Verdict::pass(
            "per_unit_taskfiles_present",
            format!(
                "every one of the {} release units has a taskfile.yml",
                units.len()
            ),
        )
    } else {
        Verdict::fail(
            "per_unit_taskfile_missing",
            format!("{} absent", missing.join(", ")),
            Remediation::new(
                "add_unit_taskfile",
                "Add a taskfile.yml at each release unit's declared path.",
            ),
        )
    }
}

fn includes(context: &AuditContext) -> Result<Vec<(String, Yaml)>, Box<Verdict>> {
    let taskfile = taskfile(context)?;
    Ok(taskfile
        .get("includes")
        .and_then(Yaml::as_map)
        .map(|entries| entries.to_vec())
        .unwrap_or_default())
}

fn includes_set_dir(context: &AuditContext) -> Verdict {
    let includes = match includes(context) {
        Ok(includes) => includes,
        Err(verdict) => return *verdict,
    };
    if includes.is_empty() {
        return Verdict::pass_at(
            "no_includes",
            "taskfile.yml",
            "the taskfile declares no includes",
        );
    }

    let missing: Vec<&String> = includes
        .iter()
        .filter(|(_, include)| include.get("dir").and_then(Yaml::as_str).is_none())
        .map(|(name, _)| name)
        .collect();

    if missing.is_empty() {
        Verdict::pass_at(
            "includes_set_dir",
            "taskfile.yml",
            format!("all {} includes set `dir:`", includes.len()),
        )
    } else {
        Verdict::fail_at(
            "include_without_dir",
            "taskfile.yml",
            format!(
                "{} set no `dir:`",
                missing
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new("set_include_dir", "Set `dir:` on every taskfile include."),
        )
    }
}

fn include_namespaces(context: &AuditContext) -> Verdict {
    let includes = match includes(context) {
        Ok(includes) => includes,
        Err(verdict) => return *verdict,
    };
    if includes.is_empty() {
        return Verdict::pass_at(
            "no_includes",
            "taskfile.yml",
            "the taskfile declares no includes",
        );
    }

    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so include namespaces could not be \
             compared against them",
        );
    };
    let unit_ids: Vec<&String> = units.iter().map(|(id, _)| id).collect();

    let unmatched: Vec<&String> = includes
        .iter()
        .map(|(name, _)| name)
        .filter(|name| !unit_ids.contains(name))
        .collect();

    if unmatched.is_empty() {
        Verdict::pass_at(
            "include_namespaces_match",
            "taskfile.yml",
            "every include namespace names a declared release unit",
        )
    } else {
        Verdict::fail_at(
            "include_namespace_unmatched",
            "taskfile.yml",
            format!(
                "{} names no declared release unit",
                unmatched
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "align_include_namespaces",
                "Name each include after the release unit id it covers.",
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Workflows
// ---------------------------------------------------------------------------

/// Workflows airlock could parse. A workflow that did not parse is reported
/// separately rather than quietly excluded from every scan.
fn readable_workflows<'a>(
    context: &'a AuditContext<'_>,
) -> Result<Vec<&'a Workflow>, Box<Verdict>> {
    if context.workflows_truncated {
        return Err(Box::new(Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget, so the workflows could not be \
             examined as a whole",
        )));
    }
    let unparsed: Vec<&str> = context
        .workflows
        .iter()
        .filter(|workflow| workflow.document.is_none())
        .map(|workflow| workflow.path.as_str())
        .collect();
    if !unparsed.is_empty() {
        return Err(Box::new(Verdict::inconclusive(
            "unparseable_workflow",
            format!("{} could not be parsed", unparsed.join(", ")),
        )));
    }
    Ok(context.workflows.iter().collect())
}

fn ci_on_pull_request(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };
    match workflows
        .iter()
        .find(|workflow| workflow.has_trigger("pull_request"))
    {
        Some(workflow) => Verdict::pass_at(
            "ci_triggers_on_pull_request",
            &workflow.path,
            format!("{} triggers on pull_request", workflow.path),
        ),
        None => Verdict::fail(
            "ci_does_not_trigger_on_pull_request",
            "no workflow triggers on pull_request",
            Remediation::new("trigger_on_pull_request", "Trigger CI on pull_request."),
        ),
    }
}

fn workflow_permissions_empty(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let offenders: Vec<String> = workflows
        .iter()
        .filter_map(|workflow| {
            let document = workflow.document.as_ref()?;
            match document.get("permissions") {
                Some(Yaml::Map(entries)) if entries.is_empty() => None,
                Some(other) => Some(format!(
                    "{} sets permissions to a {}",
                    workflow.path,
                    other.kind()
                )),
                None => Some(format!(
                    "{} declares no workflow-level permissions",
                    workflow.path
                )),
            }
        })
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "workflow_permissions_empty",
            format!("all {} workflows set `permissions: {{}}`", workflows.len()),
        )
    } else {
        Verdict::fail(
            "workflow_permissions_not_empty",
            offenders.join("; "),
            Remediation::new(
                "default_deny_permissions",
                "Set `permissions: {}` at workflow level and elevate per job.",
            ),
        )
    }
}

fn jobs_declare_permissions(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let offenders: Vec<String> = workflows
        .iter()
        .flat_map(|workflow| {
            workflow
                .jobs()
                .into_iter()
                .filter(|(_, job)| job.get("permissions").is_none())
                .map(|(name, _)| format!("{}:{name}", workflow.path))
                .collect::<Vec<_>>()
        })
        .collect();

    if offenders.is_empty() {
        // Whether the declared set is minimal is a judgment about what each
        // job needs, which airlock cannot compute.
        Verdict::manual(
            "jobs_declare_permissions",
            "every job declares a permissions block; whether each is minimal is a judgment call",
        )
    } else {
        Verdict::fail(
            "job_without_permissions",
            format!("{} declare no permissions", offenders.join(", ")),
            Remediation::new(
                "declare_job_permissions",
                "Declare the minimum permissions on every job.",
            ),
        )
    }
}

/// Every `uses:` must name a 40-character commit sha and carry a version
/// comment. Comments do not survive parsing, so this reads the text.
fn actions_pinned(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget",
        );
    }

    let mut offenders = Vec::new();
    for workflow in &context.workflows {
        for (number, line) in workflow.text.lines().enumerate() {
            let Some(reference) = uses_reference(line) else {
                continue;
            };
            if reference.starts_with("./") || reference.starts_with("docker://") {
                continue;
            }
            let Some((action, version)) = reference.rsplit_once('@') else {
                offenders.push(format!(
                    "{}:{} uses `{reference}` with no ref at all",
                    workflow.path,
                    number + 1
                ));
                continue;
            };
            if version.len() != 40 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
                offenders.push(format!(
                    "{}:{} pins `{action}` to `{version}` rather than a commit sha",
                    workflow.path,
                    number + 1
                ));
                continue;
            }
            if !line.contains('#') {
                offenders.push(format!(
                    "{}:{} pins `{action}` to a sha with no version comment",
                    workflow.path,
                    number + 1
                ));
            }
        }
    }

    if offenders.is_empty() {
        Verdict::pass(
            "actions_pinned",
            "every action is pinned to a full commit sha with a version comment",
        )
    } else {
        Verdict::fail(
            "action_not_pinned",
            offenders.join("; "),
            Remediation::new(
                "pin_action",
                "Pin every action to a full commit sha and note the version in a trailing \
                 comment.",
            ),
        )
    }
}

/// The value of a `uses:` key on one line, if the line is one.
fn uses_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim().trim_start_matches("- ").trim();
    let rest = trimmed.strip_prefix("uses:")?;
    let value = rest.split('#').next().unwrap_or("").trim();
    let value = value.trim_matches('"').trim_matches('\'');
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn no_pull_request_target(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let offenders: Vec<&str> = workflows
        .iter()
        .filter(|workflow| workflow.has_trigger("pull_request_target"))
        .map(|workflow| workflow.path.as_str())
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "no_pull_request_target",
            "no workflow uses pull_request_target",
        )
    } else {
        Verdict::fail(
            "pull_request_target_used",
            format!("{} uses pull_request_target", offenders.join(", ")),
            Remediation::new(
                "remove_pull_request_target",
                "Replace pull_request_target with pull_request. It runs fork code with secrets.",
            ),
        )
    }
}

fn concurrency_covers_pull_requests(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let pull_request_workflows: Vec<&&Workflow> = workflows
        .iter()
        .filter(|workflow| workflow.has_trigger("pull_request"))
        .collect();

    if pull_request_workflows.is_empty() {
        return Verdict::fail(
            "no_pull_request_workflow",
            "no workflow triggers on pull_request, so no concurrency group covers pull requests",
            Remediation::new("trigger_on_pull_request", "Trigger CI on pull_request."),
        );
    }

    let offenders: Vec<String> = pull_request_workflows
        .iter()
        .filter_map(|workflow| {
            let document = workflow.document.as_ref()?;
            let concurrency = document.get("concurrency")?;
            if concurrency.get("group").is_none() {
                return Some(format!("{} sets no concurrency group", workflow.path));
            }
            if concurrency.get("cancel-in-progress").is_none() {
                return Some(format!(
                    "{} sets no cancel-in-progress on its concurrency group",
                    workflow.path
                ));
            }
            None
        })
        .chain(pull_request_workflows.iter().filter_map(|workflow| {
            workflow
                .document
                .as_ref()
                .filter(|document| document.get("concurrency").is_none())
                .map(|_| format!("{} declares no concurrency", workflow.path))
        }))
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "concurrency_covers_pull_requests",
            "every pull-request workflow declares a concurrency group with cancel-in-progress",
        )
    } else {
        Verdict::fail(
            "concurrency_missing",
            offenders.join("; "),
            Remediation::new(
                "add_concurrency",
                "Add a concurrency group with cancel-in-progress covering pull requests.",
            ),
        )
    }
}

fn jobs_invoke_tasks(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let mut offenders = Vec::new();
    for workflow in workflows {
        for (job_name, job) in workflow.jobs() {
            let Some(steps) = job.get("steps").and_then(Yaml::as_seq) else {
                continue;
            };
            for step in steps {
                let Some(command) = step.get("run").and_then(Yaml::as_str) else {
                    continue;
                };
                let first = command
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty() && !line.starts_with('#'))
                    .unwrap_or_default();
                if !first
                    .split_whitespace()
                    .next()
                    .is_some_and(|word| word == "task")
                {
                    offenders.push(format!(
                        "{}:{job_name} runs `{}`",
                        workflow.path,
                        first.chars().take(40).collect::<String>()
                    ));
                }
            }
        }
    }

    if offenders.is_empty() {
        Verdict::pass(
            "jobs_invoke_tasks",
            "every job step invokes a task rather than a raw command",
        )
    } else {
        Verdict::fail(
            "job_runs_raw_command",
            offenders.join("; "),
            Remediation::new(
                "wrap_in_task",
                "Move the command into taskfile.yml and invoke the task, so local and CI cannot \
                 drift apart.",
            ),
        )
    }
}

fn pull_request_title_check(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let validating = workflows
        .iter()
        .find(|workflow| workflow.text.contains("pull_request.title"));

    let Some(workflow) = validating else {
        return Verdict::fail(
            "no_title_check",
            "no workflow reads the pull request title to validate its format",
            Remediation::new(
                "add_title_check",
                "Add a job that validates the pull request title format, and require it in the \
                 ruleset.",
            ),
        );
    };

    // The other half of the rule lives in the ruleset, and required status
    // check names are not exposed by the endpoints airlock reads.
    Verdict::manual(
        "title_check_present",
        format!(
            "{} validates the pull request title; whether the ruleset requires that check is a \
             judgment call from the ruleset configuration",
            workflow.path
        ),
    )
}

fn reconcile_token_is_scoped(context: &AuditContext) -> Verdict {
    let Some(workflow) = context.workflow("reconcile-settings.yml") else {
        return Verdict::fail(
            "no_reconcile_workflow",
            "there is no .github/workflows/reconcile-settings.yml to inspect",
            Remediation::new(
                "add_reconcile_workflow",
                "Add the reconcile workflow that applies .github/repo-settings.yml.",
            ),
        );
    };

    let Some(document) = &workflow.document else {
        return Verdict::inconclusive(
            "unparseable_workflow",
            format!("{} could not be parsed", workflow.path),
        );
    };

    let minting_steps: Vec<&Yaml> = document
        .get("jobs")
        .and_then(Yaml::as_map)
        .map(|jobs| {
            jobs.iter()
                .filter_map(|(_, job)| job.get("steps").and_then(Yaml::as_seq))
                .flatten()
                .filter(|step| {
                    step.get("uses")
                        .and_then(Yaml::as_str)
                        .is_some_and(|uses| uses.contains("create-github-app-token"))
                })
                .collect()
        })
        .unwrap_or_default();

    if minting_steps.is_empty() {
        return Verdict::fail(
            "no_token_minting_step",
            format!("{} mints no scoped app token", workflow.path),
            Remediation::new(
                "mint_scoped_token",
                "Mint the token with `repositories:` naming this repository only.",
            ),
        );
    }

    let unscoped: Vec<usize> = minting_steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.get("with")
                .and_then(|with| with.get("repositories"))
                .is_none()
        })
        .map(|(index, _)| index + 1)
        .collect();

    if unscoped.is_empty() {
        Verdict::pass_at(
            "reconcile_token_scoped",
            &workflow.path,
            "the token-minting step names the repositories the token may reach",
        )
    } else {
        Verdict::fail_at(
            "reconcile_token_unscoped",
            &workflow.path,
            format!(
                "token-minting step {} sets no `repositories:`",
                unscoped
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "scope_token",
                "Set `repositories:` on the token-minting step so the token reaches one \
                 repository.",
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

fn cd<'a>(context: &'a AuditContext<'_>) -> Option<&'a Workflow> {
    context.workflow("cd.yml")
}

/// The shared shape of the delivery rules: without a `cd.yml`, whether the
/// repository delivers anything is a judgment call, not a failure.
fn no_cd_workflow(subject: &str) -> Verdict {
    Verdict::manual(
        "no_cd_workflow",
        format!(
            "there is no .github/workflows/cd.yml, so {subject} could not be checked; whether \
             this repository delivers anything is a judgment call"
        ),
    )
}

fn cd_present(context: &AuditContext) -> Verdict {
    match cd(context) {
        Some(workflow) => Verdict::pass_at(
            "cd_workflow_present",
            &workflow.path,
            ".github/workflows/cd.yml is present",
        ),
        None => no_cd_workflow("delivery"),
    }
}

fn cd_on_tags(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the tag trigger");
    };
    let expected = rule.param_str("tag-pattern").unwrap_or(DEFAULT_TAG_PATTERN);

    let tags: Vec<String> = workflow
        .trigger("push")
        .and_then(|push| push.get("tags"))
        .and_then(Yaml::as_seq)
        .map(|patterns| {
            patterns
                .iter()
                .filter_map(|pattern| pattern.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if tags.is_empty() {
        return Verdict::manual(
            "cd_has_no_tag_trigger",
            "cd.yml does not trigger on tags; whether this repository publishes a versioned \
             artifact is a judgment call",
        );
    }
    if tags.iter().any(|pattern| pattern == expected) {
        Verdict::pass_at(
            "cd_tag_pattern_matches",
            &workflow.path,
            format!("cd.yml triggers on tags matching `{expected}`"),
        )
    } else {
        Verdict::fail_at(
            "cd_tag_pattern_wrong",
            &workflow.path,
            format!(
                "cd.yml triggers on tags {} rather than `{expected}`",
                tags.join(", ")
            ),
            Remediation::new(
                "correct_tag_pattern",
                format!("Trigger CD on tags matching `{expected}`."),
            ),
        )
    }
}

fn cd_on_default_branch(context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the default-branch trigger");
    };
    let branch = &context.snapshot.repository.default_branch;
    if workflow.pushes_to(branch) {
        Verdict::pass_at(
            "cd_triggers_on_default_branch",
            &workflow.path,
            format!("cd.yml triggers on push to `{branch}`"),
        )
    } else {
        Verdict::manual(
            "cd_has_no_branch_trigger",
            format!(
                "cd.yml does not trigger on push to `{branch}`; whether this repository deploys a \
                 site or service is a judgment call"
            ),
        )
    }
}

fn cd_concurrency(context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the concurrency group");
    };
    let Some(document) = &workflow.document else {
        return Verdict::inconclusive(
            "unparseable_workflow",
            format!("{} could not be parsed", workflow.path),
        );
    };

    match document
        .get("concurrency")
        .and_then(|concurrency| concurrency.get("cancel-in-progress"))
        .and_then(Yaml::as_bool)
    {
        Some(false) => Verdict::pass_at(
            "cd_concurrency_does_not_cancel",
            &workflow.path,
            "cd.yml sets concurrency with cancel-in-progress: false",
        ),
        Some(true) => Verdict::fail_at(
            "cd_concurrency_cancels",
            &workflow.path,
            "cd.yml sets cancel-in-progress: true, so a delivery can be killed mid-flight",
            Remediation::new(
                "do_not_cancel_delivery",
                "Set cancel-in-progress: false on the CD concurrency group.",
            ),
        ),
        None => Verdict::fail_at(
            "cd_concurrency_missing",
            &workflow.path,
            "cd.yml declares no concurrency group with cancel-in-progress",
            Remediation::new(
                "add_cd_concurrency",
                "Add a concurrency group with cancel-in-progress: false.",
            ),
        ),
    }
}

/// Publication commands that mean a workflow creates a release rather than
/// delivering one.
const RELEASE_CREATION_SIGNALS: &[&str] = &[
    "gh release create",
    "softprops/action-gh-release",
    "actions/create-release",
    "ncipollo/release-action",
];

fn release_and_delivery_separate(context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the separation of release creation from delivery");
    };

    let found: Vec<&&str> = RELEASE_CREATION_SIGNALS
        .iter()
        .filter(|signal| workflow.text.contains(**signal))
        .collect();

    if found.is_empty() {
        Verdict::pass_at(
            "delivery_does_not_create_releases",
            &workflow.path,
            "cd.yml delivers without creating releases",
        )
    } else {
        Verdict::fail_at(
            "delivery_creates_releases",
            &workflow.path,
            format!(
                "cd.yml creates releases: {}",
                found
                    .iter()
                    .map(|signal| (**signal).to_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "split_release_from_delivery",
                "Create the release in its own workflow and let CD deliver an existing tag.",
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

fn lefthook(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
    match context.yaml(".config/lefthook.yml") {
        ParsedFile::Parsed(document) => Ok(document),
        ParsedFile::Undecided(verdict) => Err(verdict),
        ParsedFile::Missing | ParsedFile::NotAFile(_) => Err(Box::new(Verdict::fail_at(
            "file_missing",
            ".config/lefthook.yml",
            "there is no .config/lefthook.yml to read hooks from",
            Remediation::new("add_lefthook", "Add .config/lefthook.yml."),
        ))),
    }
}

/// The commands one hook runs, across all its jobs.
fn hook_commands(lefthook: &Yaml, hook: &str) -> Option<Vec<String>> {
    let jobs = lefthook.get(hook)?.get("jobs")?.as_seq()?;
    Some(
        jobs.iter()
            .filter_map(|job| job.get("run").and_then(Yaml::as_str))
            .map(ToOwned::to_owned)
            .collect(),
    )
}

fn pre_commit_hook(context: &AuditContext) -> Verdict {
    let lefthook = match lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = hook_commands(&lefthook, "pre-commit") else {
        return Verdict::fail_at(
            "no_pre_commit_hook",
            ".config/lefthook.yml",
            "no pre-commit hook is defined",
            Remediation::new(
                "add_pre_commit",
                "Add a pre-commit hook running format and lint on staged files.",
            ),
        );
    };

    let missing: Vec<&str> = ["format", "lint"]
        .into_iter()
        .filter(|verb| !commands.iter().any(|command| command.contains(verb)))
        .collect();

    if missing.is_empty() {
        Verdict::manual(
            "pre_commit_runs_format_and_lint",
            "pre-commit runs format and lint; whether it is limited to staged files is a \
             judgment call about the hook runner's configuration",
        )
    } else {
        Verdict::fail_at(
            "pre_commit_incomplete",
            ".config/lefthook.yml",
            format!("pre-commit runs no {}", missing.join(" or ")),
            Remediation::new(
                "complete_pre_commit",
                "Run format and lint from the pre-commit hook.",
            ),
        )
    }
}

fn commit_msg_hook(context: &AuditContext) -> Verdict {
    let lefthook = match lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = hook_commands(&lefthook, "commit-msg") else {
        return Verdict::fail_at(
            "no_commit_msg_hook",
            ".config/lefthook.yml",
            "no commit-msg hook is defined",
            Remediation::new(
                "add_commit_msg",
                "Add a commit-msg hook validating conventional commit format.",
            ),
        );
    };

    if commands.iter().any(|command| command.contains("commit")) {
        Verdict::pass_at(
            "commit_msg_validates",
            ".config/lefthook.yml",
            "commit-msg invokes a commit-message validation task",
        )
    } else {
        Verdict::manual(
            "commit_msg_purpose_unclear",
            format!(
                "commit-msg runs {}; whether that validates conventional commit format is a \
                 judgment call",
                commands.join(", ")
            ),
        )
    }
}

fn pre_push_hook(context: &AuditContext) -> Verdict {
    let lefthook = match lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = hook_commands(&lefthook, "pre-push") else {
        return Verdict::pass_at(
            "no_pre_push_hook",
            ".config/lefthook.yml",
            "pre-push runs nothing",
        );
    };

    let heavy: Vec<&String> = commands
        .iter()
        .filter(|command| !command.contains("lint"))
        .collect();

    if heavy.is_empty() {
        Verdict::pass_at(
            "pre_push_runs_lint_only",
            ".config/lefthook.yml",
            "pre-push runs lint only",
        )
    } else {
        Verdict::fail_at(
            "pre_push_runs_more_than_lint",
            ".config/lefthook.yml",
            format!(
                "pre-push runs {}",
                heavy
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "lighten_pre_push",
                "Run nothing or lint only from pre-push. A slow pre-push teaches contributors to \
                 pass --no-verify, which disables pre-commit too.",
            ),
        )
    }
}

fn hooks_invoke_tasks(context: &AuditContext) -> Verdict {
    let lefthook = match lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };

    let mut offenders = Vec::new();
    for hook in [
        "pre-commit",
        "commit-msg",
        "pre-push",
        "post-checkout",
        "post-merge",
    ] {
        let Some(commands) = hook_commands(&lefthook, hook) else {
            continue;
        };
        for command in commands {
            let first = command.split_whitespace().next().unwrap_or_default();
            if first != "task" {
                offenders.push(format!("{hook} runs `{command}`"));
            }
        }
    }

    if offenders.is_empty() {
        Verdict::pass_at(
            "hooks_invoke_tasks",
            ".config/lefthook.yml",
            "every hook invokes a task",
        )
    } else {
        Verdict::fail_at(
            "hook_runs_raw_command",
            ".config/lefthook.yml",
            offenders.join("; "),
            Remediation::new(
                "wrap_hook_in_task",
                "Invoke tasks from hooks rather than raw commands.",
            ),
        )
    }
}

/// Whether a verdict decided anything, for the tests below.
#[cfg(test)]
fn decided(verdict: &Verdict) -> bool {
    matches!(
        verdict.status,
        crate::findings::Status::Pass | crate::findings::Status::Fail
    )
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
}
