use super::*;

pub(super) fn readable_workflows<'a>(
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

pub(super) fn ci_on_pull_request(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };
    let triggered = match super::super::workflows_with_trigger(&workflows, "pull_request") {
        Ok(triggered) => triggered,
        Err(verdict) => return *verdict,
    };
    match triggered.first() {
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

pub(super) fn workflow_permissions_empty(context: &AuditContext) -> Verdict {
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

pub(super) fn jobs_declare_permissions(context: &AuditContext) -> Verdict {
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

/// Every `uses:` must name a 40-character commit sha and carry a non-empty
/// version comment. Comments do not survive parsing, so this reads the text.
pub(super) fn actions_pinned(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget",
        );
    }

    let mut offenders = Vec::new();
    for workflow in &context.workflows {
        for (number, line) in workflow.text.lines().enumerate() {
            let Some(step) = uses_step(line) else {
                continue;
            };
            let location = format!("{}:{}", workflow.path, number + 1);
            if step.reference.starts_with("./") || step.reference.starts_with("docker://") {
                continue;
            }
            let Some((action, version)) = step.reference.rsplit_once('@') else {
                offenders.push(format!(
                    "{location} uses `{}` with no ref at all",
                    step.reference
                ));
                continue;
            };
            if version.len() != 40 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
                offenders.push(format!(
                    "{location} pins `{action}` to `{version}` rather than a commit sha"
                ));
                continue;
            }
            match step.comment {
                // A bare `#`, or a comment of only whitespace, is not a
                // version comment. Neither is a `#` inside the quoted scalar,
                // which `uses_step` never treats as a comment at all.
                None => offenders.push(format!(
                    "{location} pins `{action}` to a sha with no version comment"
                )),
                Some(comment) if comment.trim().is_empty() => offenders.push(format!(
                    "{location} pins `{action}` to a sha with an empty version comment"
                )),
                Some(comment) if !comment.chars().any(|c| c.is_ascii_digit()) => {
                    offenders.push(format!(
                        "{location} pins `{action}` with the comment `{}`, which names no \
                         version",
                        comment.trim()
                    ));
                }
                Some(_) => {}
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
                "Pin every action to a full commit sha and name the version it came from in a \
                 trailing comment, for example `# v4`.",
            ),
        )
    }
}

/// One `uses:` line, split into its reference and its trailing comment.
pub(super) struct UsesStep<'a> {
    pub(super) reference: &'a str,
    /// The text after the `#`, when the line carries a real YAML comment.
    pub(super) comment: Option<&'a str>,
}

/// Split a `uses:` line into its value and its trailing comment.
///
/// YAML starts a comment at a `#` that follows whitespace, so a `#` inside a
/// scalar is part of the value. A quoted scalar is read to its closing quote
/// first, which is what stops `uses: "action@sha#not-a-comment"` from
/// counting as a version comment.
pub(super) fn uses_step(line: &str) -> Option<UsesStep<'_>> {
    let trimmed = line.trim().trim_start_matches("- ").trim();
    let rest = trimmed.strip_prefix("uses:")?.trim_start();

    let (value, remainder) = match rest.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let body = &rest[quote.len_utf8()..];
            let close = body.find(quote)?;
            (&body[..close], &body[close + quote.len_utf8()..])
        }
        _ => match find_comment_start(rest) {
            Some(position) => (rest[..position].trim_end(), &rest[position..]),
            None => (rest.trim_end(), ""),
        },
    };

    if value.is_empty() {
        return None;
    }

    let comment = remainder
        .find('#')
        .map(|position| &remainder[position + 1..]);

    Some(UsesStep {
        reference: value,
        comment,
    })
}

/// The index of the `#` that starts a YAML comment, if the scalar has one.
pub(super) fn find_comment_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    value.char_indices().find_map(|(index, character)| {
        if character != '#' {
            return None;
        }
        // A `#` only opens a comment when it follows whitespace or opens the
        // scalar; `sha#fragment` is one token.
        match index.checked_sub(1).map(|previous| bytes[previous]) {
            None => Some(index),
            Some(previous) if previous.is_ascii_whitespace() => Some(index),
            Some(_) => None,
        }
    })
}

pub(super) fn no_pull_request_target(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let offenders: Vec<&str> =
        match super::super::workflows_with_trigger(&workflows, "pull_request_target") {
            Ok(matching) => matching
                .iter()
                .map(|workflow| workflow.path.as_str())
                .collect(),
            Err(verdict) => return *verdict,
        };

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

pub(super) fn concurrency_covers_pull_requests(context: &AuditContext) -> Verdict {
    let workflows = match readable_workflows(context) {
        Ok(workflows) => workflows,
        Err(verdict) => return *verdict,
    };

    let pull_request_workflows =
        match super::super::workflows_with_trigger(&workflows, "pull_request") {
            Ok(matching) => matching,
            Err(verdict) => return *verdict,
        };

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

pub(super) fn jobs_invoke_tasks(context: &AuditContext) -> Verdict {
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

pub(super) fn pull_request_title_check(context: &AuditContext) -> Verdict {
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

pub(super) fn reconcile_token_is_scoped(context: &AuditContext) -> Verdict {
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
