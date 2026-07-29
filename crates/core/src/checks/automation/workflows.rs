use super::*;
use crate::ActionGroup;

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
    let workflows = try_verdict!(readable_workflows(context));
    let triggered = try_verdict!(super::super::workflows_with_trigger(
        &workflows,
        "pull_request"
    ));
    match triggered.first() {
        Some(workflow) => Verdict::pass_at(
            "ci_triggers_on_pull_request",
            &workflow.path,
            format!("{} triggers on pull_request", workflow.path),
        ),
        None => Verdict::fail(
            "ci_does_not_trigger_on_pull_request",
            "no workflow triggers on pull_request",
            Remediation::new(
                ActionGroup::TRIGGER_ON_PULL_REQUEST,
                "Trigger CI on pull_request.",
            ),
        ),
    }
}

pub(super) fn workflow_permissions_empty(context: &AuditContext) -> Verdict {
    let workflows = try_verdict!(readable_workflows(context));

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
                ActionGroup::DEFAULT_DENY_PERMISSIONS,
                "Set `permissions: {}` at workflow level and elevate per job.",
            ),
        )
    }
}

pub(super) fn jobs_declare_permissions(context: &AuditContext) -> Verdict {
    let workflows = try_verdict!(readable_workflows(context));

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
                ActionGroup::DECLARE_JOB_PERMISSIONS,
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
                ActionGroup::PIN_ACTION,
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
    let workflows = try_verdict!(readable_workflows(context));

    let offenders: Vec<&str> = try_verdict!(super::super::workflows_with_trigger(
        &workflows,
        "pull_request_target"
    ))
    .iter()
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
                ActionGroup::REMOVE_PULL_REQUEST_TARGET,
                "Replace pull_request_target with pull_request. It runs fork code with secrets.",
            ),
        )
    }
}

pub(super) fn concurrency_covers_pull_requests(context: &AuditContext) -> Verdict {
    let workflows = try_verdict!(readable_workflows(context));

    let pull_request_workflows = try_verdict!(super::super::workflows_with_trigger(
        &workflows,
        "pull_request"
    ));

    if pull_request_workflows.is_empty() {
        return Verdict::fail(
            "no_pull_request_workflow",
            "no workflow triggers on pull_request, so no concurrency group covers pull requests",
            Remediation::new(
                ActionGroup::TRIGGER_ON_PULL_REQUEST,
                "Trigger CI on pull_request.",
            ),
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
                ActionGroup::ADD_CONCURRENCY,
                "Add a concurrency group with cancel-in-progress covering pull requests.",
            ),
        )
    }
}

pub(super) fn jobs_invoke_tasks(context: &AuditContext) -> Verdict {
    let workflows = try_verdict!(readable_workflows(context));

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
                ActionGroup::WRAP_IN_TASK,
                "Move the command into taskfile.yml and invoke the task, so local and CI cannot \
                 drift apart.",
            ),
        )
    }
}

pub(super) fn pull_request_title_check(context: &AuditContext) -> Verdict {
    let workflows = try_verdict!(readable_workflows(context));

    let validating = workflows
        .iter()
        .find(|workflow| workflow.text.contains("pull_request.title"));

    let Some(workflow) = validating else {
        return Verdict::fail(
            "no_title_check",
            "no workflow reads the pull request title to validate its format",
            Remediation::new(
                ActionGroup::ADD_TITLE_CHECK,
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
                ActionGroup::ADD_RECONCILE_WORKFLOW,
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
                ActionGroup::MINT_SCOPED_TOKEN,
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
                ActionGroup::SCOPE_TOKEN,
                "Set `repositories:` on the token-minting step so the token reaches one \
                 repository.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::evaluate;
    use super::super::super::fixtures::*;
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        CheckFixture::new(files).verdict(id).status
    }

    use super::super::decided;
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
