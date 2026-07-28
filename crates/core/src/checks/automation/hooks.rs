use super::*;

pub(super) fn parse_lefthook(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
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
///
/// `Ok(None)` means the hook is not defined. A job whose command airlock
/// cannot read is malformed rather than absent: a job declared with `script:`
/// instead of `run:` is still a command, and dropping it would let "every hook
/// invokes a task" pass over a command nobody read.
pub(super) fn hook_commands(
    lefthook: &Yaml,
    hook: &str,
) -> Result<Option<Vec<String>>, Box<Verdict>> {
    let Some(block) = lefthook.get(hook) else {
        return Ok(None);
    };
    let Some(jobs) = block.get("jobs") else {
        return Ok(None);
    };
    let Some(jobs) = jobs.as_seq() else {
        return Err(Box::new(Verdict::inconclusive(
            super::super::MALFORMED_DECLARATION,
            format!("the `{hook}` jobs in .config/lefthook.yml are not a list"),
        )));
    };

    let mut commands = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        match job.get("run") {
            Some(Yaml::String(command)) => commands.push(command.clone()),
            _ => {
                return Err(Box::new(Verdict::inconclusive(
                    super::super::MALFORMED_DECLARATION,
                    format!(
                        "job {} of the `{hook}` hook in .config/lefthook.yml declares no string \
                         `run` command",
                        index + 1
                    ),
                )))
            }
        }
    }
    Ok(Some(commands))
}

pub(super) fn pre_commit_hook(context: &AuditContext) -> Verdict {
    let lefthook = try_verdict!(parse_lefthook(context));
    let commands = match hook_commands(&lefthook, "pre-commit") {
        Ok(commands) => commands,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = commands else {
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

pub(super) fn commit_msg_hook(context: &AuditContext) -> Verdict {
    let lefthook = match parse_lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };
    let commands = match hook_commands(&lefthook, "commit-msg") {
        Ok(commands) => commands,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = commands else {
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

pub(super) fn pre_push_hook(context: &AuditContext) -> Verdict {
    let lefthook = match parse_lefthook(context) {
        Ok(lefthook) => lefthook,
        Err(verdict) => return *verdict,
    };
    let commands = match hook_commands(&lefthook, "pre-push") {
        Ok(commands) => commands,
        Err(verdict) => return *verdict,
    };
    let Some(commands) = commands else {
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

pub(super) fn hooks_invoke_tasks(context: &AuditContext) -> Verdict {
    let lefthook = match parse_lefthook(context) {
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
        let commands = match hook_commands(&lefthook, hook) {
            Ok(commands) => commands,
            Err(verdict) => return *verdict,
        };
        let Some(commands) = commands else {
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
pub(super) fn decided(verdict: &Verdict) -> bool {
    matches!(
        verdict.status,
        crate::findings::Status::Pass | crate::findings::Status::Fail
    )
}
