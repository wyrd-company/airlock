//! Files: what must be present, what must not be, and what must be a symlink.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::snapshot::FileState;

use super::{presence, AuditContext, Verdict};

/// Agent harness directories and files that must not be committed.
const DEFAULT_FORBIDDEN_PATHS: &[&str] = &[
    ".claude",
    ".cursor",
    ".windsurf",
    ".codex",
    ".aider.conf.yml",
    ".github/copilot-instructions.md",
];

/// Every place GitHub honours a CODEOWNERS file.
const CODEOWNERS_PATHS: &[&str] = &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];

pub(crate) fn run(id: &str, rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-FILE-01" => presence(context, "README.md", "README.md"),
        "REPO-FILE-02" => presence(context, "CONTRIBUTING.md", "CONTRIBUTING.md"),
        "REPO-FILE-03" => gitignore(context),
        "REPO-FILE-04" => gitattributes(context),
        "REPO-FILE-05" => presence(context, ".editorconfig", ".editorconfig"),
        "REPO-FILE-06" => taskfile(context),
        "REPO-FILE-07" => ci_workflow(context),
        "REPO-FILE-08" => renovate(rule, context),
        "REPO-FILE-09" => presence(context, ".config/lefthook.yml", ".config/lefthook.yml"),
        "REPO-FILE-10" => devcontainer(context),
        "REPO-FILE-11" => presence(context, "AGENTS.md", "AGENTS.md"),
        "REPO-FILE-12" => claude_symlink(context),
        "REPO-FILE-13" => no_harness_config(rule, context),
        "REPO-FILE-14" => no_codeowners(context),
        "REPO-FILE-16" => presence(
            context,
            ".github/repo-settings.yml",
            ".github/repo-settings.yml",
        ),
        "REPO-FILE-17" => reconcile_workflow(context),
        _ => return None,
    })
}

fn gitignore(context: &AuditContext) -> Verdict {
    let verdict = presence(context, ".gitignore", ".gitignore");
    if verdict.status != crate::findings::Status::Pass {
        return verdict;
    }
    // Presence is a fact; "ecosystem-appropriate" is a judgment about what the
    // repository builds, so airlock stops where it can no longer prove.
    Verdict::manual(
        "file_present_appropriateness_unproven",
        ".gitignore is present; whether it is ecosystem-appropriate is a judgment call",
    )
}

fn gitattributes(context: &AuditContext) -> Verdict {
    let Some(text) = context.text(".gitattributes") else {
        return presence(context, ".gitattributes", ".gitattributes");
    };
    let normalises = text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line.split_whitespace().any(|token| token == "text=auto")
    });
    if normalises {
        Verdict::pass_at(
            "line_endings_normalised",
            ".gitattributes",
            ".gitattributes normalises line endings with `text=auto`",
        )
    } else {
        Verdict::fail_at(
            "line_endings_not_normalised",
            ".gitattributes",
            ".gitattributes does not normalise line endings",
            Remediation::new(
                "normalise_line_endings",
                "Add `* text=auto` to .gitattributes.",
            ),
        )
    }
}

fn taskfile(context: &AuditContext) -> Verdict {
    if context.has_file("taskfile.yml") {
        return Verdict::pass_at("file_present", "taskfile.yml", "taskfile.yml is present");
    }
    // A capitalised or differently-suffixed taskfile is a different failure
    // from having none at all, and the remediation differs too.
    let alternatives = ["Taskfile.yml", "Taskfile.yaml", "taskfile.yaml"];
    if let Some(found) = alternatives
        .iter()
        .find(|candidate| context.snapshot.entry(candidate).is_some())
    {
        return Verdict::fail_at(
            "taskfile_misnamed",
            found,
            format!("the taskfile is named `{found}` rather than `taskfile.yml`"),
            Remediation::new(
                "rename_taskfile",
                format!("Rename {found} to taskfile.yml."),
            ),
        );
    }
    presence(context, "taskfile.yml", "taskfile.yml")
}

fn ci_workflow(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget, so the absence of a pull-request \
             workflow could not be established",
        );
    }
    match context
        .workflows
        .iter()
        .find(|workflow| workflow.has_trigger("pull_request"))
    {
        Some(workflow) => Verdict::pass_at(
            "ci_workflow_present",
            &workflow.path,
            format!("{} triggers on pull_request", workflow.path),
        ),
        None => Verdict::fail(
            "ci_workflow_missing",
            "no workflow under .github/workflows/ triggers on pull_request",
            Remediation::new(
                "add_ci_workflow",
                "Add a CI workflow triggered on pull_request.",
            ),
        ),
    }
}

fn renovate(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let Some(text) = context.text(".github/renovate.json") else {
        return presence(context, ".github/renovate.json", ".github/renovate.json");
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return Verdict::inconclusive(
            "unparseable_json",
            ".github/renovate.json is not valid JSON, so its presets could not be read",
        );
    };
    let extends: Vec<String> = document
        .get("extends")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if extends.is_empty() {
        return Verdict::fail_at(
            "renovate_extends_nothing",
            ".github/renovate.json",
            ".github/renovate.json extends no preset",
            Remediation::new(
                "extend_org_preset",
                "Extend the organisation's shared renovate preset.",
            ),
        );
    }

    match rule.param_str("renovate-preset") {
        Some(expected) if extends.iter().any(|preset| preset == expected) => Verdict::pass_at(
            "renovate_extends_org_preset",
            ".github/renovate.json",
            format!(".github/renovate.json extends `{expected}`"),
        ),
        Some(expected) => Verdict::fail_at(
            "renovate_preset_mismatch",
            ".github/renovate.json",
            format!(
                ".github/renovate.json extends {} rather than `{expected}`",
                extends.join(", ")
            ),
            Remediation::new(
                "extend_org_preset",
                format!("Extend `{expected}` in .github/renovate.json."),
            ),
        ),
        None => Verdict::manual(
            "renovate_preset_unspecified",
            format!(
                ".github/renovate.json extends {}; the policy sets no `renovate-preset` \
                 parameter, so whether that is the organisation preset is a judgment call",
                extends.join(", ")
            ),
        ),
    }
}

fn devcontainer(context: &AuditContext) -> Verdict {
    if context.snapshot.has_directory(".devcontainer") {
        Verdict::pass_at(
            "directory_present",
            ".devcontainer",
            ".devcontainer/ is present",
        )
    } else {
        Verdict::fail_at(
            "directory_missing",
            ".devcontainer",
            ".devcontainer/ is absent",
            Remediation::new("add_devcontainer", "Add a .devcontainer/ definition."),
        )
    }
}

/// `CLAUDE.md` must be a symlink to `AGENTS.md` — mode `120000`, blob payload
/// exactly `AGENTS.md`. A link that escapes the repository or points anywhere
/// else is a failure, not a near miss.
fn claude_symlink(context: &AuditContext) -> Verdict {
    match context.snapshot.file("CLAUDE.md") {
        FileState::Symlink { target } => {
            let target = target.trim();
            if target == "AGENTS.md" {
                Verdict::pass_at(
                    "symlink_to_agents",
                    "CLAUDE.md",
                    "CLAUDE.md is a symlink (mode 120000) whose target is AGENTS.md",
                )
            } else {
                Verdict::fail_at(
                    "symlink_target_wrong",
                    "CLAUDE.md",
                    format!("CLAUDE.md is a symlink to `{target}` rather than `AGENTS.md`"),
                    Remediation::new(
                        "relink_claude_md",
                        "Point the CLAUDE.md symlink at AGENTS.md.",
                    ),
                )
            }
        }
        FileState::Content { .. } => Verdict::fail_at(
            "not_a_symlink",
            "CLAUDE.md",
            "CLAUDE.md is a regular file rather than a symlink to AGENTS.md",
            Remediation::new(
                "replace_with_symlink",
                "Replace CLAUDE.md with a symlink to AGENTS.md.",
            ),
        ),
        FileState::Missing => Verdict::fail_at(
            "file_missing",
            "CLAUDE.md",
            "CLAUDE.md is absent",
            Remediation::new("add_symlink", "Add CLAUDE.md as a symlink to AGENTS.md."),
        ),
        other => presence_fallback("CLAUDE.md", other),
    }
}

fn presence_fallback(path: &str, state: &FileState) -> Verdict {
    match state {
        FileState::OverBudget { size, limit } => Verdict::inconclusive(
            "file_over_budget",
            format!("{path} is {size} bytes, over the {limit} byte limit, so it was not read"),
        ),
        FileState::Unreadable(error) => Verdict::from_api_error(error),
        FileState::NotAFile { kind, mode } => Verdict::fail_at(
            "path_is_not_a_file",
            path,
            format!("{path} is a {kind:?} (mode {mode})"),
            Remediation::new("replace_entry", format!("Make {path} a regular file.")),
        ),
        _ => Verdict::inconclusive("indeterminate_path", format!("{path} could not be read")),
    }
}

fn no_harness_config(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let forbidden = rule.param_strings("forbidden-paths").unwrap_or_else(|| {
        DEFAULT_FORBIDDEN_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect()
    });

    let found: Vec<String> = forbidden
        .iter()
        .filter(|path| {
            context.snapshot.entry(path).is_some() || context.snapshot.has_directory(path)
        })
        .cloned()
        .collect();

    if found.is_empty() {
        Verdict::pass(
            "no_harness_config",
            "no agent harness configuration is committed",
        )
    } else {
        Verdict::fail(
            "harness_config_committed",
            format!("{} is committed", found.join(", ")),
            Remediation::new(
                "remove_harness_config",
                "Remove the agent harness configuration; it belongs outside the repository.",
            ),
        )
    }
}

fn no_codeowners(context: &AuditContext) -> Verdict {
    let found: Vec<&&str> = CODEOWNERS_PATHS
        .iter()
        .filter(|path| context.snapshot.entry(path).is_some())
        .collect();

    if found.is_empty() {
        Verdict::pass("no_codeowners", "no CODEOWNERS file is present")
    } else {
        Verdict::fail(
            "codeowners_present",
            format!(
                "{} is present",
                found
                    .iter()
                    .map(|path| (**path).to_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new("remove_codeowners", "Remove the CODEOWNERS file."),
        )
    }
}

fn reconcile_workflow(context: &AuditContext) -> Verdict {
    let Some(workflow) = context.workflow("reconcile-settings.yml") else {
        return presence(
            context,
            ".github/workflows/reconcile-settings.yml",
            ".github/workflows/reconcile-settings.yml",
        );
    };
    let branch = &context.snapshot.repository.default_branch;
    if workflow.pushes_to(branch) {
        Verdict::pass_at(
            "reconcile_triggers_on_default_branch",
            &workflow.path,
            format!("the reconcile workflow triggers on push to `{branch}`"),
        )
    } else {
        Verdict::fail_at(
            "reconcile_trigger_wrong",
            &workflow.path,
            format!("the reconcile workflow does not trigger on push to `{branch}`"),
            Remediation::new(
                "trigger_on_default_branch",
                format!("Trigger the reconcile workflow on push to `{branch}`."),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;
    use crate::snapshot::FileState;
    use serde_json::json;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        evaluate(&rule(id), &context).status
    }

    #[test]
    fn presence_rules_pass_when_the_file_is_there() {
        for (id, path) in [
            ("REPO-FILE-01", "README.md"),
            ("REPO-FILE-02", "CONTRIBUTING.md"),
            ("REPO-FILE-05", ".editorconfig"),
            ("REPO-FILE-09", ".config/lefthook.yml"),
            ("REPO-FILE-11", "AGENTS.md"),
            ("REPO-FILE-16", ".github/repo-settings.yml"),
        ] {
            assert_eq!(verdict(id, &[(path, "content")]), Status::Pass, "{id}");
            assert_eq!(verdict(id, &[]), Status::Fail, "{id}");
        }
    }

    #[test]
    fn a_present_gitignore_still_defers_the_appropriateness_judgment() {
        assert_eq!(
            verdict("REPO-FILE-03", &[(".gitignore", "target\n")]),
            Status::Manual
        );
        assert_eq!(verdict("REPO-FILE-03", &[]), Status::Fail);
    }

    #[test]
    fn gitattributes_must_normalise_line_endings() {
        assert_eq!(
            verdict("REPO-FILE-04", &[(".gitattributes", "* text=auto\n")]),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-FILE-04", &[(".gitattributes", "*.png binary\n")]),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-FILE-04", &[(".gitattributes", "# * text=auto\n")]),
            Status::Fail
        );
    }

    #[test]
    fn a_capitalised_taskfile_fails_with_its_own_reason() {
        let snapshot = snapshot(&[("Taskfile.yml", "version: '3'\n")]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-FILE-06"), &context);
        assert_eq!(verdict.status, Status::Fail);
        assert_eq!(verdict.evidence.unwrap().code, "taskfile_misnamed");
    }

    #[test]
    fn a_pull_request_workflow_satisfies_the_ci_file_rule() {
        assert_eq!(
            verdict(
                "REPO-FILE-07",
                &[(
                    ".github/workflows/ci.yml",
                    "on:\n  pull_request:\njobs: {}\n"
                )]
            ),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-FILE-07",
                &[(".github/workflows/ci.yml", "on:\n  push:\njobs: {}\n")]
            ),
            Status::Fail
        );
    }

    #[test]
    fn renovate_presets_are_compared_when_the_policy_names_one() {
        let snapshot = snapshot(&[(
            ".github/renovate.json",
            "{\"extends\":[\"github>owner/.github\"]}",
        )]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-FILE-08"), &context).status,
            Status::Manual
        );
        let matched = rule_with(
            "REPO-FILE-08",
            &[("renovate-preset", json!("github>owner/.github"))],
        );
        assert_eq!(evaluate(&matched, &context).status, Status::Pass);
        let mismatched = rule_with(
            "REPO-FILE-08",
            &[("renovate-preset", json!("github>elsewhere/.github"))],
        );
        assert_eq!(evaluate(&mismatched, &context).status, Status::Fail);
    }

    #[test]
    fn a_devcontainer_directory_is_recognised_by_its_contents() {
        assert_eq!(
            verdict("REPO-FILE-10", &[(".devcontainer/devcontainer.json", "{}")]),
            Status::Pass
        );
        assert_eq!(verdict("REPO-FILE-10", &[]), Status::Fail);
    }

    #[test]
    fn claude_md_must_be_a_symlink_to_agents_md() {
        let mut snapshot = snapshot(&[("AGENTS.md", "guidance")]);
        snapshot.files.insert(
            "CLAUDE.md".to_owned(),
            FileState::Symlink {
                target: "AGENTS.md".to_owned(),
            },
        );
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-FILE-12"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_symlink_escaping_the_repository_fails() {
        let mut snapshot = snapshot(&[("AGENTS.md", "guidance")]);
        snapshot.files.insert(
            "CLAUDE.md".to_owned(),
            FileState::Symlink {
                target: "../../etc/passwd".to_owned(),
            },
        );
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let verdict = evaluate(&rule("REPO-FILE-12"), &context);
        assert_eq!(verdict.status, Status::Fail);
        assert_eq!(verdict.evidence.unwrap().code, "symlink_target_wrong");
    }

    #[test]
    fn a_regular_claude_md_fails() {
        assert_eq!(
            verdict("REPO-FILE-12", &[("CLAUDE.md", "not a link")]),
            Status::Fail
        );
    }

    #[test]
    fn committed_harness_configuration_fails() {
        assert_eq!(
            verdict("REPO-FILE-13", &[(".claude/settings.json", "{}")]),
            Status::Fail
        );
        assert_eq!(verdict("REPO-FILE-13", &[("README.md", "x")]), Status::Pass);
    }

    #[test]
    fn a_codeowners_file_anywhere_github_honours_it_fails() {
        for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] {
            assert_eq!(verdict("REPO-FILE-14", &[(path, "* @owner")]), Status::Fail);
        }
        assert_eq!(verdict("REPO-FILE-14", &[]), Status::Pass);
    }

    #[test]
    fn the_reconcile_workflow_must_trigger_on_the_default_branch() {
        assert_eq!(
            verdict(
                "REPO-FILE-17",
                &[(
                    ".github/workflows/reconcile-settings.yml",
                    "on:\n  push:\n    branches: [main]\njobs: {}\n"
                )]
            ),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-FILE-17",
                &[(
                    ".github/workflows/reconcile-settings.yml",
                    "on:\n  workflow_dispatch: {}\njobs: {}\n"
                )]
            ),
            Status::Fail
        );
        assert_eq!(verdict("REPO-FILE-17", &[]), Status::Fail);
    }
}
