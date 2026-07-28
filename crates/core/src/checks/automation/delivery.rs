use super::*;

pub(super) fn cd<'a>(context: &'a AuditContext<'_>) -> Option<&'a Workflow> {
    context.workflow("cd.yml")
}

/// The shared shape of the delivery rules: without a `cd.yml`, whether the
/// repository delivers anything is a judgment call, not a failure.
pub(super) fn no_cd_workflow(subject: &str) -> Verdict {
    Verdict::manual(
        "no_cd_workflow",
        format!(
            "there is no .github/workflows/cd.yml, so {subject} could not be checked; whether \
             this repository delivers anything is a judgment call"
        ),
    )
}

pub(super) fn cd_present(context: &AuditContext) -> Verdict {
    match cd(context) {
        Some(workflow) => Verdict::pass_at(
            "cd_workflow_present",
            &workflow.path,
            ".github/workflows/cd.yml is present",
        ),
        None => no_cd_workflow("delivery"),
    }
}

pub(super) fn cd_on_tags(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the tag trigger");
    };
    let expected = rule.param_str("tag-pattern").unwrap_or(DEFAULT_TAG_PATTERN);

    let tags = match workflow.trigger("push") {
        Some(push) => {
            match super::super::yaml_strings(
                push,
                "tags",
                &format!("the push tags in {}", workflow.path),
            ) {
                Ok(tags) => tags.unwrap_or_default(),
                Err(verdict) => return *verdict,
            }
        }
        None => Vec::new(),
    };

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

pub(super) fn cd_on_default_branch(context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the default-branch trigger");
    };
    let branch = &context.snapshot.repository.default_branch;
    let pushes_to_branch = match workflow.pushes_to(branch) {
        Ok(pushes) => pushes,
        Err(verdict) => return *verdict,
    };
    if pushes_to_branch {
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

pub(super) fn cd_concurrency(context: &AuditContext) -> Verdict {
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

pub(super) fn release_and_delivery_separate(context: &AuditContext) -> Verdict {
    let Some(workflow) = cd(context) else {
        return no_cd_workflow("the separation of release creation from delivery");
    };

    let found = super::super::workflow_signals(&workflow.text, RELEASE_CREATION_SIGNALS);

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
