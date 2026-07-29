use super::*;
use crate::remediation::ActionGroup;

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
        Some(push) => try_verdict!(super::super::yaml_strings(
            push,
            "tags",
            &format!("the push tags in {}", workflow.path),
        ))
        .unwrap_or_default(),
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
                ActionGroup::CORRECT_TAG_PATTERN,
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
    let pushes_to_branch = try_verdict!(workflow.pushes_to(branch));
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
                ActionGroup::DO_NOT_CANCEL_DELIVERY,
                "Set cancel-in-progress: false on the CD concurrency group.",
            ),
        ),
        None => Verdict::fail_at(
            "cd_concurrency_missing",
            &workflow.path,
            "cd.yml declares no concurrency group with cancel-in-progress",
            Remediation::new(
                ActionGroup::ADD_CD_CONCURRENCY,
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
                ActionGroup::SPLIT_RELEASE_FROM_DELIVERY,
                "Create the release in its own workflow and let CD deliver an existing tag.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::evaluate;
    use super::super::super::fixtures::*;
    use crate::findings::Status;
    use serde_json::json;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        CheckFixture::new(files).verdict(id).status
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

    #[test]
    fn a_malformed_cd_tag_list_is_not_read_as_no_tag_trigger() {
        let cd = "on:\n  push:\n    tags: ['1.0.0', 7]\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict("REPO-CD-02", &[(".github/workflows/cd.yml", cd)]),
            Status::Inconclusive
        );
    }
}
