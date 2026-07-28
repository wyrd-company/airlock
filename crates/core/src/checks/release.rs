//! Release: release units, changelogs, and the release workflow.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::yaml::Yaml;

use super::{AuditContext, ParsedFile, Verdict};

/// Publication commands that mean a workflow publishes rather than delivers.
const PUBLICATION_SIGNALS: &[&str] = &[
    "cargo publish",
    "npm publish",
    "gh release create",
    "docker push",
    "twine upload",
];

pub(crate) fn run(id: &str, _rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-REL-01" => release_units_declared(context),
        "REPO-REL-02" => changelog_per_unit(context),
        "REPO-REL-03" => no_root_aggregate_changelog(context),
        "REPO-REL-04" => release_is_dispatched(context),
        "REPO-REL-07" => no_publish_on_merge(context),
        _ => return None,
    })
}

fn release_units_declared(context: &AuditContext) -> Verdict {
    match context.yaml(".intentional/config.yml") {
        ParsedFile::Undecided(verdict) => *verdict,
        ParsedFile::Missing | ParsedFile::NotAFile(_) => Verdict::fail_at(
            "file_missing",
            ".intentional/config.yml",
            ".intentional/config.yml is absent, so no release units are declared",
            Remediation::new(
                "declare_release_units",
                "Add .intentional/config.yml declaring the repository's release units.",
            ),
        ),
        ParsedFile::Parsed(document) => {
            let units = document
                .get("release-units")
                .and_then(Yaml::as_map)
                .map(<[(String, Yaml)]>::len)
                .unwrap_or_default();
            if units == 0 {
                Verdict::fail_at(
                    "no_release_units",
                    ".intentional/config.yml",
                    ".intentional/config.yml declares no release units",
                    Remediation::new(
                        "declare_release_units",
                        "Declare at least one release unit.",
                    ),
                )
            } else {
                Verdict::pass_at(
                    "release_units_declared",
                    ".intentional/config.yml",
                    format!("{units} release unit(s) are declared"),
                )
            }
        }
    }
}

fn changelog_per_unit(context: &AuditContext) -> Verdict {
    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so per-unit changelogs could not be \
             checked",
        );
    };

    let missing: Vec<String> = units
        .iter()
        .map(|(_, path)| changelog_path(path))
        .filter(|path| !context.has_file(path))
        .collect();

    if missing.is_empty() {
        Verdict::pass(
            "changelog_per_unit",
            format!(
                "every one of the {} release units has a CHANGELOG.md",
                units.len()
            ),
        )
    } else {
        Verdict::fail(
            "changelog_missing",
            format!("{} absent", missing.join(", ")),
            Remediation::new(
                "add_changelog",
                "Add a CHANGELOG.md at each release unit's declared path.",
            ),
        )
    }
}

fn changelog_path(unit_path: &str) -> String {
    if unit_path == "." || unit_path.is_empty() {
        "CHANGELOG.md".to_owned()
    } else {
        format!("{unit_path}/CHANGELOG.md")
    }
}

fn no_root_aggregate_changelog(context: &AuditContext) -> Verdict {
    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so whether a root changelog aggregates \
             them could not be established",
        );
    };

    if units.len() <= 1 {
        return Verdict::pass(
            "single_release_unit",
            "the repository declares one release unit, so its root changelog is that unit's",
        );
    }

    let root_belongs_to_a_unit = units.iter().any(|(_, path)| path == "." || path.is_empty());
    if root_belongs_to_a_unit {
        return Verdict::fail(
            "root_unit_in_multi_unit_repository",
            "a multi-unit repository declares a release unit at the root, so its root \
             CHANGELOG.md cannot be anything but an aggregate",
            Remediation::new(
                "move_root_unit",
                "Give every release unit its own path below the root.",
            ),
        );
    }

    if context.has_file("CHANGELOG.md") {
        Verdict::fail_at(
            "root_aggregate_changelog",
            "CHANGELOG.md",
            format!(
                "a root CHANGELOG.md exists in a {}-unit repository where no unit lives at the root",
                units.len()
            ),
            Remediation::new(
                "remove_root_changelog",
                "Remove the root CHANGELOG.md; each release unit keeps its own.",
            ),
        )
    } else {
        Verdict::pass(
            "no_root_aggregate_changelog",
            "no aggregate CHANGELOG.md sits at the root",
        )
    }
}

fn release_is_dispatched(context: &AuditContext) -> Verdict {
    let Some(workflow) = context.workflow("release.yml") else {
        return Verdict::manual(
            "no_release_workflow",
            "there is no .github/workflows/release.yml; whether this repository creates releases \
             is a judgment call",
        );
    };

    let all_triggers = try_verdict!(workflow.triggers());

    let mut gaps = Vec::new();
    if !all_triggers
        .iter()
        .any(|trigger| trigger == "workflow_dispatch")
    {
        gaps.push("it does not trigger on workflow_dispatch".to_owned());
    }
    let triggers: Vec<String> = all_triggers
        .into_iter()
        .filter(|trigger| trigger != "workflow_dispatch")
        .collect();
    if !triggers.is_empty() {
        gaps.push(format!("it also triggers on {}", triggers.join(", ")));
    }

    let pins_a_sha = workflow
        .trigger("workflow_dispatch")
        .and_then(|dispatch| dispatch.get("inputs"))
        .into_iter()
        .flat_map(Yaml::keys)
        .any(|input| input.contains("sha") || input.contains("commit"));
    if !pins_a_sha {
        gaps.push("its dispatch inputs name no source sha".to_owned());
    }

    if gaps.is_empty() {
        Verdict::pass_at(
            "release_is_dispatched_on_a_pinned_sha",
            &workflow.path,
            "the release workflow is workflow_dispatch only and takes a source sha",
        )
    } else {
        Verdict::fail_at(
            "release_trigger_wrong",
            &workflow.path,
            gaps.join("; "),
            Remediation::new(
                "dispatch_on_pinned_sha",
                "Make release a workflow_dispatch taking the source sha as an input.",
            ),
        )
    }
}

fn no_publish_on_merge(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget, so the absence of a publish-on-merge \
             workflow could not be established",
        );
    }

    let branch = &context.snapshot.repository.default_branch;
    let mut pushing = Vec::new();
    for workflow in &context.workflows {
        if try_verdict!(workflow.pushes_to(branch)) {
            pushing.push(workflow);
        }
    }

    let offenders: Vec<String> = pushing
        .into_iter()
        .filter_map(|workflow| {
            let found = super::workflow_signals(&workflow.text, PUBLICATION_SIGNALS);
            if found.is_empty() {
                None
            } else {
                Some(format!(
                    "{} runs {} on push to `{branch}`",
                    workflow.path,
                    found
                        .iter()
                        .map(|signal| (**signal).to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        })
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "no_publish_on_merge",
            format!("no workflow publishes on push to `{branch}`"),
        )
    } else {
        Verdict::fail(
            "publishes_on_merge",
            offenders.join("; "),
            Remediation::new(
                "dispatch_publication",
                "Publish from a dispatched workflow, never automatically on merge.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        evaluate(&rule(id), &context).status
    }

    const SINGLE_UNIT: &str = "release-units:\n  airlock:\n    path: .\n";
    const TWO_UNITS: &str = "release-units:\n  core:\n    path: core\n  cli:\n    path: cli\n";

    #[test]
    fn release_units_must_be_declared() {
        assert_eq!(
            verdict("REPO-REL-01", &[(".intentional/config.yml", SINGLE_UNIT)]),
            Status::Pass
        );
        assert_eq!(verdict("REPO-REL-01", &[]), Status::Fail);
        assert_eq!(
            verdict(
                "REPO-REL-01",
                &[(".intentional/config.yml", "settings: {}\n")]
            ),
            Status::Fail
        );
    }

    #[test]
    fn each_release_unit_needs_a_changelog() {
        assert_eq!(
            verdict(
                "REPO-REL-02",
                &[
                    (".intentional/config.yml", SINGLE_UNIT),
                    ("CHANGELOG.md", "# log")
                ]
            ),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-REL-02", &[(".intentional/config.yml", SINGLE_UNIT)]),
            Status::Fail
        );
        assert_eq!(
            verdict(
                "REPO-REL-02",
                &[
                    (".intentional/config.yml", TWO_UNITS),
                    ("core/CHANGELOG.md", "# log")
                ]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_single_unit_repository_keeps_its_root_changelog() {
        assert_eq!(
            verdict(
                "REPO-REL-03",
                &[
                    (".intentional/config.yml", SINGLE_UNIT),
                    ("CHANGELOG.md", "# log")
                ]
            ),
            Status::Pass
        );
    }

    #[test]
    fn a_multi_unit_repository_may_not_keep_a_root_changelog() {
        assert_eq!(
            verdict(
                "REPO-REL-03",
                &[
                    (".intentional/config.yml", TWO_UNITS),
                    ("CHANGELOG.md", "# log")
                ]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-REL-03", &[(".intentional/config.yml", TWO_UNITS)]),
            Status::Pass
        );
    }

    #[test]
    fn a_release_workflow_must_be_dispatched_on_a_pinned_sha() {
        let good = "on:\n  workflow_dispatch:\n    inputs:\n      source-sha:\n        \
                    required: true\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict("REPO-REL-04", &[(".github/workflows/release.yml", good)]),
            Status::Pass
        );
        let automatic = "on:\n  push:\n    branches: [main]\npermissions: {}\njobs: {}\n";
        assert_eq!(
            verdict(
                "REPO-REL-04",
                &[(".github/workflows/release.yml", automatic)]
            ),
            Status::Fail
        );
        assert_eq!(verdict("REPO-REL-04", &[]), Status::Manual);
    }

    #[test]
    fn publishing_on_merge_fails() {
        let publishing = "on:\n  push:\n    branches: [main]\npermissions: {}\njobs:\n  a:\n    \
                          steps:\n      - run: cargo publish\n";
        assert_eq!(
            verdict("REPO-REL-07", &[(".github/workflows/x.yml", publishing)]),
            Status::Fail
        );
        let harmless = "on:\n  push:\n    branches: [main]\npermissions: {}\njobs:\n  a:\n    \
                        steps:\n      - run: task check\n";
        assert_eq!(
            verdict("REPO-REL-07", &[(".github/workflows/x.yml", harmless)]),
            Status::Pass
        );
    }
}
