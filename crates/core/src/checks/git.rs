//! Git configuration: branches, rulesets, merge settings, tags, and history.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::remediation::ActionGroup;

use super::{AuditContext, Verdict};

pub(crate) fn run(id: &str, rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-GIT-01" => default_branch(context),
        "REPO-GIT-02" => org_ruleset_coverage(context),
        "REPO-GIT-03" => branch_rule_shape(context),
        "REPO-GIT-04" => merge_commits_disabled(context),
        "REPO-GIT-05" => squash_enabled(context),
        "REPO-GIT-06" => auto_delete_enabled(context),
        "REPO-GIT-07" => optional_features_off(context),
        "REPO-GIT-08" => tags_have_no_v_prefix(context),
        "REPO-GIT-09" => multi_unit_tag_shape(context),
        "REPO-GIT-10" => no_merge_commits(rule, context),
        "REPO-GIT-13" => app_identity_conventions(context),
        _ => return None,
    })
}

fn default_branch(context: &AuditContext) -> Verdict {
    let branch = &context.snapshot.repository.default_branch;
    if branch == "main" {
        Verdict::pass("default_branch_is_main", "the default branch is `main`")
    } else {
        Verdict::fail(
            "default_branch_is_not_main",
            format!("the default branch is `{branch}`"),
            Remediation::new(
                ActionGroup::RENAME_DEFAULT_BRANCH,
                "Rename the default branch to `main`.",
            ),
        )
    }
}

fn org_ruleset_coverage(context: &AuditContext) -> Verdict {
    let rulesets = match &context.rulesets {
        Ok(rulesets) => rulesets,
        Err(error) => return Verdict::from_api_error(error),
    };

    let covering: Vec<&crate::github::Ruleset> = rulesets
        .iter()
        .filter(|ruleset| {
            ruleset.source_type.as_deref() == Some("Organization")
                && ruleset.target.as_deref().unwrap_or("branch") == "branch"
                && ruleset.enforcement.as_deref() == Some("active")
        })
        .collect();

    if covering.is_empty() {
        // Absence over a listing airlock only saw part of is not absence.
        if rulesets.truncated {
            return Verdict::inconclusive(
                "ruleset_listing_truncated",
                format!(
                    "no organisation ruleset was found in the {} rulesets airlock could read, \
                     but the listing stopped at the page budget, so the rest was never examined",
                    rulesets.len()
                ),
            );
        }
        Verdict::fail(
            "no_org_ruleset",
            "no active organisation-sourced branch ruleset covers the repository",
            Remediation::new(
                ActionGroup::APPLY_ORG_RULESET,
                "Apply an organisation ruleset targeting the default branch. Rulesets are an \
                 organisation-side setting airlock cannot change.",
            ),
        )
    } else {
        Verdict::pass(
            "org_ruleset_active",
            format!(
                "{} active organisation ruleset(s) cover the repository: {}",
                covering.len(),
                covering
                    .iter()
                    .map(|ruleset| ruleset.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
}

fn branch_rule_shape(context: &AuditContext) -> Verdict {
    let rules = match &context.branch_rules {
        Ok(rules) => rules,
        Err(error) => return Verdict::from_api_error(error),
    };

    let branch = &context.snapshot.repository.default_branch;
    let pull_request = rules.iter().find(|rule| rule.rule_type == "pull_request");
    let linear = rules
        .iter()
        .any(|rule| rule.rule_type == "required_linear_history");

    // A rule airlock did not see is not a rule that is absent. Only a complete
    // listing can support "this branch is not protected".
    if rules.truncated && (pull_request.is_none() || !linear) {
        return Verdict::inconclusive(
            "branch_rule_listing_truncated",
            format!(
                "the rules on `{branch}` stopped at the page budget after {} rules, so a \
                 missing rule may simply be one airlock never read",
                rules.len()
            ),
        );
    }

    let mut gaps = Vec::new();
    let Some(pull_request) = pull_request else {
        gaps.push("pull requests are not required".to_owned());
        return report_branch_gaps(branch, gaps);
    };

    let methods = try_verdict!(super::json_strings(
        &pull_request.parameters,
        "allowed_merge_methods",
        "the allowed merge methods on the pull request rule",
    ))
    .unwrap_or_default();

    let mut sorted = methods.clone();
    sorted.sort();
    if sorted != vec!["rebase".to_owned(), "squash".to_owned()] {
        gaps.push(format!(
            "allowed merge methods are [{}], expected squash and rebase only",
            methods.join(", ")
        ));
    }
    if !linear {
        gaps.push("linear history is not required".to_owned());
    }

    report_branch_gaps(branch, gaps)
}

fn report_branch_gaps(branch: &str, gaps: Vec<String>) -> Verdict {
    if gaps.is_empty() {
        Verdict::pass(
            "branch_rules_conform",
            format!(
                "rules on `{branch}` require pull requests, allow only squash and rebase, and \
                 require linear history"
            ),
        )
    } else {
        Verdict::fail(
            "branch_rules_insufficient",
            format!("on `{branch}`: {}", gaps.join("; ")),
            Remediation::new(
                ActionGroup::TIGHTEN_RULESET,
                "Update the ruleset to require pull requests, allow only squash and rebase, and \
                 require linear history.",
            ),
        )
    }
}

fn boolean_setting(
    actual: bool,
    expected: bool,
    code_pass: &str,
    code_fail: &str,
    subject: &str,
    remedy: &str,
) -> Verdict {
    if actual == expected {
        Verdict::pass(code_pass, format!("{subject} is {actual}"))
    } else {
        Verdict::fail(
            code_fail,
            format!("{subject} is {actual}, expected {expected}"),
            Remediation::new(ActionGroup::CHANGE_REPOSITORY_SETTING, remedy.to_owned()),
        )
    }
}

fn merge_commits_disabled(context: &AuditContext) -> Verdict {
    let setting = super::merge_setting("merge_commit");
    boolean_setting(
        setting.live(&context.snapshot.repository),
        setting.expected,
        "merge_commits_disabled",
        "merge_commits_enabled",
        "merge commits allowed",
        "Disable merge commits on the repository.",
    )
}

fn squash_enabled(context: &AuditContext) -> Verdict {
    let setting = super::merge_setting("squash");
    boolean_setting(
        setting.live(&context.snapshot.repository),
        setting.expected,
        "squash_enabled",
        "squash_disabled",
        "squash merge allowed",
        "Enable squash merging on the repository.",
    )
}

fn auto_delete_enabled(context: &AuditContext) -> Verdict {
    let setting = super::merge_setting("delete_branch_on_merge");
    boolean_setting(
        setting.live(&context.snapshot.repository),
        setting.expected,
        "auto_delete_enabled",
        "auto_delete_disabled",
        "auto-delete head branch on merge",
        "Enable auto-delete of head branches on merge.",
    )
}

fn optional_features_off(context: &AuditContext) -> Verdict {
    let repository = &context.snapshot.repository;
    let on: Vec<&str> = [
        ("wikis", repository.has_wiki),
        ("projects", repository.has_projects),
        ("discussions", repository.has_discussions),
    ]
    .iter()
    .filter(|(_, enabled)| *enabled)
    .map(|(name, _)| *name)
    .collect();

    if on.is_empty() {
        Verdict::pass(
            "optional_features_off",
            "wikis, projects, and discussions are all off",
        )
    } else {
        // Whether an enabled feature is deliberate is not something the API
        // can answer, so airlock reports it rather than failing it.
        Verdict::manual(
            "optional_features_on",
            format!(
                "{} enabled; whether that is deliberate use is a judgment call",
                on.join(", ")
            ),
        )
    }
}

fn tags_have_no_v_prefix(context: &AuditContext) -> Verdict {
    let tags = match &context.tags {
        Ok(tags) => tags,
        Err(error) => return Verdict::from_api_error(error),
    };

    let offenders: Vec<&str> = tags
        .iter()
        .map(|tag| tag.name.as_str())
        .filter(|name| {
            name.strip_prefix('v')
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        .collect();

    if offenders.is_empty() {
        // "No tag carries a `v` prefix" is an assertion about every tag. A
        // clean prefix of the tag list does not establish it.
        if tags.truncated {
            return Verdict::inconclusive(
                "tag_listing_truncated",
                format!(
                    "none of the {} tags airlock read carry a `v` prefix, but the listing \
                     stopped at the page budget, so the rest were never examined",
                    tags.len()
                ),
            );
        }
        Verdict::pass(
            "no_v_prefixed_tags",
            format!("none of the {} tags carry a `v` prefix", tags.len()),
        )
    } else {
        Verdict::fail(
            "v_prefixed_tags",
            format!("{} carry a `v` prefix", offenders.join(", ")),
            Remediation::new(
                ActionGroup::RETAG_WITHOUT_PREFIX,
                "Tag releases without the `v` prefix.",
            ),
        )
    }
}

fn multi_unit_tag_shape(context: &AuditContext) -> Verdict {
    // Built-in applicability intercepts this; retain the guard as belt-and-braces defense.
    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so whether its tags should be scoped \
             could not be established",
        );
    };
    if units.len() <= 1 {
        return Verdict::pass(
            "single_release_unit",
            "the repository declares one release unit, so scoped tag names do not apply",
        );
    }

    let tags = match &context.tags {
        Ok(tags) => tags,
        Err(error) => return Verdict::from_api_error(error),
    };

    let offenders: Vec<&str> = tags
        .iter()
        .map(|tag| tag.name.as_str())
        .filter(|name| !name.trim_start_matches('@').contains('@'))
        .collect();

    if offenders.is_empty() {
        if tags.truncated {
            return Verdict::inconclusive(
                "tag_listing_truncated",
                format!(
                    "all {} tags airlock read are scoped, but the listing stopped at the page \
                     budget, so the rest were never examined",
                    tags.len()
                ),
            );
        }
        Verdict::pass(
            "scoped_tags",
            format!(
                "every tag in this {}-unit repository is scoped as name@version",
                units.len()
            ),
        )
    } else {
        Verdict::fail(
            "unscoped_tags",
            format!(
                "{} do not name a release unit; a {}-unit repository needs scoped tags",
                offenders.join(", "),
                units.len()
            ),
            Remediation::new(
                ActionGroup::SCOPE_TAGS,
                "Tag each release unit as `@scope/name@version`.",
            ),
        )
    }
}

fn no_merge_commits(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let budget = rule
        .param_u64("max-commits")
        .unwrap_or(context.limits.max_history_commits as u64) as usize;

    let history = match &context.history {
        Ok(history) => history,
        Err(error) => return Verdict::from_api_error(error),
    };
    let commits = &history.items;
    let truncated = history.truncated;

    let merges: Vec<&str> = commits
        .iter()
        .filter(|commit| commit.parents >= 2)
        .map(|commit| commit.sha.as_str())
        .collect();

    if !merges.is_empty() {
        return Verdict::fail(
            "merge_commits_in_history",
            format!(
                "{} merge commit(s) in the newest {} commits, starting at {}",
                merges.len(),
                commits.len(),
                merges[0]
            ),
            Remediation::new(
                ActionGroup::REWRITE_OR_PREVENT_MERGES,
                "Require linear history so merge commits cannot enter the default branch.",
            ),
        );
    }

    if truncated {
        // The assertion is about the whole history. A clean prefix does not
        // prove it, so this is inconclusive with the bound named.
        return Verdict::inconclusive(
            "history_scan_truncated",
            format!(
                "no merge commits in the newest {} commits, but the walk stopped at the {budget} \
                 commit budget, so the whole history was not examined",
                commits.len()
            ),
        );
    }

    Verdict::pass(
        "no_merge_commits",
        format!(
            "no merge commits in all {} commits of history",
            commits.len()
        ),
    )
}

/// A GitHub App's id is a variable and only its private key is a secret.
fn app_identity_conventions(context: &AuditContext) -> Verdict {
    let mut offenders = Vec::new();

    for workflow in &context.workflows {
        for (line_number, line) in workflow.text.lines().enumerate() {
            if contains_reference(line, "secrets.", "_APP_ID") {
                offenders.push(format!(
                    "{}:{} reads an app id from `secrets`",
                    workflow.path,
                    line_number + 1
                ));
            }
            if contains_reference(line, "vars.", "_APP_PRIVATE_KEY") {
                offenders.push(format!(
                    "{}:{} reads an app private key from `vars`",
                    workflow.path,
                    line_number + 1
                ));
            }
        }
    }

    if offenders.is_empty() {
        Verdict::pass(
            "app_identity_conventions_followed",
            "no workflow stores an app id as a secret or an app private key as a variable",
        )
    } else {
        Verdict::fail(
            "app_identity_conventions_broken",
            offenders.join("; "),
            Remediation::new(
                ActionGroup::MOVE_APP_IDENTITY,
                "Store the app id as a variable named `<APP>_APP_ID` and only the private key as \
                 a secret named `<APP>_APP_PRIVATE_KEY`.",
            ),
        )
    }
}

fn contains_reference(line: &str, namespace: &str, suffix: &str) -> bool {
    let Some(position) = line.find(namespace) else {
        return false;
    };
    let rest = &line[position + namespace.len()..];
    let name: String = rest
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect();
    name.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;
    use crate::github::{ApiError, BranchRule, CommitSummary, ErrorCause, Paged, Ruleset, TagRef};
    use crate::remediation::ActionGroup;
    use serde_json::json;

    #[test]
    fn the_default_branch_must_be_main() {
        let mut fixture = CheckFixture::new(&[]);
        assert_eq!(
            evaluate(&rule("REPO-GIT-01"), &fixture.context()).status,
            Status::Pass
        );
        fixture.snapshot.repository.default_branch = "master".to_owned();
        assert_eq!(
            evaluate(&rule("REPO-GIT-01"), &fixture.context()).status,
            Status::Fail
        );
    }

    #[test]
    fn an_organisation_ruleset_is_required() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        assert_eq!(
            evaluate(&rule("REPO-GIT-02"), &context).status,
            Status::Fail
        );

        context.rulesets = Ok(Paged::complete(vec![Ruleset {
            id: 1,
            name: "org-default".to_owned(),
            target: Some("branch".to_owned()),
            source_type: Some("Organization".to_owned()),
            source: Some("owner".to_owned()),
            enforcement: Some("active".to_owned()),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-02"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_repository_level_ruleset_does_not_satisfy_the_organisation_rule() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Ok(Paged::complete(vec![Ruleset {
            id: 1,
            name: "local".to_owned(),
            target: Some("branch".to_owned()),
            source_type: Some("Repository".to_owned()),
            source: Some("owner/name".to_owned()),
            enforcement: Some("active".to_owned()),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-02"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn a_permission_error_makes_a_ruleset_rule_an_error_finding() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Err(ApiError {
            cause: ErrorCause::Permission,
            endpoint: "GET /repos/owner/name/rulesets".to_owned(),
            status: Some(403),
            message: Some("Resource not accessible by integration".to_owned()),
            documentation_url: None,
            accepted_permissions: Some("administration=read".to_owned()),
            request_id: Some("REQ:1".to_owned()),
        });
        let verdict = evaluate(&rule("REPO-GIT-02"), &context);
        assert_eq!(verdict.status, Status::Error);
        let error = verdict.error.unwrap();
        assert_eq!(error.cause, "permission");
        assert_eq!(
            error.accepted_permissions.as_deref(),
            Some("administration=read")
        );
    }

    #[test]
    fn a_plan_limitation_error_names_the_plan_gate() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Err(ApiError {
            cause: ErrorCause::PlanLimitation,
            endpoint: "GET /repos/owner/name/rulesets".to_owned(),
            status: Some(403),
            message: Some("Upgrade to GitHub Pro or make this repository public.".to_owned()),
            documentation_url: None,
            accepted_permissions: None,
            request_id: None,
        });
        let verdict = evaluate(&rule("REPO-GIT-02"), &context);
        assert_eq!(verdict.status, Status::Error);
        assert_eq!(
            verdict.remediation.unwrap().action_group,
            ActionGroup::PLAN_GATE
        );
    }

    #[test]
    fn branch_rules_must_require_pull_requests_squash_rebase_and_linear_history() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();

        context.branch_rules = Ok(Paged::complete(vec![
            BranchRule {
                rule_type: "pull_request".to_owned(),
                source_type: Some("Organization".to_owned()),
                parameters: json!({ "allowed_merge_methods": ["squash", "rebase"] }),
            },
            BranchRule {
                rule_type: "required_linear_history".to_owned(),
                source_type: Some("Organization".to_owned()),
                parameters: json!({}),
            },
        ]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-03"), &context).status,
            Status::Pass
        );

        context.branch_rules = Ok(Paged::complete(vec![BranchRule {
            rule_type: "pull_request".to_owned(),
            source_type: None,
            parameters: json!({ "allowed_merge_methods": ["squash", "rebase", "merge"] }),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-03"), &context).status,
            Status::Fail
        );

        context.branch_rules = Ok(Paged::complete(Vec::new()));
        assert_eq!(
            evaluate(&rule("REPO-GIT-03"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn live_merge_settings_are_checked_individually() {
        let mut fixture = CheckFixture::new(&[]);
        assert_eq!(
            evaluate(&rule("REPO-GIT-04"), &fixture.context()).status,
            Status::Pass
        );
        fixture.snapshot.repository.allow_merge_commit = true;
        fixture.snapshot.repository.allow_squash_merge = false;
        fixture.snapshot.repository.delete_branch_on_merge = false;
        let context = fixture.context();
        for id in ["REPO-GIT-04", "REPO-GIT-05", "REPO-GIT-06"] {
            assert_eq!(evaluate(&rule(id), &context).status, Status::Fail, "{id}");
        }
    }

    #[test]
    fn an_enabled_optional_feature_is_reported_rather_than_failed() {
        let mut fixture = CheckFixture::new(&[]);
        fixture.snapshot.repository.has_wiki = true;
        let context = fixture.context();
        assert_eq!(
            evaluate(&rule("REPO-GIT-07"), &context).status,
            Status::Manual
        );
    }

    #[test]
    fn v_prefixed_tags_fail() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.tags = Ok(Paged::complete(vec![
            TagRef {
                name: "1.0.0".to_owned(),
                sha: "a".to_owned(),
            },
            TagRef {
                name: "v2.0.0".to_owned(),
                sha: "b".to_owned(),
            },
        ]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-08"), &context).status,
            Status::Fail
        );

        context.tags = Ok(Paged::complete(vec![
            TagRef {
                name: "1.0.0".to_owned(),
                sha: "a".to_owned(),
            },
            // A tag that merely starts with the letter v is not a prefix.
            TagRef {
                name: "very-old".to_owned(),
                sha: "b".to_owned(),
            },
        ]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-08"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_single_unit_repository_needs_no_scoped_tags() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units:\n  only:\n    path: .\n",
        )]);
        let mut context = fixture.context();
        context.tags = Ok(Paged::complete(vec![TagRef {
            name: "1.0.0".to_owned(),
            sha: "a".to_owned(),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-09"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_multi_unit_repository_needs_scoped_tags() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units:\n  one:\n    path: a\n  two:\n    path: b\n",
        )]);
        let mut context = fixture.context();
        context.tags = Ok(Paged::complete(vec![TagRef {
            name: "1.0.0".to_owned(),
            sha: "a".to_owned(),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-09"), &context).status,
            Status::Fail
        );

        context.tags = Ok(Paged::complete(vec![TagRef {
            name: "one@1.0.0".to_owned(),
            sha: "a".to_owned(),
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-09"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_merge_commit_in_history_fails() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.history = Ok(Paged::complete(vec![
            CommitSummary {
                sha: "a".to_owned(),
                parents: 1,
            },
            CommitSummary {
                sha: "b".to_owned(),
                parents: 2,
            },
        ]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-10"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn a_truncated_history_scan_is_inconclusive_never_a_pass() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.history = Ok(Paged {
            items: vec![CommitSummary {
                sha: "a".to_owned(),
                parents: 1,
            }],
            truncated: true,
        });
        let verdict = evaluate(&rule("REPO-GIT-10"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert!(verdict.evidence.unwrap().detail.contains("budget"));
    }

    #[test]
    fn a_complete_clean_history_passes() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.history = Ok(Paged::complete(vec![CommitSummary {
            sha: "a".to_owned(),
            parents: 1,
        }]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-10"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn an_app_id_stored_as_a_secret_fails() {
        let fixture = CheckFixture::new(&[(
            ".github/workflows/x.yml",
            "jobs:\n  a:\n    steps:\n      - with:\n          app-id: ${{ secrets.THING_APP_ID }}\n",
        )]);
        let context = fixture.context();
        assert_eq!(
            evaluate(&rule("REPO-GIT-13"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn the_documented_app_identity_split_passes() {
        let fixture = CheckFixture::new(&[(
            ".github/workflows/x.yml",
            concat!(
                "jobs:\n  a:\n    steps:\n      - with:\n",
                "          app-id: ${{ vars.THING_APP_ID }}\n",
                "          private-key: ${{ secrets.THING_APP_PRIVATE_KEY }}\n"
            ),
        )]);
        let context = fixture.context();
        assert_eq!(
            evaluate(&rule("REPO-GIT-13"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_truncated_tag_listing_cannot_prove_no_tag_carries_a_prefix() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.tags = Ok(Paged {
            items: vec![TagRef {
                name: "1.0.0".to_owned(),
                sha: "a".to_owned(),
            }],
            truncated: true,
        });
        let verdict = evaluate(&rule("REPO-GIT-08"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert_eq!(verdict.evidence.unwrap().code, "tag_listing_truncated");
    }

    #[test]
    fn a_truncated_tag_listing_still_fails_on_a_prefix_it_did_see() {
        // Truncation cannot prove absence, but it does not un-see a violation.
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.tags = Ok(Paged {
            items: vec![TagRef {
                name: "v1.0.0".to_owned(),
                sha: "a".to_owned(),
            }],
            truncated: true,
        });
        assert_eq!(
            evaluate(&rule("REPO-GIT-08"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn a_truncated_tag_listing_cannot_prove_every_tag_is_scoped() {
        let fixture = CheckFixture::new(&[(
            ".intentional/config.yml",
            "release-units:\n  one:\n    path: a\n  two:\n    path: b\n",
        )]);
        let mut context = fixture.context();
        context.tags = Ok(Paged {
            items: vec![TagRef {
                name: "one@1.0.0".to_owned(),
                sha: "a".to_owned(),
            }],
            truncated: true,
        });
        assert_eq!(
            evaluate(&rule("REPO-GIT-09"), &context).status,
            Status::Inconclusive
        );
    }

    #[test]
    fn a_truncated_ruleset_listing_cannot_prove_no_org_ruleset_covers_the_branch() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Ok(Paged {
            items: vec![Ruleset {
                id: 1,
                name: "repo-local".to_owned(),
                target: Some("branch".to_owned()),
                source_type: Some("Repository".to_owned()),
                source: Some("owner/name".to_owned()),
                enforcement: Some("active".to_owned()),
            }],
            truncated: true,
        });
        let verdict = evaluate(&rule("REPO-GIT-02"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert_eq!(verdict.evidence.unwrap().code, "ruleset_listing_truncated");
    }

    #[test]
    fn a_truncated_ruleset_listing_that_already_found_one_still_passes() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Ok(Paged {
            items: vec![Ruleset {
                id: 1,
                name: "org-default".to_owned(),
                target: Some("branch".to_owned()),
                source_type: Some("Organization".to_owned()),
                source: Some("owner".to_owned()),
                enforcement: Some("active".to_owned()),
            }],
            truncated: true,
        });
        assert_eq!(
            evaluate(&rule("REPO-GIT-02"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_truncated_branch_rule_listing_cannot_prove_a_rule_is_missing() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.branch_rules = Ok(Paged {
            items: vec![BranchRule {
                rule_type: "pull_request".to_owned(),
                source_type: None,
                parameters: json!({ "allowed_merge_methods": ["squash", "rebase"] }),
            }],
            truncated: true,
        });
        let verdict = evaluate(&rule("REPO-GIT-03"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert_eq!(
            verdict.evidence.unwrap().code,
            "branch_rule_listing_truncated"
        );
    }

    #[test]
    fn a_truncated_branch_rule_listing_that_saw_everything_still_passes() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.branch_rules = Ok(Paged {
            items: vec![
                BranchRule {
                    rule_type: "pull_request".to_owned(),
                    source_type: None,
                    parameters: json!({ "allowed_merge_methods": ["squash", "rebase"] }),
                },
                BranchRule {
                    rule_type: "required_linear_history".to_owned(),
                    source_type: None,
                    parameters: json!({}),
                },
            ],
            truncated: true,
        });
        assert_eq!(
            evaluate(&rule("REPO-GIT-03"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_budget_failure_after_verification_is_an_error_finding_not_a_pass() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.rulesets = Err(ApiError::local(
            ErrorCause::Budget,
            "GET /repos/owner/name/rulesets",
            "the 300 second audit budget was exhausted before this request completed",
        ));
        let verdict = evaluate(&rule("REPO-GIT-02"), &context);
        assert_eq!(verdict.status, Status::Error);
        assert_eq!(verdict.error.unwrap().cause, "budget_exhausted");
    }

    #[test]
    fn a_malformed_merge_method_list_is_not_read_as_an_empty_one() {
        let fixture = CheckFixture::new(&[]);
        let mut context = fixture.context();
        context.branch_rules = Ok(Paged::complete(vec![
            BranchRule {
                rule_type: "pull_request".to_owned(),
                source_type: None,
                parameters: json!({ "allowed_merge_methods": ["squash", 7] }),
            },
            BranchRule {
                rule_type: "required_linear_history".to_owned(),
                source_type: None,
                parameters: json!({}),
            },
        ]));
        assert_eq!(
            evaluate(&rule("REPO-GIT-03"), &context).status,
            Status::Inconclusive
        );
    }
}
