//! Identity: naming and declared metadata.

use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::yaml::Yaml;
use crate::ActionGroup;

use super::{declared_topics, repo_settings, AuditContext, Verdict};

pub(crate) fn run(id: &str, rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-NAME-01" => name_is_lower_kebab(context),
        "REPO-META-01" => description_declared(context),
        "REPO-META-02" => description_shape(context),
        "REPO-META-06" => topic_count(rule, context),
        "REPO-META-07" => topic_vocabulary(context),
        "REPO-META-09" => topics_are_catalogued(context),
        "REPO-META-10" => no_org_topic(rule, context),
        "REPO-META-11" => merge_settings_declared(context),
        "REPO-META-12" => no_visibility_declared(context),
        "REPO-META-13" => live_matches_declared(context),
        _ => return None,
    })
}

fn name_is_lower_kebab(context: &AuditContext) -> Verdict {
    let name = &context.snapshot.repository.name;
    let offenders: Vec<char> = name
        .chars()
        .filter(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || *character == '-'
                || *character == '.')
        })
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "name_is_lower_kebab",
            format!("`{name}` is lower-kebab-case"),
        )
    } else {
        Verdict::fail(
            "name_is_not_lower_kebab",
            format!(
                "`{name}` contains {}",
                offenders
                    .iter()
                    .map(|character| format!("`{character}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                ActionGroup::RENAME_REPOSITORY,
                format!("Rename the repository to lower-kebab-case; `{name}` is not."),
            ),
        )
    }
}

fn description(context: &AuditContext) -> Result<String, Box<Verdict>> {
    let settings = repo_settings(context)?;
    match settings.get("description") {
        Some(Yaml::String(description)) if !description.trim().is_empty() => {
            Ok(description.clone())
        }
        _ => Err(Box::new(Verdict::fail_at(
            "description_not_declared",
            ".github/repo-settings.yml",
            "the declared settings file has no non-empty `description`",
            Remediation::new(
                ActionGroup::DECLARE_DESCRIPTION,
                "Add a one-sentence `description:` to .github/repo-settings.yml.",
            ),
        ))),
    }
}

fn description_declared(context: &AuditContext) -> Verdict {
    match description(context) {
        Ok(description) => Verdict::pass_at(
            "description_declared",
            ".github/repo-settings.yml",
            format!("a description is declared: {description}"),
        ),
        Err(verdict) => *verdict,
    }
}

/// The mechanically decidable half of the description rule.
///
/// Length and sentence count are facts. Whether a description "survives
/// truncation at ~80" is a judgment about meaning, so a description that
/// clears the facts is reported manual rather than passed.
fn description_shape(context: &AuditContext) -> Verdict {
    const MAX_CHARS: usize = 160;
    const TRUNCATION: usize = 80;

    let description = try_verdict!(description(context));
    let description = description.trim();

    let length = description.chars().count();
    if length > MAX_CHARS {
        return Verdict::fail_at(
            "description_too_long",
            ".github/repo-settings.yml",
            format!("the description is {length} characters, over the {MAX_CHARS} limit"),
            Remediation::new(
                ActionGroup::SHORTEN_DESCRIPTION,
                format!("Cut the description to {MAX_CHARS} characters or fewer."),
            ),
        );
    }

    let sentences = description
        .trim_end_matches('.')
        .split(". ")
        .filter(|sentence| !sentence.trim().is_empty())
        .count();
    if sentences > 1 {
        return Verdict::fail_at(
            "description_is_multiple_sentences",
            ".github/repo-settings.yml",
            format!("the description reads as {sentences} sentences"),
            Remediation::new(
                ActionGroup::SINGLE_SENTENCE_DESCRIPTION,
                "Reduce the description to one sentence.",
            ),
        );
    }

    Verdict::manual(
        "description_shape_verified",
        format!(
            "the description is {length} characters and one sentence; whether it still reads \
             correctly truncated at {TRUNCATION} is a judgment call"
        ),
    )
}

fn topics(context: &AuditContext) -> Result<Vec<String>, Box<Verdict>> {
    let settings = repo_settings(context)?;
    declared_topics(&settings)?.ok_or_else(|| {
        Box::new(Verdict::fail_at(
            "topics_not_declared",
            ".github/repo-settings.yml",
            "the declared settings file has no `topics` list",
            Remediation::new(
                ActionGroup::DECLARE_TOPICS,
                "Add a `topics:` list to .github/repo-settings.yml.",
            ),
        ))
    })
}

fn topic_count(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let minimum = rule.param_u64("min-topics").unwrap_or(3) as usize;
    let maximum = rule.param_u64("max-topics").unwrap_or(8) as usize;

    let topics = try_verdict!(topics(context));

    if topics.len() < minimum || topics.len() > maximum {
        Verdict::fail_at(
            "topic_count_out_of_range",
            ".github/repo-settings.yml",
            format!(
                "{} topics are declared; the policy expects between {minimum} and {maximum}",
                topics.len()
            ),
            Remediation::new(
                ActionGroup::ADJUST_TOPICS,
                format!("Declare between {minimum} and {maximum} topics."),
            ),
        )
    } else {
        Verdict::pass_at(
            "topic_count_in_range",
            ".github/repo-settings.yml",
            format!("{} topics are declared", topics.len()),
        )
    }
}

/// The reference vocabulary for one category.
///
/// `Ok(None)` means the policy declares no such category. A category that is
/// declared but is not a list of strings is malformed reference data, and a
/// vocabulary airlock read only part of would silently accept topics it never
/// compared.
fn vocabulary(context: &AuditContext, category: &str) -> Result<Option<Vec<String>>, Box<Verdict>> {
    let Some(topics) = context.policy.reference_data.get("topics") else {
        return Ok(None);
    };
    super::yaml_strings(
        topics,
        category,
        &format!("the `{category}` list in the policy's topic vocabulary"),
    )
}

fn topic_vocabulary(context: &AuditContext) -> Verdict {
    let topics = try_verdict!(topics(context));

    let artifacts = try_verdict!(vocabulary(context, "artifact-type"));
    let ecosystems = try_verdict!(vocabulary(context, "ecosystem"));
    let (Some(artifacts), Some(ecosystems)) = (artifacts, ecosystems) else {
        return Verdict::inconclusive(
            "no_topic_reference_data",
            "the policy declares no `topics` reference data with `artifact-type` and \
             `ecosystem` lists, so the declared topics cannot be classified",
        );
    };

    let has_artifact = topics.iter().any(|topic| artifacts.contains(topic));
    let has_ecosystem = topics.iter().any(|topic| ecosystems.contains(topic));

    if has_artifact && has_ecosystem {
        Verdict::pass_at(
            "topic_categories_covered",
            ".github/repo-settings.yml",
            "the declared topics include an artifact-type term and an ecosystem term",
        )
    } else {
        let mut missing = Vec::new();
        if !has_artifact {
            missing.push("artifact-type");
        }
        if !has_ecosystem {
            missing.push("ecosystem");
        }
        Verdict::fail_at(
            "topic_category_missing",
            ".github/repo-settings.yml",
            format!("no declared topic is {}", missing.join(" or ")),
            Remediation::new(
                ActionGroup::ADD_TOPIC,
                format!("Add a topic from the {} vocabulary.", missing.join(" and ")),
            ),
        )
    }
}

fn topics_are_catalogued(context: &AuditContext) -> Verdict {
    let topics = try_verdict!(topics(context));

    let Some(reference) = context.policy.reference_data.get("topics") else {
        return Verdict::inconclusive(
            "no_topic_reference_data",
            "the policy declares no `topics` reference data, so the declared topics cannot be \
             checked against a catalogue",
        );
    };

    let Some(categories) = reference.as_map() else {
        return Verdict::inconclusive(
            super::MALFORMED_DECLARATION,
            "the policy's topic vocabulary is not a mapping of category to terms",
        );
    };

    let mut catalogue: Vec<String> = Vec::new();
    for (category, values) in categories {
        catalogue.extend(try_verdict!(super::yaml_string_seq(
            values,
            &format!("the `{category}` list in the policy's topic vocabulary"),
        )));
    }

    let uncatalogued: Vec<&String> = topics
        .iter()
        .filter(|topic| !catalogue.contains(topic))
        .collect();

    if uncatalogued.is_empty() {
        Verdict::pass_at(
            "topics_catalogued",
            ".github/repo-settings.yml",
            "every declared topic appears in the reference vocabulary",
        )
    } else {
        Verdict::fail_at(
            "topic_not_catalogued",
            ".github/repo-settings.yml",
            format!(
                "{} is not in the reference vocabulary",
                uncatalogued
                    .iter()
                    .map(|topic| format!("`{topic}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                ActionGroup::CATALOGUE_TOPIC,
                "Add the topic to the reference vocabulary, or use one already there.",
            ),
        )
    }
}

fn no_org_topic(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    let topics = try_verdict!(topics(context));
    let mut org_names = match rule.param_strings("org-names") {
        Ok(Some(names)) => names,
        Ok(None) => Vec::new(),
        Err(malformed) => {
            return Verdict::inconclusive(super::MALFORMED_DECLARATION, malformed.to_string())
        }
    };
    org_names.push(context.snapshot.repository.owner.clone());

    let offenders: Vec<&String> = topics
        .iter()
        .filter(|topic| {
            org_names
                .iter()
                .any(|org| org.eq_ignore_ascii_case(topic.as_str()))
        })
        .collect();

    if offenders.is_empty() {
        Verdict::pass_at(
            "no_org_topic",
            ".github/repo-settings.yml",
            "no declared topic names an organisation",
        )
    } else {
        Verdict::fail_at(
            "org_topic_declared",
            ".github/repo-settings.yml",
            format!(
                "{} names an organisation",
                offenders
                    .iter()
                    .map(|topic| format!("`{topic}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                ActionGroup::REMOVE_ORG_TOPIC,
                "Remove the organisation-name topic.",
            ),
        )
    }
}

fn merge_settings_declared(context: &AuditContext) -> Verdict {
    let settings = try_verdict!(repo_settings(context));
    let Some(merge) = settings.get("merge") else {
        return Verdict::fail_at(
            "merge_settings_not_declared",
            ".github/repo-settings.yml",
            "the declared settings file has no `merge` block",
            Remediation::new(
                ActionGroup::DECLARE_MERGE_SETTINGS,
                "Declare squash and rebase enabled, merge commits disabled, and head branches \
                 auto-deleted.",
            ),
        );
    };

    let wrong: Vec<String> = super::MERGE_SETTINGS
        .iter()
        .filter_map(|setting| {
            let key = setting.declared;
            let expected = setting.expected;
            let actual = merge.get(key).and_then(Yaml::as_bool);
            match actual {
                Some(actual) if actual == expected => None,
                Some(actual) => Some(format!("{key} is {actual}, expected {expected}")),
                None => Some(format!("{key} is not declared, expected {expected}")),
            }
        })
        .collect();

    if wrong.is_empty() {
        Verdict::pass_at(
            "merge_settings_declared",
            ".github/repo-settings.yml",
            "squash and rebase are enabled, merge commits disabled, head branches auto-deleted",
        )
    } else {
        Verdict::fail_at(
            "merge_settings_wrong",
            ".github/repo-settings.yml",
            wrong.join("; "),
            Remediation::new(
                ActionGroup::CORRECT_MERGE_SETTINGS,
                "Declare squash and rebase enabled, merge commits disabled, and head branches \
                 auto-deleted.",
            ),
        )
    }
}

fn no_visibility_declared(context: &AuditContext) -> Verdict {
    let settings = try_verdict!(repo_settings(context));
    if settings.get("visibility").is_some() {
        Verdict::fail_at(
            "visibility_declared",
            ".github/repo-settings.yml",
            "the declared settings file carries a `visibility` field",
            Remediation::new(
                ActionGroup::REMOVE_VISIBILITY,
                "Remove `visibility` from .github/repo-settings.yml. Publishing a repository is \
                 unrecoverable and stays a deliberate manual act.",
            ),
        )
    } else {
        Verdict::pass_at(
            "no_visibility_declared",
            ".github/repo-settings.yml",
            "no `visibility` field is declared",
        )
    }
}

fn live_matches_declared(context: &AuditContext) -> Verdict {
    let settings = try_verdict!(repo_settings(context));
    let live = &context.snapshot.repository;

    let mut drift = Vec::new();

    if let Some(declared) = settings.get("description").and_then(Yaml::as_str) {
        if live.description.as_deref().unwrap_or_default() != declared {
            drift.push("description".to_owned());
        }
    }

    if let Some(merge) = settings.get("merge") {
        let live_values = [
            ("squash", live.allow_squash_merge),
            ("rebase", live.allow_rebase_merge),
            ("merge_commit", live.allow_merge_commit),
            ("delete_branch_on_merge", live.delete_branch_on_merge),
        ];
        for (key, live_value) in live_values {
            if let Some(declared) = merge.get(key).and_then(Yaml::as_bool) {
                let Some(live_value) = live_value else {
                    return Verdict::inconclusive(
                        "merge_settings_unavailable",
                        "this credential cannot verify merge settings; run the interactive airlock session to verify and align them.",
                    );
                };
                if declared != live_value {
                    drift.push(format!("merge.{key}"));
                }
            }
        }
    }

    if let Some(features) = settings.get("features") {
        let live_values = [
            ("wiki", live.has_wiki),
            ("projects", live.has_projects),
            ("discussions", live.has_discussions),
        ];
        for (key, live_value) in live_values {
            if let Some(declared) = features.get(key).and_then(Yaml::as_bool) {
                if declared != live_value {
                    drift.push(format!("features.{key}"));
                }
            }
        }
    }

    let declared_topic_list = try_verdict!(declared_topics(&settings));
    if let Some(declared) = declared_topic_list {
        match &context.snapshot.topics {
            Ok(live_topics) => {
                let mut declared_sorted = declared.clone();
                declared_sorted.sort();
                let mut live_sorted = live_topics.clone();
                live_sorted.sort();
                if declared_sorted != live_sorted {
                    drift.push("topics".to_owned());
                }
            }
            Err(error) => return Verdict::from_api_error(error),
        }
    }

    if drift.is_empty() {
        Verdict::pass(
            "live_matches_declared",
            format!(
                "live metadata matches the declared file (observed {})",
                live.observed_at.as_deref().unwrap_or("at audit time")
            ),
        )
    } else {
        Verdict::fail(
            "live_drifts_from_declared",
            format!(
                "live metadata differs from the declared file in {}",
                drift.join(", ")
            ),
            Remediation::new(
                ActionGroup::RUN_ALIGN,
                "Use Airlock's operator terminal interface, or fix the declared file. Drift means \
                 the declared and live settings have not been aligned; `airlock align-files` \
                 cannot write repository settings.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;
    use crate::yaml;
    use serde_json::json;

    const SETTINGS: &str = "\
description: A tool that audits repositories.
topics:
  - cli
  - rust
  - github
merge:
  squash: true
  rebase: true
  merge_commit: false
  delete_branch_on_merge: true
features:
  wiki: false
  projects: false
  discussions: false
";

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        evaluate(&rule(id), &context).status
    }

    #[test]
    fn declared_merge_settings_are_inconclusive_when_live_values_are_undisclosed() {
        let mut snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        snapshot.repository.allow_merge_commit = None;
        snapshot.repository.allow_squash_merge = None;
        snapshot.repository.allow_rebase_merge = None;
        snapshot.repository.delete_branch_on_merge = None;
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());

        let verdict = evaluate(&rule("REPO-META-13"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        assert_eq!(
            verdict.evidence.expect("inconclusive evidence").code,
            "merge_settings_unavailable"
        );
    }

    #[test]
    fn a_lower_kebab_name_passes() {
        assert_eq!(verdict("REPO-NAME-01", &[]), Status::Pass);
    }

    #[test]
    fn an_underscored_name_fails() {
        let mut snapshot = snapshot(&[]);
        snapshot.repository.name = "some_repo".to_owned();
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-NAME-01"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn a_declared_description_passes() {
        assert_eq!(
            verdict("REPO-META-01", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Pass
        );
    }

    #[test]
    fn a_missing_settings_file_fails_the_description_rule() {
        assert_eq!(verdict("REPO-META-01", &[]), Status::Fail);
    }

    #[test]
    fn an_unparseable_settings_file_is_inconclusive_not_absent() {
        assert_eq!(
            verdict(
                "REPO-META-01",
                &[(
                    ".github/repo-settings.yml",
                    "description: a\ndescription: b\n"
                )]
            ),
            Status::Inconclusive
        );
    }

    #[test]
    fn a_description_over_the_limit_fails_the_shape_rule() {
        let long = format!("description: \"{}\"\n", "x".repeat(200));
        assert_eq!(
            verdict("REPO-META-02", &[(".github/repo-settings.yml", &long)]),
            Status::Fail
        );
    }

    #[test]
    fn a_two_sentence_description_fails_the_shape_rule() {
        assert_eq!(
            verdict(
                "REPO-META-02",
                &[(
                    ".github/repo-settings.yml",
                    "description: One thing. Then another.\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_well_shaped_description_defers_the_truncation_judgment() {
        assert_eq!(
            verdict("REPO-META-02", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Manual
        );
    }

    #[test]
    fn topic_count_honours_policy_parameters() {
        let snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-06"), &context).status,
            Status::Pass
        );
        let strict = rule_with("REPO-META-06", &[("min-topics", json!(5))]);
        assert_eq!(evaluate(&strict, &context).status, Status::Fail);
    }

    #[test]
    fn topic_vocabulary_is_inconclusive_without_reference_data() {
        assert_eq!(
            verdict("REPO-META-07", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Inconclusive
        );
    }

    #[test]
    fn topic_vocabulary_passes_against_reference_data() {
        let snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        let mut policy = policy();
        policy.reference_data.insert(
            "topics".to_owned(),
            yaml::parse_mapping(
                "artifact-type: [cli]\necosystem: [rust]\nplatform: [github]\n",
                crate::limits::Limits::default().yaml,
            )
            .unwrap(),
        );
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-07"), &context).status,
            Status::Pass
        );
        assert_eq!(
            evaluate(&rule("REPO-META-09"), &context).status,
            Status::Pass
        );
    }

    #[test]
    fn an_uncatalogued_topic_fails() {
        let snapshot = snapshot(&[(
            ".github/repo-settings.yml",
            "topics: [cli, rust, surprising]\n",
        )]);
        let mut policy = policy();
        policy.reference_data.insert(
            "topics".to_owned(),
            yaml::parse_mapping(
                "artifact-type: [cli]\necosystem: [rust]\n",
                crate::limits::Limits::default().yaml,
            )
            .unwrap(),
        );
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-09"), &context).status,
            Status::Fail
        );
    }

    #[test]
    fn an_org_name_topic_fails() {
        assert_eq!(
            verdict(
                "REPO-META-10",
                &[(".github/repo-settings.yml", "topics: [cli, rust, owner]\n")]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-META-10", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Pass
        );
    }

    #[test]
    fn declared_merge_settings_are_checked_field_by_field() {
        assert_eq!(
            verdict("REPO-META-11", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-META-11",
                &[(
                    ".github/repo-settings.yml",
                    "merge:\n  squash: true\n  rebase: true\n  merge_commit: true\n  \
                     delete_branch_on_merge: true\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_declared_visibility_fails() {
        assert_eq!(
            verdict(
                "REPO-META-12",
                &[(".github/repo-settings.yml", "visibility: public\n")]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict("REPO-META-12", &[(".github/repo-settings.yml", SETTINGS)]),
            Status::Pass
        );
    }

    #[test]
    fn live_metadata_drift_is_reported() {
        let snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        let policy = policy();
        let mut drifted = snapshot.clone();
        drifted.repository.description = Some("Something else entirely.".to_owned());
        let drifted_context = context(&drifted, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-13"), &drifted_context).status,
            Status::Fail
        );

        let mut aligned = snapshot;
        aligned.repository.description = Some("A tool that audits repositories.".to_owned());
        aligned.topics = Ok(vec![
            "cli".to_owned(),
            "rust".to_owned(),
            "github".to_owned(),
        ]);
        let aligned_context = context(&aligned, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-13"), &aligned_context).status,
            Status::Pass
        );
    }

    #[test]
    fn a_non_string_topic_never_miscounts_the_topic_rule() {
        // `topics: [cli, 42, rust]` used to yield two topics, so a three-topic
        // minimum failed over a repository that declared three.
        let files = [(
            ".github/repo-settings.yml",
            "topics:\n  - cli\n  - 42\n  - rust\n",
        )];
        let snapshot = snapshot(&files);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());

        let verdict = evaluate(&rule("REPO-META-06"), &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        let evidence = verdict.evidence.unwrap();
        assert_eq!(evidence.code, crate::checks::MALFORMED_DECLARATION);
        assert!(evidence.detail.contains("entry 2"));
    }

    #[test]
    fn a_non_string_topic_is_never_skipped_by_the_vocabulary_rule() {
        // The dropped entry used to be compared against nothing at all, so a
        // topic outside the vocabulary could pass by being wrong-typed.
        let snapshot = snapshot(&[(
            ".github/repo-settings.yml",
            "topics:\n  - cli\n  - 42\n  - rust\n",
        )]);
        let mut policy = policy();
        policy.reference_data.insert(
            "topics".to_owned(),
            yaml::parse_mapping(
                "artifact-type: [cli]\necosystem: [rust]\n",
                crate::limits::Limits::default().yaml,
            )
            .unwrap(),
        );
        let context = context(&snapshot, &policy, Vec::new());

        for id in ["REPO-META-07", "REPO-META-09", "REPO-META-10"] {
            let verdict = evaluate(&rule(id), &context);
            assert_eq!(verdict.status, Status::Inconclusive, "{id}");
            assert_eq!(
                verdict.evidence.unwrap().code,
                crate::checks::MALFORMED_DECLARATION,
                "{id}"
            );
        }
    }

    #[test]
    fn a_malformed_topic_vocabulary_in_the_policy_is_also_refused() {
        let snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        let mut policy = policy();
        policy.reference_data.insert(
            "topics".to_owned(),
            yaml::parse_mapping(
                "artifact-type: [cli, 7]\necosystem: [rust]\n",
                crate::limits::Limits::default().yaml,
            )
            .unwrap(),
        );
        let context = context(&snapshot, &policy, Vec::new());
        for id in ["REPO-META-07", "REPO-META-09"] {
            assert_eq!(
                evaluate(&rule(id), &context).status,
                Status::Inconclusive,
                "{id}"
            );
        }
    }

    #[test]
    fn live_metadata_drift_reports_a_malformed_declaration_rather_than_comparing_part_of_it() {
        let mut snapshot = snapshot(&[(".github/repo-settings.yml", "topics:\n  - cli\n  - 42\n")]);
        snapshot.topics = Ok(vec!["cli".to_owned()]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        assert_eq!(
            evaluate(&rule("REPO-META-13"), &context).status,
            Status::Inconclusive
        );
    }

    #[test]
    fn a_malformed_policy_parameter_is_reported_rather_than_partly_applied() {
        // `org-names: [wyrd-company, 42]` must not quietly check against one
        // org name and pass.
        let snapshot = snapshot(&[(".github/repo-settings.yml", SETTINGS)]);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        let instance = rule_with(
            "REPO-META-10",
            &[("org-names", json!(["wyrd-company", 42]))],
        );
        let verdict = evaluate(&instance, &context);
        assert_eq!(verdict.status, Status::Inconclusive);
        let evidence = verdict.evidence.unwrap();
        assert_eq!(evidence.code, crate::checks::MALFORMED_DECLARATION);
        assert!(evidence.detail.contains("org-names"));
    }
}
