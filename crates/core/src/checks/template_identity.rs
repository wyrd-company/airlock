//! Verify parent template identity and accepted parts.
//
// relationships:
//   implements: release-process-conformance

use super::{AuditContext, Verdict};
use crate::document::DocumentError;
use crate::findings::Remediation;
use crate::policy::RuleInstance;
use crate::snapshot::FileState;
use crate::template_identity::{
    self as input, config, TemplateEvidence, TemplateItem, TemplateRevision,
};
use crate::ActionGroup;
use serde_json::Value;

fn accepted(status: Option<&str>) -> bool {
    matches!(status, Some("identical" | "ahead"))
}

fn gap(reason: &str, path: &str, detail: impl Into<String>) -> Verdict {
    Verdict::fail_at(
        reason,
        path,
        detail,
        Remediation::new(
            ActionGroup::APPLY_ACCEPTED_TEMPLATE,
            "Apply, update or baseline with Toha, select accepted parts, and commit the result.",
        ),
    )
}

fn input_error(code: &str, endpoint: String, detail: String) -> Box<Verdict> {
    let mut verdict = Verdict::run_error(code, detail);
    verdict.error.as_mut().expect("run error").endpoint = endpoint;
    Box::new(verdict)
}

fn record(context: &AuditContext, path: &str) -> Result<Value, Box<Verdict>> {
    if input::non_file_path(context.snapshot, path) {
        return Err(Box::new(gap(
            "record-not-a-file",
            path,
            "The record path contains a non-regular file",
        )));
    }
    match context.snapshot.file(path) {
        FileState::Content { bytes, .. } => input::read(bytes).map_err(|error| {
            Box::new(match error {
                DocumentError::Identity(message) => {
                    gap("record-schema-not-supported", path, message)
                }
                DocumentError::Invalid(message) => gap("record-unreadable", path, message),
            })
        }),
        FileState::Missing => Err(Box::new(gap(
            "record-missing",
            path,
            "The applied record is absent",
        ))),
        FileState::NotAFile { .. } | FileState::Symlink { .. } => Err(Box::new(gap(
            "record-not-a-file",
            path,
            "The applied record is not a regular file",
        ))),
        FileState::TreeTruncated => Err(input_error(
            "tree_truncated",
            format!(
                "GET /repos/{}/git/trees/{}?recursive=1",
                context.full_name(),
                context.snapshot.commit
            ),
            format!("The truncated tree cannot establish whether {path} exists"),
        )),
        FileState::OverBudget { size, limit } => Err(input_error(
            "file_over_budget",
            format!(
                "GET /repos/{}/git/blobs/{}",
                context.full_name(),
                context
                    .snapshot
                    .entry(path)
                    .map_or(path, |e| e.sha.as_str())
            ),
            format!("{path}: {size} bytes exceeds {limit}"),
        )),
        FileState::Unreadable(error) => Err(Box::new(Verdict::from_api_error(error))),
        FileState::LocalUnreadable { detail } => Err(input_error(
            "local_path_unreadable",
            format!("working-tree://{path}"),
            detail.clone(),
        )),
    }
}

fn item(
    expected: config::ExpectedTemplate,
    record: &Value,
    revisions: &[TemplateRevision],
) -> Result<TemplateItem, Box<Verdict>> {
    let mut item = TemplateItem {
        revision: revisions.iter().find(|r| r.source == expected.source && r.target == expected.target).cloned(),
        found: input::application(record, &expected).map(|a| {
            // Answers, context and paths are not identity evidence.
            serde_json::json!({"template": a["template"], "source": a["source"], "target": a["target"], "commit": a["commit"], "content_digest": a["content_digest"], "parts": a["parts"]})
        }),
        expected, other_targets: Vec::new(), outcome: "gap".into(), reasons: Vec::new(),
    };
    let Some(found) = &item.found else {
        item.other_targets = record["applications"]
            .as_array()
            .expect("validated applications")
            .iter()
            .filter(|a| a["source"] == item.expected.source)
            .filter_map(|a| a["target"].as_str().map(ToOwned::to_owned))
            .collect();
        item.reasons.push("application-missing".into());
        return Ok(item);
    };
    if found["commit"].is_null() {
        item.reasons.push("revision-not-git".into());
    } else {
        let Some(revision) = &item.revision else {
            return Err(Box::new(Verdict::run_error(
                "template-input-unobserved",
                "Template revision observation was not gathered",
            )));
        };
        if !accepted(revision.reachability.as_deref())
            || (item.expected.minimum.is_some() && !accepted(revision.minimum_ancestry.as_deref()))
        {
            item.reasons.push("revision-not-accepted".into());
        }
    }
    if found["parts"]
        .as_array()
        .expect("validated parts")
        .iter()
        .any(|part| !item.expected.parts.iter().any(|p| part == p))
    {
        item.reasons.push("part-not-accepted".into());
    }
    if item.reasons.is_empty() {
        item.outcome = "met".into();
    }
    Ok(item)
}

pub(crate) fn run(rule: &RuleInstance, context: &AuditContext) -> Verdict {
    try_verdict!(context.release_units());
    let entries = match config::expected(rule) {
        Ok(v) => v,
        Err(e) => return Verdict::run_error("invalid-template-configuration", e.to_string()),
    };
    let path = config::record_path(rule);
    let (mut verdict, items) = match record(context, path) {
        Err(verdict) if verdict.error.is_some() => return *verdict,
        Err(verdict) => {
            let reason = verdict
                .evidence
                .as_ref()
                .expect("gap evidence")
                .code
                .clone();
            let items = entries
                .into_iter()
                .map(|expected| TemplateItem {
                    expected,
                    found: None,
                    other_targets: Vec::new(),
                    revision: None,
                    outcome: "gap".into(),
                    reasons: vec![reason.clone()],
                })
                .collect();
            (*verdict, items)
        }
        Ok(record) => {
            let revisions = match &context.template_revisions {
                Ok(v) => v,
                Err(error) => return Verdict::from_api_error(error),
            };
            let items = try_verdict!(entries
                .into_iter()
                .map(|expected| item(expected, &record, revisions))
                .collect::<Result<Vec<_>, _>>());
            let verdict = match items.iter().flat_map(|i| &i.reasons).next() {
                Some(reason) => gap(reason, path, "One or more expected parents have a Gap"),
                None => Verdict::pass_at(
                    "templates-accepted",
                    path,
                    "Every expected parent has an accepted revision and only accepted parts",
                ),
            };
            (verdict, items)
        }
    };
    let evidence = verdict.evidence.as_mut().expect("decided evidence");
    for item in &items {
        evidence.detail.push_str(&format!(
            "; {} at {}: {}",
            item.expected.source,
            item.expected.target,
            if item.reasons.is_empty() {
                "Met".into()
            } else {
                item.reasons.join(", ")
            }
        ));
    }
    evidence.template_identity = Some(TemplateEvidence {
        record_path: path.into(),
        audited_commit: context.snapshot.commit.clone(),
        items,
    });
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixtures;
    use crate::findings::Status;
    use crate::template_identity::TemplateRevision;
    use serde_json::{json, Value};

    fn record() -> Value {
        json!({"$schema":input::SCHEMA_ID,"applications":[{
            "target":".","template":"gh:example-org/catalog@main#bundle","source":"gh:example-org/catalog#bundle",
            "commit":"a".repeat(40),"generated":"toha/1","parts":["alpha"],"answers":{},"context":{},"paths":{}
        }]})
    }
    fn rule() -> RuleInstance {
        fixtures::rule_with(
            config::RULE,
            &[(
                "templates",
                json!([{
                    "source":"gh:example-org/catalog#bundle","ref":"main","minimum":"start","parts":["alpha","beta"]
                }]),
            )],
        )
    }
    fn revision() -> TemplateRevision {
        TemplateRevision {
            source: "gh:example-org/catalog#bundle".into(),
            target: ".".into(),
            resolved_ref: "b".repeat(40),
            resolved_minimum: Some("c".repeat(40)),
            reachability: Some("ahead".into()),
            minimum_ancestry: Some("identical".into()),
        }
    }
    fn check(bytes: &str, mutate: impl FnOnce(&mut AuditContext)) -> Verdict {
        let snapshot = fixtures::snapshot(&[
            (".toha.json", bytes),
            (
                ".intentional/config.yml",
                "release-units: {sample: {path: .}}",
            ),
        ]);
        let policy = fixtures::policy();
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.template_revisions = Ok(vec![revision()]);
        mutate(&mut context);
        super::run(&rule(), &context)
    }
    fn reason(value: Value) -> String {
        check(&value.to_string(), |_| {}).evidence.unwrap().code
    }

    #[test]
    fn template_parent_accepts_reachable_revision_and_selected_subset() {
        let verdict = check(&record().to_string(), |_| {});
        assert_eq!(verdict.status, Some(Status::Met));
        let evidence = verdict.evidence.unwrap().template_identity.unwrap();
        assert_eq!(evidence.items.len(), 1);
        assert_eq!(evidence.items[0].outcome, "met");
        assert_eq!(
            evidence.items[0].revision.as_ref().unwrap().resolved_ref,
            "b".repeat(40)
        );
        assert!(evidence.items[0]
            .found
            .as_ref()
            .unwrap()
            .get("answers")
            .is_none());
    }
    #[test]
    fn template_parent_requires_each_expected_parent_and_ignores_unrelated_applications() {
        let mut value = record();
        let mut unrelated = value["applications"][0].clone();
        unrelated["source"] = json!("gh:example-org/other#bundle");
        unrelated["parts"] = json!(["unlisted"]);
        value["applications"]
            .as_array_mut()
            .unwrap()
            .push(unrelated);
        assert_eq!(check(&value.to_string(), |_| {}).status, Some(Status::Met));
        let mut rule = rule();
        rule.params
            .get_mut("templates")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(json!({"source":"gh:example-org/second#bundle","ref":"main"}));
        let snapshot = fixtures::snapshot(&[
            (".toha.json", &record().to_string()),
            (
                ".intentional/config.yml",
                "release-units: {sample: {path: .}}",
            ),
        ]);
        let policy = fixtures::policy();
        let mut context = fixtures::context(&snapshot, &policy, Vec::new());
        context.template_revisions = Ok(vec![revision()]);
        let verdict = super::run(&rule, &context);
        assert_eq!(verdict.status, Some(Status::Gap));
        let evidence = verdict.evidence.unwrap().template_identity.unwrap();
        assert_eq!(evidence.items[0].outcome, "met");
        assert_eq!(evidence.items[1].reasons, vec!["application-missing"]);
    }

    #[test]
    fn template_parent_rejects_unlisted_parts() {
        let mut value = record();
        value["applications"][0]["parts"] = json!(["gamma"]);
        assert_eq!(reason(value), "part-not-accepted");
    }
    #[test]
    fn template_parent_requires_source_and_target_pair() {
        let mut value = record();
        value["applications"][0]["target"] = json!("nested");
        let evidence = check(&value.to_string(), |_| {}).evidence.unwrap();
        assert_eq!(evidence.code, "application-missing");
        assert_eq!(
            evidence.template_identity.unwrap().items[0].other_targets,
            vec!["nested"]
        );
        let mut value = record();
        value["applications"][0]["source"] = json!("gh:example-org/other#bundle");
        assert_eq!(reason(value), "application-missing");
    }
    #[test]
    fn template_parent_requires_a_git_revision() {
        let mut value = record();
        value["applications"][0]["commit"] = Value::Null;
        value["applications"][0]["content_digest"] = json!("d".repeat(64));
        assert_eq!(reason(value), "revision-not-git");
    }
    #[test]
    fn template_parent_checks_reachability_and_minimum_in_correct_directions() {
        for status in ["behind", "diverged"] {
            for minimum in [false, true] {
                let verdict = check(&record().to_string(), |c| {
                    let r = &mut c.template_revisions.as_mut().unwrap()[0];
                    if minimum {
                        r.minimum_ancestry = Some(status.into());
                    } else {
                        r.reachability = Some(status.into());
                    }
                });
                assert_eq!(verdict.evidence.unwrap().code, "revision-not-accepted");
            }
        }
    }
    #[test]
    fn template_record_syntax_schema_identity_and_validation_are_distinct_gaps() {
        assert_eq!(
            check("not JSON", |_| {}).evidence.unwrap().code,
            "record-unreadable"
        );
        for identity in [
            Value::Null,
            json!(42),
            json!("https://example.invalid/other"),
        ] {
            let mut value = record();
            value["$schema"] = identity;
            let e = check(&value.to_string(), |_| {}).evidence.unwrap();
            assert_eq!(e.code, "record-schema-not-supported");
            assert!(e.detail.contains(input::SCHEMA_ID));
        }
        let mut value = record();
        value["applications"][0]["parts"] = json!(42);
        let e = check(&value.to_string(), |_| {}).evidence.unwrap();
        assert_eq!(e.code, "record-unreadable");
        assert!(e.detail.contains("/applications/0/parts"));
        assert!(e.detail.contains("type"));
    }
    #[test]
    fn template_record_rejects_duplicate_pairs() {
        let mut value = record();
        let app = value["applications"][0].clone();
        value["applications"].as_array_mut().unwrap().push(app);
        assert_eq!(reason(value), "record-unreadable");
    }
    #[test]
    fn template_record_errors_are_never_gaps_or_met() {
        let error = crate::github::ApiError::local(
            crate::github::ErrorCause::NotFound,
            "GET /repos/example-org/catalog/commits/main",
            "not resolvable",
        );
        let v = check(&record().to_string(), |c| c.template_revisions = Err(error));
        assert!(v.status.is_none());
        assert!(v.error.is_some());
    }
    #[test]
    fn template_record_missing_truncated_budget_and_nonfile_are_distinct() {
        for state in [
            FileState::Missing,
            FileState::TreeTruncated,
            FileState::OverBudget {
                size: 100,
                limit: 1,
            },
            FileState::Symlink {
                target: "elsewhere".into(),
            },
            FileState::LocalUnreadable {
                detail: "permission".into(),
            },
        ] {
            let mut snapshot = fixtures::snapshot(&[(
                ".intentional/config.yml",
                "release-units: {sample: {path: .}}",
            )]);
            snapshot.files.insert(".toha.json".into(), state.clone());
            let policy = fixtures::policy();
            let context = fixtures::context(&snapshot, &policy, Vec::new());
            let verdict = super::run(&rule(), &context);
            match state {
                FileState::Missing => assert_eq!(verdict.evidence.unwrap().code, "record-missing"),
                FileState::Symlink { .. } => {
                    assert_eq!(verdict.evidence.unwrap().code, "record-not-a-file")
                }
                _ => {
                    assert!(verdict.status.is_none());
                    assert!(verdict.error.is_some());
                }
            }
        }
    }
    #[test]
    fn template_record_link_in_parent_path_is_not_followed() {
        let mut snapshot = fixtures::snapshot(&[(
            ".intentional/config.yml",
            "release-units: {sample: {path: .}}",
        )]);
        snapshot.tree.entries.push(crate::github::TreeEntry {
            path: "linked".into(),
            kind: crate::github::EntryKind::Symlink,
            mode: "120000".into(),
            sha: "a".repeat(40),
            size: Some(10),
        });
        let mut rule = rule();
        rule.params
            .insert("record-path".into(), json!("linked/record.json"));
        let policy = fixtures::policy();
        let context = fixtures::context(&snapshot, &policy, Vec::new());
        assert_eq!(
            super::run(&rule, &context).evidence.unwrap().code,
            "record-not-a-file"
        );
    }
    #[test]
    fn template_parent_preserves_the_declared_release_unit_scope() {
        let snapshot = fixtures::snapshot(&[]);
        let policy = fixtures::policy();
        let context = fixtures::context(&snapshot, &policy, Vec::new());
        let verdict = crate::checks::evaluate(&rule(), &context);
        assert!(verdict.status.is_none());
        assert!(verdict.error.is_none());
        assert_eq!(verdict.routing.unwrap().reason, "out-of-scope");
    }
    #[test]
    fn template_parent_missing_revision_observation_is_a_run_error() {
        let verdict = check(&record().to_string(), |context| {
            context.template_revisions = Ok(Vec::new())
        });
        assert!(verdict.status.is_none());
        assert_eq!(verdict.error.unwrap().cause, "template-input-unobserved");
    }
}
