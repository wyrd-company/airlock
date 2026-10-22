//! REPO-REL-08: published records for required primary releases.
//
// relationships:
//   implements: release-process-conformance

use super::{AuditContext, Verdict};
use crate::document::{self, DocumentError};
use crate::findings::Fix;
use crate::github::{ApiError, ErrorCause};
use crate::release_records::{complete, matched_version, MODEL_PATH};
use crate::snapshot::FileState;
use crate::FixGroup;

fn model_gap(reason: &str, detail: impl Into<String>) -> Verdict {
    Verdict::fail_at(reason, MODEL_PATH, detail, Fix::new(FixGroup::DECLARE_RELEASE_UNITS,
        "Run intentional model with a supported producer and commit .intentional/release-model.json (agent reasoning)."))
}

pub(super) fn run(context: &AuditContext) -> Verdict {
    let bytes = match context.snapshot.file(MODEL_PATH) {
        FileState::Content { bytes, .. } => bytes,
        FileState::Missing => {
            return model_gap("release-model-missing", "No committed Release Model")
        }
        FileState::NotAFile { .. } | FileState::Symlink { .. } => {
            return model_gap(
                "release-model-not-a-file",
                "Release Model path is not a regular file",
            )
        }
        FileState::Unreadable(error) => return Verdict::from_api_error(error),
        other => {
            return Verdict::from_api_error(&ApiError::local(
                ErrorCause::Budget,
                format!(
                    "GET /repos/{}/git/trees/{}",
                    context.full_name(),
                    context.snapshot.commit
                ),
                format!("Release Model could not be observed: {other:?}"),
            ))
        }
    };
    let model = match document::model(bytes) {
        Ok(model) => model,
        Err(DocumentError::Identity(detail)) => {
            return model_gap("release-model-schema-not-supported", detail)
        }
        Err(DocumentError::Invalid(detail)) => {
            return model_gap("release-model-unreadable", detail)
        }
    };
    if !model["release_units"]
        .as_object()
        .expect("validated units")
        .values()
        .any(|unit| unit["release_record"] == "required")
    {
        return Verdict::pass(
            "release-records-present",
            r#"{"releases":[],"excluded_tags":[]}"#,
        );
    }
    let tags = match &context.tags {
        Ok(tags) => tags,
        Err(error) => return Verdict::from_api_error(error),
    };
    if let Err(error) = complete(
        tags.truncated,
        &format!("GET /repos/{}/git/matching-refs/tags/", context.full_name()),
    ) {
        return Verdict::from_api_error(&error);
    }
    let inputs = match &context.release_records {
        Ok(inputs) => inputs,
        Err(error) => return Verdict::from_api_error(error),
    };
    let mut items = Vec::new();
    let mut excluded = Vec::new();
    let mut missing = false;
    for (id, unit) in model["release_units"].as_object().expect("validated units") {
        if unit["release_record"] != "required" {
            continue;
        }
        for (key, primary) in unit["tags"].as_object().expect("validated tags") {
            if primary["role"] != "primary" {
                continue;
            }
            let template = primary["template"].as_str().expect("validated template");
            for tag in tags.iter() {
                let Some(version) = matched_version(template, id, &tag.name) else {
                    continue;
                };
                let reason = if tag.object_type != "tag" {
                    Some("lightweight-tag".to_owned())
                } else {
                    None
                };
                if let Some(reason) = reason {
                    excluded
                        .push(serde_json::json!({"unit": id, "tag": tag.name, "reason": reason}));
                    continue;
                }
                let Some(object) = inputs.tags.get(&tag.sha) else {
                    return Verdict::from_api_error(&ApiError::local(
                        ErrorCause::Malformed,
                        format!("GET /repos/{}/git/tags/{}", context.full_name(), tag.sha),
                        "matching annotated tag object was not observed",
                    ));
                };
                let record = match document::tag(&object.message) {
                    Ok(record) => record,
                    Err(reason) => {
                        excluded.push(
                            serde_json::json!({"unit": id, "tag": tag.name, "reason": reason}),
                        );
                        continue;
                    }
                };
                let reason = if record["baseline"] == true {
                    Some("baseline-tag-record")
                } else if record["tag-id"] != format!("release-unit/{id}/{key}") {
                    Some("tag-id-mismatch")
                } else if record["version"] != version {
                    Some("version-mismatch")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    excluded
                        .push(serde_json::json!({"unit": id, "tag": tag.name, "reason": reason}));
                    continue;
                }
                let release = inputs
                    .releases
                    .iter()
                    .find(|release| !release.draft && release.tag_name == tag.name);
                missing |= release.is_none();
                items.push(serde_json::json!({"unit": id, "primary_tag_template": template, "tag_name": tag.name,
                    "tag_record_version": record["version"], "tagged_commit": object.commit,
                    "outcome": if release.is_some() { "Met" } else { "Gap" },
                    "release_record": release.map(|release| serde_json::json!({"id": release.id, "url": release.url}))}));
            }
        }
    }
    let detail = serde_json::json!({"releases": items, "excluded_tags": excluded}).to_string();
    if missing {
        Verdict::fail("release-record-missing", detail, Fix::new(FixGroup::DISPATCH_PUBLICATION,
        "A release workflow or operator must publish a GitHub Release on each missing primary tag (operator)."))
    } else {
        Verdict::pass("release-records-present", detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixtures::*;
    use crate::findings::Status;
    use crate::github::{AnnotatedTag, Paged, ReleaseRecord, TagRef};
    use serde_json::{json, Value};

    fn model() -> Value {
        json!({"$schema": document::MODEL_ID,
            "paths": {"config": ".intentional/config.yml", "intents": ".intentional/intents", "model": MODEL_PATH},
            "release_units": {"sample": {"path": ".", "changelog": "CHANGELOG.md", "disposition": "managed",
                "release_record": "required", "depends_on": [], "ecosystems": [], "projections": [], "sources": [],
                "tags": {"primary": {"role": "primary", "template": "{id}@{version}", "tag_after": []}}}},
            "workspace_tags": {}, "release_groups": {"fixed": [], "linked": []}})
    }

    // Protocol shape measured from Intentional 0.1.8 and 0.2.0 annotated objects:
    // neither target nor tag-role is present. Values are generic fixture data.
    fn record(version: &str) -> String {
        format!("intentional release record\n\ncontract: contract-1\ngenerator: intentional 0.2.0\nplan-digest: sha256:{}\ntag-id: release-unit/sample/primary\nversion: {version}\nbaseline: false\n", "a".repeat(64))
    }

    fn evaluate_with(
        model: &str,
        message: &str,
        object_type: &str,
        published: Option<bool>,
    ) -> Verdict {
        let snapshot = snapshot(&[(MODEL_PATH, model)]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, vec![]);
        context.tags = Ok(Paged::complete(vec![TagRef {
            name: "sample@0.2.0".into(),
            sha: "object".into(),
            object_type: object_type.into(),
        }]));
        let inputs = context.release_records.as_mut().unwrap();
        inputs.tags.insert(
            "object".into(),
            AnnotatedTag {
                has_tagger: true,
                target_kind: "commit".into(),
                message: message.into(),
                commit: "b".repeat(40),
            },
        );
        if let Some(draft) = published {
            inputs.releases.push(ReleaseRecord {
                id: 42,
                tag_name: "sample@0.2.0".into(),
                draft,
                url: "https://example.test/release/42".into(),
            });
        }
        run(&context)
    }

    #[test]
    fn required_release_without_record_is_gap() {
        let verdict = evaluate_with(&model().to_string(), &record("0.2.0"), "tag", None);
        assert_eq!(verdict.status, Some(Status::Gap));
        assert_eq!(verdict.evidence.unwrap().code, "release-record-missing");
    }
    #[test]
    fn published_prereleases_count_and_evidence_uses_object_commit() {
        let verdict = evaluate_with(&model().to_string(), &record("0.2.0"), "tag", Some(false));
        assert_eq!(verdict.status, Some(Status::Met));
        let detail: Value = serde_json::from_str(&verdict.evidence.unwrap().detail).unwrap();
        assert_eq!(detail["releases"][0]["tagged_commit"], "b".repeat(40));
        assert_eq!(detail["releases"][0]["release_record"]["id"], 42);
        assert_eq!(
            detail["releases"][0]["release_record"]["url"],
            "https://example.test/release/42"
        );
        assert_eq!(
            matched_version("{id}@{version}", "sample", "sample@1.2.3-rc.1+build.9"),
            Some("1.2.3-rc.1+build.9".into())
        );
    }
    #[test]
    fn drafts_do_not_count_as_release_records() {
        assert_eq!(
            evaluate_with(&model().to_string(), &record("0.2.0"), "tag", Some(true)).status,
            Some(Status::Gap)
        );
    }
    #[test]
    fn baseline_records_are_excluded() {
        let verdict = evaluate_with(
            &model().to_string(),
            &record("0.2.0").replace("baseline: false", "baseline: true"),
            "tag",
            None,
        );
        assert_eq!(verdict.status, Some(Status::Met));
        assert!(verdict
            .evidence
            .unwrap()
            .detail
            .contains("baseline-tag-record"));
    }
    #[test]
    fn another_tag_identity_is_excluded() {
        let verdict = evaluate_with(
            &model().to_string(),
            &record("0.2.0").replace("sample/primary", "other/primary"),
            "tag",
            None,
        );
        assert_eq!(verdict.status, Some(Status::Met));
        assert!(verdict.evidence.unwrap().detail.contains("tag-id-mismatch"));
    }
    #[test]
    fn another_record_version_is_excluded() {
        let verdict = evaluate_with(&model().to_string(), &record("0.1.8"), "tag", None);
        assert_eq!(verdict.status, Some(Status::Met));
        assert!(verdict
            .evidence
            .unwrap()
            .detail
            .contains("version-mismatch"));
    }
    #[test]
    fn lightweight_and_non_protocol_tags_are_excluded_with_reasons() {
        for (kind, message, reason) in [
            ("commit", record("0.2.0"), "lightweight-tag"),
            ("tag", "ordinary annotation".into(), "not-a-tag-record"),
        ] {
            let verdict = evaluate_with(&model().to_string(), &message, kind, None);
            assert_eq!(verdict.status, Some(Status::Met));
            assert!(verdict.evidence.unwrap().detail.contains(reason));
        }
    }
    #[test]
    fn none_units_are_not_examined_even_when_suspended() {
        let mut model = model();
        model["release_units"]["sample"]["release_record"] = json!("none");
        assert_eq!(
            evaluate_with(&model.to_string(), &record("0.2.0"), "tag", None).status,
            Some(Status::Met)
        );
        let mut other = model["release_units"]["sample"].clone();
        other["release_record"] = json!("required");
        model["release_units"]["other"] = other;
        assert_eq!(
            evaluate_with(&model.to_string(), &record("0.2.0"), "tag", None).status,
            Some(Status::Met)
        );
        model["release_units"]["sample"]["release_record"] = json!("required");
        model["release_units"]["sample"]["disposition"] = json!("suspended");
        assert_eq!(
            evaluate_with(&model.to_string(), &record("0.2.0"), "tag", None).status,
            Some(Status::Gap)
        );
    }
    #[test]
    fn model_syntax_identity_and_schema_failures_are_distinct_gaps() {
        for (text, reason) in [
            ("no JSON".into(), "release-model-unreadable"),
            ("{}".into(), "release-model-schema-not-supported"),
            (
                json!({"$schema": document::MODEL_ID}).to_string(),
                "release-model-unreadable",
            ),
        ] {
            let verdict = evaluate_with(&text, &record("0.2.0"), "tag", None);
            assert_eq!(verdict.status, Some(Status::Gap));
            assert_eq!(verdict.evidence.unwrap().code, reason);
        }
    }
    #[test]
    fn missing_model_is_gap_before_vacuous_met() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let context = context(&snapshot, &policy, vec![]);
        let verdict = run(&context);
        assert_eq!(verdict.status, Some(Status::Gap));
        assert_eq!(verdict.evidence.unwrap().code, "release-model-missing");
    }
    #[test]
    fn truncated_tag_listing_never_becomes_met_or_missing_record() {
        let snapshot = snapshot(&[(MODEL_PATH, &model().to_string())]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, vec![]);
        context.tags = Ok(Paged {
            items: vec![],
            truncated: true,
        });
        let verdict = run(&context);
        assert_eq!(verdict.status, None);
        assert!(verdict
            .error
            .unwrap()
            .endpoint
            .ends_with("/git/matching-refs/tags/"));
        assert!(verdict.evidence.is_none());
    }
    #[test]
    fn release_listing_errors_are_run_errors() {
        for error in [
            complete(true, "GET /repos/owner/name/releases").unwrap_err(),
            ApiError::local(
                ErrorCause::Transport,
                "GET /repos/owner/name/releases",
                "connection failed",
            ),
        ] {
            let snapshot = snapshot(&[(MODEL_PATH, &model().to_string())]);
            let policy = policy();
            let mut context = context(&snapshot, &policy, vec![]);
            context.release_records = Err(error);
            let verdict = run(&context);
            assert_eq!(verdict.status, None);
            assert!(verdict.error.is_some());
        }
    }
    #[test]
    fn templates_match_literals_and_semver_without_implicit_prefix() {
        for name in [
            "sample@v1.2.3",
            "sample@01.2.3",
            "sample@1.2",
            "sample@1.2.3-01",
            "other@1.2.3",
            "sample@1.2.3\n",
        ] {
            assert_eq!(
                matched_version("{id}@{version}", "sample", name),
                None,
                "{name}"
            );
        }
        assert_eq!(
            matched_version("pkg.+/{version}/end", "sample", "pkg.+/1.2.3/end"),
            Some("1.2.3".into())
        );
    }
    #[test]
    fn tag_protocol_rejects_duplicates_order_contract_and_schema_violations() {
        let good = record("0.2.0");
        assert!(document::tag(&good).is_ok());
        for bad in [
            good.replace("contract-1", "contract-2"),
            good.replace("baseline: false", "baseline: false\nbaseline: false"),
            good.replace("generator: intentional 0.2.0\n", ""),
            good.replace("version: 0.2.0", "version: v0.2.0"),
            good.replace("baseline: false", "baseline: no"),
            good.replace("tag-id:", "unknown:"),
        ] {
            assert!(document::tag(&bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn optional_message_target_and_role_do_not_select_the_release() {
        let message = record("0.2.0")
            .replace("version:", "tag-role: projection\nversion:")
            .replace(
                "baseline:",
                &format!("target: {}\nbaseline:", "c".repeat(40)),
            );
        let verdict = evaluate_with(&model().to_string(), &message, "tag", Some(false));
        assert_eq!(verdict.status, Some(Status::Met));
        assert!(verdict.evidence.unwrap().detail.contains(&"b".repeat(40)));
    }

    #[test]
    fn tag_fields_and_prerequisites_are_canonical() {
        let good = record("0.2.0");
        let prerequisite = format!(
            "prerequisite: release-unit/other/primary {}\n",
            "d".repeat(40)
        );
        assert!(document::tag(&format!("{good}{prerequisite}")).is_ok());
        for bad in [
            format!("{good}{prerequisite}{prerequisite}"),
            format!(
                "{good}{prerequisite}{}",
                prerequisite.replace("other/", "another/")
            ),
            good.replace(
                "contract: contract-1\ngenerator: intentional 0.2.0",
                "generator: intentional 0.2.0\ncontract: contract-1",
            ),
            format!("{good}\n"),
        ] {
            assert!(document::tag(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nonregular_model_is_gap_but_unobserved_model_is_run_error() {
        use crate::github::EntryKind;
        for state in [
            FileState::NotAFile {
                kind: EntryKind::Tree,
                mode: "040000".into(),
            },
            FileState::Symlink {
                target: "elsewhere".into(),
            },
        ] {
            let mut snapshot = snapshot(&[]);
            snapshot.files.insert(MODEL_PATH.into(), state);
            let policy = policy();
            let context = context(&snapshot, &policy, vec![]);
            let verdict = run(&context);
            assert_eq!(verdict.status, Some(Status::Gap));
            assert_eq!(verdict.evidence.unwrap().code, "release-model-not-a-file");
        }
        for state in [
            FileState::TreeTruncated,
            FileState::OverBudget {
                size: 100,
                limit: 1,
            },
            FileState::Unreadable(ApiError::local(
                ErrorCause::Transport,
                "GET /blob",
                "failure",
            )),
        ] {
            let mut snapshot = snapshot(&[]);
            snapshot.files.insert(MODEL_PATH.into(), state);
            let policy = policy();
            let context = context(&snapshot, &policy, vec![]);
            let verdict = run(&context);
            assert!(verdict.status.is_none());
            assert!(verdict.error.is_some());
        }
    }
    #[test]
    fn projection_tags_are_not_primary_releases() {
        let mut model = model();
        model["release_units"]["sample"]["tags"]["primary"]["role"] = json!("projection");
        assert_eq!(
            evaluate_with(&model.to_string(), &record("0.2.0"), "tag", None).status,
            Some(Status::Met)
        );
    }

    #[test]
    fn release_record_on_another_tag_does_not_count() {
        let snapshot = snapshot(&[(MODEL_PATH, &model().to_string())]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, vec![]);
        context.tags = Ok(Paged::complete(vec![TagRef {
            name: "sample@0.2.0".into(),
            sha: "object".into(),
            object_type: "tag".into(),
        }]));
        let inputs = context.release_records.as_mut().unwrap();
        inputs.tags.insert(
            "object".into(),
            AnnotatedTag {
                has_tagger: true,
                target_kind: "commit".into(),
                message: record("0.2.0"),
                commit: "b".repeat(40),
            },
        );
        inputs.releases.push(ReleaseRecord {
            id: 42,
            tag_name: "sample@0.1.8".into(),
            draft: false,
            url: "https://example.test/42".into(),
        });
        assert_eq!(run(&context).status, Some(Status::Gap));
    }
}
