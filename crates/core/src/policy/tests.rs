//! Configuration contract tests.
//
// relationships:
//   references: org-config

use super::*;

fn org(extra: &str) -> ResolvedPolicy {
    compile_text(&format!("version: 0.6.0\n{extra}")).unwrap()
}
fn compile_text(text: &str) -> Result<ResolvedPolicy> {
    let document = yaml::parse_mapping(text, Limits::default().yaml).unwrap();
    compilation::compile(
        &PolicySource::Local("org-airlock.yml".into()),
        &document,
        Vec::new(),
    )
}
fn repository(policy: &ResolvedPolicy, text: &str) -> Result<ResolvedPolicy> {
    policy.for_repository("example-org/sample", Some(text), &Limits::default())
}

#[test]
fn organization_and_repository_reject_unknown_and_retired_keys() {
    for key in [
        "name: sample",
        "checks: {}",
        "rules: {}",
        "capabilities: {}",
        "apply: {}",
        "suppressions: {}",
        "reference-data: {}",
        "requires-rules: '>=0.1'",
        "surprise: true",
    ] {
        assert!(
            compile_text(&format!("version: 0.6.0\n{key}\n")).is_err(),
            "accepted {key}"
        );
        assert!(
            repository(&org(""), &format!("version: 0.6.0\n{key}\n")).is_err(),
            "accepted repository {key}"
        );
    }
    assert!(compile_text(
        "version: 0.6.0\nexceptions:\n  REPO-LIC-01: {reason: Sample, enabled: false}\n"
    )
    .is_err());
}
#[test]
fn exceptions_require_known_rules_and_nonempty_reasons_and_valid_parameters() {
    for extra in [
        "exceptions: {REPO-LIC-01: {severity: none}}",
        "exceptions: {REPO-LIC-01: {reason: ' ', severity: none}}",
        "exceptions: {UNKNOWN: {reason: Sample}}",
        "exceptions: {REPO-LIC-01: {reason: Sample, allow-override: wrong}}",
        "exceptions: {REPO-LIC-01: {reason: Sample, severity: severe}}",
        "exceptions: {REPO-META-06: {reason: Sample, min-topics: wrong}}",
        "exceptions: {REPO-LIC-01: {reason: Sample, parameter: wrong}}",
        "exceptions: {REPO-META-07: {reason: Sample, topics: {ecosystem: [42]}}}",
    ] {
        assert!(
            compile_text(&format!("version: 0.6.0\n{extra}\n")).is_err(),
            "accepted {extra}"
        );
    }
}
#[test]
fn config_does_not_select_rules() {
    let policy = org("");
    assert_eq!(policy.rules.len(), rules::RULES.len());
    assert!(policy.rules.windows(2).all(|r| r[0].def.id < r[1].def.id));
}
#[test]
fn repository_generation_cannot_lag_organization() {
    let policy = org("");
    let error = repository(&policy, "version: 0.5.0\n").unwrap_err();
    assert!(error.to_string().contains("below organization version"));
    assert_eq!(
        repository(&policy, "version: 0.7.0\n")
            .unwrap()
            .accepted_version,
        semver::Version::new(0, 7, 0)
    );
    assert!(repository(&policy, "description: Sample\n").is_err());
    assert!(compile_text("version: 1\n").is_err());
}
#[test]
fn declarations_and_requests_share_repository_file() {
    let result = repository(&org(""), "version: 0.6.0\ndescription: Sample\ntopics: [cli, rust]\nmerge: {squash: true}\nfeatures: {wiki: false}\nexceptions:\n  REPO-DOCS-01: {reason: Small utility, severity: none}\n").unwrap();
    assert_eq!(
        result.rule("REPO-DOCS-01").unwrap().severity,
        Severity::None
    );
    assert!(compile_text("version: 0.6.0\ndescription: Sample\n").is_err());
}
#[test]
fn repository_scoped_exception_uses_exact_full_name_and_keeps_reason() {
    let policy = org("exceptions:\n  REPO-LIC-01:\n    reason: Default license check\n    repositories:\n      example-org/sample: {reason: License review, severity: none}\n");
    let selected = repository(&policy, "version: 0.6.0\n").unwrap();
    assert_eq!(
        selected.rule("REPO-LIC-01").unwrap().severity,
        Severity::None
    );
    assert_eq!(
        selected
            .suppressions
            .direct_for("REPO-LIC-01", "example-org/sample")
            .unwrap()
            .reason,
        "License review"
    );
    let other = policy
        .for_repository("another-org/sample", None, &Limits::default())
        .unwrap();
    assert_eq!(
        other.rule("REPO-LIC-01").unwrap().severity,
        Severity::Blocking
    );
}
#[test]
fn organization_can_tighten_but_not_loosen_compiled_override_permission() {
    assert!(!rules::find("REPO-TPL-01").unwrap().allow_override());
    assert!(compile_text(
        "version: 0.6.0\nexceptions:\n  REPO-TPL-01: {reason: Sample, allow-override: true}\n"
    )
    .is_err());
    let policy =
        org("exceptions:\n  REPO-LIC-01: {reason: Organization decision, allow-override: false}\n");
    let result = repository(
        &policy,
        "version: 0.6.0\nexceptions:\n  REPO-LIC-01: {reason: Request, severity: none}\n",
    )
    .unwrap();
    assert_eq!(
        result.rule("REPO-LIC-01").unwrap().severity,
        Severity::Blocking
    );
    assert!(!result
        .suppressions
        .allow_repo_requests
        .contains("REPO-LIC-01"));
}
#[test]
fn permitted_repository_parameters_and_severity_are_requests() {
    let policy = org("");
    let result = repository(&policy, "version: 0.6.0\nexceptions:\n  REPO-META-06: {reason: Fewer topics, min-topics: 1, severity: advisory}\n").unwrap();
    assert_eq!(
        result.rule("REPO-META-06").unwrap().param_u64("min-topics"),
        Some(1)
    );
    assert_eq!(
        result.rule("REPO-META-06").unwrap().severity,
        Severity::Advisory
    );
}
#[test]
fn repository_cannot_set_override_authority() {
    let result = repository(&org(""), "version: 0.6.0\nexceptions:\n  REPO-LIC-01: {reason: Request, allow-override: true, severity: none}\n").unwrap();
    assert_eq!(
        result.rule("REPO-LIC-01").unwrap().severity,
        Severity::Blocking
    );
    assert!(!result
        .suppressions
        .allow_repo_requests
        .contains("REPO-LIC-01"));
}
#[test]
fn required_configuration_is_visibly_not_asked_until_supplied() {
    let policy = org("");
    for id in ["REPO-META-07", "REPO-META-09", "REPO-TPL-01"] {
        assert_eq!(policy.rule(id).unwrap().severity, Severity::None);
    }
    let configured = org("exceptions:\n  REPO-META-07: {reason: Vocabulary, topics: {artifact-type: [cli], ecosystem: [rust]}}\n");
    assert_eq!(
        configured.rule("REPO-META-07").unwrap().severity,
        Severity::Advisory
    );
}
#[test]
fn template_configuration_shape_and_compiled_prohibition_are_preserved() {
    let valid = "version: 0.6.0\nexceptions:\n  REPO-TPL-01:\n    reason: Expected process\n    templates: [{source: 'gh:example-org/catalog#bundle', ref: main, parts: [alpha]}]\n";
    assert_eq!(
        compile_text(valid)
            .unwrap()
            .rule("REPO-TPL-01")
            .unwrap()
            .severity,
        Severity::Blocking
    );
    for input in [
        valid.replace("ref: main", "wrong: main"),
        valid.replace("ref: main", "ref: ''"),
        valid.replace("parts: [alpha]", "parts: [alpha, alpha]"),
        valid.replace("ref: main", "ref: main, target: ../elsewhere"),
    ] {
        assert!(compile_text(&input).is_err());
    }
    let result = repository(
        &compile_text(valid).unwrap(),
        "version: 0.6.0\nexceptions:\n  REPO-TPL-01: {reason: Request, severity: none}\n",
    )
    .unwrap();
    assert_eq!(
        result.rule("REPO-TPL-01").unwrap().severity,
        Severity::Blocking
    );
}

fn local_client() -> crate::github::RestClient {
    crate::github::RestClient::new(
        "fixture",
        crate::github::RestClientConfig {
            base_url: "http://127.0.0.1:9".into(),
            max_rate_limit_retries: 0,
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn topic_parameters_resolve_and_pin_local_sources_under_one_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    let vocabulary = "artifact-type: [cli]\necosystem: [rust]\n";
    std::fs::write(dir.path().join("topics.yml"), vocabulary).unwrap();
    let text = "version: 0.6.0\nexceptions:\n  REPO-META-07: {reason: Vocabulary, topics: ./topics.yml}\n  REPO-META-09: {reason: Vocabulary, topics: ./topics.yml}\n";
    let source = PolicySource::Local(dir.path().join("airlock.yml"));
    std::fs::write(dir.path().join("airlock.yml"), text).unwrap();
    let policy = resolve(&local_client(), &source, &Limits::default())
        .await
        .unwrap();
    assert_eq!(policy.sources.len(), 3);
    assert_eq!(
        policy.rule("REPO-META-07").unwrap().params["topics"]["ecosystem"][0],
        "rust"
    );
    let limits = Limits {
        max_total_bytes: text.len() + vocabulary.len() * 2 - 1,
        ..Limits::default()
    };
    assert!(resolve(&local_client(), &source, &limits)
        .await
        .unwrap_err()
        .to_string()
        .contains("budget"));
}

#[tokio::test]
async fn topic_reference_count_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("topics.yml"), "ecosystem: [rust]\n").unwrap();
    std::fs::write(dir.path().join("airlock.yml"), "version: 0.6.0\nexceptions:\n  REPO-META-07: {reason: Vocabulary, topics: ./topics.yml}\n  REPO-META-09: {reason: Vocabulary, topics: ./topics.yml}\n").unwrap();
    let limits = Limits {
        max_policy_references: 1,
        ..Limits::default()
    };
    let error = resolve(
        &local_client(),
        &PolicySource::Local(dir.path().join("airlock.yml")),
        &limits,
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("too many topic vocabulary references"));
}

#[tokio::test]
async fn topic_reference_cycles_and_depth_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("airlock.yml"),
        "version: 0.6.0\nexceptions:\n  REPO-META-07: {reason: Vocabulary, topics: ./first.yml}\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("first.yml"), "./second.yml\n").unwrap();
    std::fs::write(dir.path().join("second.yml"), "ecosystem: [rust]\n").unwrap();
    let source = PolicySource::Local(dir.path().join("airlock.yml"));
    let limits = Limits {
        max_policy_reference_depth: 0,
        ..Limits::default()
    };
    assert!(resolve(&local_client(), &source, &limits)
        .await
        .unwrap_err()
        .to_string()
        .contains("too deep"));
    std::fs::write(dir.path().join("second.yml"), "./first.yml\n").unwrap();
    assert!(resolve(&local_client(), &source, &Limits::default())
        .await
        .unwrap_err()
        .to_string()
        .contains("cyclic"));
}

#[tokio::test]
async fn remote_topic_parameters_cannot_read_local_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("topics.yml");
    std::fs::write(&path, "ecosystem: [rust]\n").unwrap();
    let mut document = yaml::parse_mapping(
        &format!(
            "exceptions:\n  REPO-META-07: {{reason: Vocabulary, topics: {}}}\n",
            path.display()
        ),
        Limits::default().yaml,
    )
    .unwrap();
    let root = PolicySource::default_for_owner("example-org");
    let error = references::resolve_references(
        &local_client(),
        &root,
        &mut document,
        &Limits::default(),
        &mut Vec::new(),
        &mut ByteBudget::new(1024),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("remote config cannot reference the local file"));
}

#[test]
fn compiled_policy_reads_defaults_from_each_rule() {
    let policy = compile_text("version: 0.6.0\n").unwrap();
    let rule = |id| policy.rules.iter().find(|rule| rule.def.id == id).unwrap();
    assert_eq!(rule("REPO-META-06").param_u64("min-topics"), Some(3));
    assert_eq!(rule("REPO-META-06").param_u64("max-topics"), Some(8));
    assert_eq!(
        rule("REPO-META-10").param_strings("org-names").unwrap(),
        Some(vec![])
    );
    assert_eq!(rule("REPO-GIT-10").param_u64("max-commits"), Some(1000));
    assert_eq!(
        rule("REPO-CD-02").param_str("tag-pattern"),
        Some("[0-9]*.[0-9]*.[0-9]*")
    );
    assert_eq!(
        rule("REPO-CD-02")
            .param_str_for_owner("tag-pattern", None)
            .as_deref(),
        Some("[0-9]*.[0-9]*.[0-9]*")
    );
    assert_eq!(
        rule("REPO-FILE-08")
            .param_str_for_owner("renovate-preset", Some("example-org"))
            .as_deref(),
        Some("github>example-org/.github")
    );
    assert_eq!(
        rule("REPO-FILE-13")
            .param_strings("forbidden-paths")
            .unwrap()
            .unwrap(),
        [
            ".claude",
            ".cursor",
            ".windsurf",
            ".codex",
            ".aider.conf.yml",
            ".github/copilot-instructions.md"
        ]
    );
    // Defaults are compiled metadata, not new policy refinements or digest inputs.
    assert!(policy.rules.iter().all(|rule| rule.params.is_empty()));
}

#[test]
fn only_defaults_substitute_the_owner_and_only_as_literal_text() {
    let policy = compile_text("version: 0.6.0\n").unwrap();
    let mut rule = policy
        .rules
        .into_iter()
        .find(|rule| rule.def.id == "REPO-FILE-08")
        .unwrap();
    assert_eq!(rule.param_str_for_owner("renovate-preset", None), None);
    assert_eq!(rule.param_str_for_owner("renovate-preset", Some("")), None);
    assert_eq!(
        rule.param_str_for_owner("renovate-preset", Some("{repo}-$org"))
            .as_deref(),
        Some("github>{repo}-$org/.github")
    );
    rule.params.insert(
        "renovate-preset".into(),
        serde_json::json!("github>{owner}/{repo}"),
    );
    assert_eq!(
        rule.param_str_for_owner("renovate-preset", Some("example-org"))
            .as_deref(),
        Some("github>{owner}/{repo}")
    );
    assert_eq!(
        rule.param_str_for_owner("renovate-preset", None).as_deref(),
        Some("github>{owner}/{repo}")
    );
}

#[test]
fn explicit_empty_lists_override_defaults_and_malformed_lists_are_errors() {
    let policy = compile_text("version: 0.6.0\n").unwrap();
    let mut rule = policy
        .rules
        .into_iter()
        .find(|rule| rule.def.id == "REPO-FILE-13")
        .unwrap();
    rule.params
        .insert("forbidden-paths".into(), serde_json::json!([]));
    assert_eq!(rule.param_strings("forbidden-paths").unwrap(), Some(vec![]));
    rule.params
        .insert("forbidden-paths".into(), serde_json::Value::Null);
    assert!(rule.param_strings("forbidden-paths").is_err());
    assert_eq!(rule.param_u64("unknown"), None);
    assert_eq!(rule.param_str("unknown"), None);
    assert_eq!(rule.param_strings("unknown").unwrap(), None);
}

#[test]
fn policy_sources_parse() {
    assert_eq!(
        PolicySource::parse("owner/repo:airlock/policy.yml").unwrap(),
        PolicySource::Remote {
            owner: "owner".to_owned(),
            repo: "repo".to_owned(),
            path: "airlock/policy.yml".to_owned(),
            reference: None,
        }
    );
    assert_eq!(
        PolicySource::parse("owner/repo:airlock/policy.yml@v1").unwrap(),
        PolicySource::Remote {
            owner: "owner".to_owned(),
            repo: "repo".to_owned(),
            path: "airlock/policy.yml".to_owned(),
            reference: Some("v1".to_owned()),
        }
    );
    assert_eq!(
        PolicySource::parse("./policy.yml").unwrap(),
        PolicySource::Local(PathBuf::from("./policy.yml"))
    );
    assert!(PolicySource::parse("just-a-word").is_err());
}

#[test]
fn the_default_source_is_the_owners_dot_github_repository() {
    assert_eq!(
        PolicySource::default_for_owner("example-org").label(),
        "example-org/.github:.github/airlock.yml"
    );
}

#[test]
fn the_bundle_budget_is_aggregate_not_per_file() {
    let mut budget = ByteBudget::new(100);
    assert_eq!(budget.cap_for(80), 80);
    budget.spend("first", 80).unwrap();
    // The second file is individually legal at 80 bytes, but the bundle
    // has only 20 left, so that is the cap it faces.
    assert_eq!(budget.cap_for(80), 20);
    let error = budget.spend("second", 80).unwrap_err().to_string();
    assert!(error.contains("policy bundle exceeds its 100 byte budget"));
    assert!(error.contains("second"));
}

#[test]
fn the_bundle_budget_admits_files_that_fit_together() {
    let mut budget = ByteBudget::new(100);
    budget.spend("first", 60).unwrap();
    budget.spend("second", 40).unwrap();
    assert_eq!(budget.remaining(), 0);
    assert_eq!(budget.cap_for(1_000), 0);
}

#[test]
fn organization_scoped_override_tightening_is_respected() {
    let policy = org("exceptions:\n  REPO-META-06:\n    reason: Topic convention\n    repositories:\n      example-org/sample: {reason: Organization decision, allow-override: false}\n");
    let request =
        "version: 0.6.0\nexceptions:\n  REPO-META-06: {reason: Fewer topics, min-topics: 1}\n";
    let selected = repository(&policy, request).unwrap();
    assert_eq!(
        selected
            .rule("REPO-META-06")
            .unwrap()
            .param_u64("min-topics"),
        Some(3)
    );
    let other = policy
        .for_repository("example-org/other", Some(request), &Limits::default())
        .unwrap();
    assert_eq!(
        other.rule("REPO-META-06").unwrap().param_u64("min-topics"),
        Some(1)
    );
}

#[test]
fn required_repository_parameter_enables_only_requested_rule() {
    let result = repository(&org(""), "version: 0.6.0\nexceptions:\n  REPO-META-07: {reason: Vocabulary, topics: {artifact-type: [cli], ecosystem: [rust]}}\n").unwrap();
    assert_eq!(
        result.rule("REPO-META-07").unwrap().severity,
        Severity::Advisory
    );
    assert_eq!(
        result.rule("REPO-META-09").unwrap().severity,
        Severity::None
    );
}

#[test]
fn scoped_required_configuration_enables_only_matching_repository() {
    let policy = org("exceptions:\n  REPO-TPL-01:\n    reason: Expected process\n    repositories:\n      example-org/sample:\n        reason: Governed repository\n        templates: [{source: 'gh:example-org/catalog#bundle', ref: main}]\n");
    assert_eq!(
        repository(&policy, "version: 0.6.0\n")
            .unwrap()
            .rule("REPO-TPL-01")
            .unwrap()
            .severity,
        Severity::Blocking
    );
    assert_eq!(
        policy
            .for_repository("example-org/other", None, &Limits::default())
            .unwrap()
            .rule("REPO-TPL-01")
            .unwrap()
            .severity,
        Severity::None
    );
}

#[test]
fn repository_declarations_reject_unknown_nested_keys() {
    for field in [
        "merge: {unknown: true}",
        "features: {unknown: true}",
        "merge: false",
        "features: []",
    ] {
        assert!(repository(&org(""), &format!("version: 0.6.0\n{field}\n")).is_err());
    }
}
