// ---
// relationships:
//   verifies: configurable-rules
// ---

use airlock_core::{
    configurable::{
        audit,
        config::*,
        evaluation::{Decision, Evaluation, EvaluationInput, Evaluations},
        probe::{ProbeProvider, ProbeSchema, RepositoryTarget},
        report::*,
        RepositoryInput,
    },
    limits::DEFAULT_YAML_LIMITS,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Facts {
    calls: Vec<ProbeRequest>,
    broken: bool,
    bad_output: bool,
    score: i64,
}
impl ProbeProvider for Facts {
    fn schema(&self, kind: &str) -> Option<ProbeSchema> {
        match kind {
            "facts" | "unused" => Some(ProbeSchema {
                input: json!({"type":"object","additionalProperties":false}),
                output: json!({"type":"object","required":["score","component","name"]}),
            }),
            _ => None,
        }
    }
    async fn observe(
        &mut self,
        target: &RepositoryTarget,
        request: &ProbeRequest,
    ) -> Result<Value, String> {
        self.calls.push(request.clone());
        if self.broken {
            return Err("observation unavailable".into());
        }
        if self.bad_output {
            return Ok(Value::Null);
        }
        Ok(json!({"score":self.score,"component":"true","name":target.name}))
    }
}
fn source(repo: &str, commit: &str) -> ConfigSource {
    ConfigSource {
        repository: repo.into(),
        path: ".github/airlock.yml".into(),
        commit: commit.repeat(40),
    }
}
fn snapshot<T: serde::de::DeserializeOwned>(
    source: ConfigSource,
    document: Value,
) -> ConfigSnapshot<T> {
    ConfigSnapshot::load(
        source,
        &serde_norway::to_string(&document).unwrap(),
        DEFAULT_YAML_LIMITS,
    )
    .unwrap()
}
fn condition(pointer: &str, evaluation: &str, floor: Value, value: Value) -> Value {
    json!({"probe":"observed","pointer":pointer,"evaluation":evaluation,"setting":{"floor":floor,"value":value}})
}
fn rule(min: i64) -> Value {
    json!({"statement":"The sample meets the configured measure.","probes":{"observed":{"kind":"facts","input":{}}},"conditions":[condition("/score","minimum",json!(3),json!(min))],"severity":{"floor":"advisory","value":"blocking"}})
}
fn org(rules: Value, references: Vec<&str>) -> ConfigSnapshot<OrganizationConfig> {
    snapshot(
        source("sample/.github", "a"),
        json!({"rules":rules,"assignments":{"selected":{"probes":{"observed":{"kind":"facts","input":{}}},"conditions":[condition("/component","equal",json!("true"),json!("true"))],"rules":references}}}),
    )
}
fn input(rules: Option<Value>) -> RepositoryInput {
    RepositoryInput {
        target: RepositoryTarget {
            owner: "sample".into(),
            name: "sample-kit".into(),
            commit: "c".repeat(40),
            maturity: Lifecycle::Building,
        },
        config: rules
            .map(|rules| snapshot(source("sample/sample-kit", "b"), json!({"rules":rules}))),
    }
}
async fn run(
    org: &ConfigSnapshot<OrganizationConfig>,
    input: RepositoryInput,
    score: i64,
) -> (Report, Facts) {
    let mut facts = Facts {
        score,
        ..Facts::default()
    };
    let report = audit(
        "sample",
        org,
        &[input],
        &mut facts,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    (report, facts)
}
fn only(report: &Report) -> &RuleResult {
    &report.repositories[0].rules[0]
}

#[tokio::test]
async fn duplicate_assignments_share_one_org_instance_and_only_demand_needed_facts() {
    let mut org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    org.document.assignments.insert(
        "also-selected".into(),
        org.document.assignments["selected"].clone(),
    );
    org.document.rules.insert(
        "unassigned-rule".into(),
        json!({"statement":"never demanded","probes":{"x":{"kind":"unused","input":{}}}}),
    );
    let (report, facts) = run(&org, input(None), 5).await;
    assert_eq!(report.repositories[0].rules.len(), 1);
    assert_eq!(only(&report).instances.len(), 1);
    assert_eq!(only(&report).flavor, Flavor::Gap);
    assert_eq!(facts.calls.len(), 1);
    assert_eq!(facts.calls[0].kind, "facts");
    assert_eq!(report.organization_config.commit, "a".repeat(40));
    assert_eq!(only(&report).instances[0].config_commit, "a".repeat(40));
}

#[tokio::test]
async fn reason_selects_parent_floor_and_keeps_both_instances_and_commits() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut child = rule(4);
    child["reason"] = json!("A smaller initial sample is sufficient.");
    let (report, _) = run(&org, input(Some(json!({"sample-measure":child}))), 5).await;
    let result = only(&report);
    assert_eq!(result.flavor, Flavor::Passed);
    assert_eq!(result.instances.len(), 2);
    assert_eq!(result.instances[0].mode, Mode::Floor);
    assert_eq!(result.instances[0].conditions[0].expected, json!(3));
    assert_eq!(
        result.instances[0].relaxation_reason.as_deref(),
        Some("A smaller initial sample is sufficient.")
    );
    assert_eq!(result.instances[1].config_commit, "b".repeat(40));
    assert_eq!(
        report.repositories[0]
            .repository_config
            .as_ref()
            .unwrap()
            .commit,
        "b".repeat(40)
    );
    assert!(report.repositories[0].warnings.is_empty());
}

#[tokio::test]
async fn missing_or_blank_reason_retains_parent_value_and_warns() {
    for reason in [Value::Null, json!(" ")] {
        let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
        let mut child = rule(4);
        child["reason"] = reason;
        let (report, _) = run(&org, input(Some(json!({"sample-measure":child}))), 5).await;
        assert_eq!(only(&report).flavor, Flavor::Gap);
        assert_eq!(only(&report).instances[0].mode, Mode::Value);
        assert_eq!(only(&report).instances[0].conditions[0].expected, json!(6));
        assert_eq!(
            report.repositories[0].warnings[0].code,
            "relaxation-without-reason"
        );
    }
}

#[tokio::test]
async fn child_below_floor_cannot_bypass_parent_and_no_refusal_occurs() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut child = rule(2);
    child["conditions"][0]["setting"]["floor"] = json!(1);
    child["reason"] = json!("Small trial.");
    let (report, _) = run(&org, input(Some(json!({"sample-measure":child}))), 2).await;
    assert_eq!(only(&report).flavor, Flavor::Gap);
    assert_eq!(only(&report).instances[0].flavor, Flavor::Gap);
    assert_eq!(only(&report).instances[1].flavor, Flavor::Passed);
    assert_eq!(only(&report).severity, Severity::Advisory);
}

#[tokio::test]
async fn stricter_child_can_fail_with_no_relaxation_warning() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let (report, _) = run(&org, input(Some(json!({"sample-measure":rule(9)}))), 7).await;
    assert_eq!(only(&report).instances[0].flavor, Flavor::Passed);
    assert_eq!(only(&report).instances[1].flavor, Flavor::Gap);
    assert_eq!(only(&report).result, ResultKind::Fail);
    assert!(report.repositories[0].warnings.is_empty());
}

#[tokio::test]
async fn highest_failing_severity_ignores_stronger_passing_instance() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut child = rule(9);
    child["severity"] = json!({"floor":"advisory","value":"advisory"});
    let (report, _) = run(
        &org,
        input(Some(json!({"sample-measure":child.clone()}))),
        7,
    )
    .await;
    assert_eq!(only(&report).severity, Severity::Advisory);
    let (report, _) = run(&org, input(Some(json!({"sample-measure":child}))), 5).await;
    assert_eq!(only(&report).severity, Severity::Blocking);
}

#[tokio::test]
async fn invalid_rules_and_child_are_visible_and_do_not_stop_valid_siblings() {
    let mut unknown_probe = rule(6);
    unknown_probe["probes"]["observed"]["kind"] = json!("not-coded");
    let mut bad_input = rule(6);
    bad_input["probes"]["observed"]["input"] = json!({"surprise":true});
    let mut unknown_eval = rule(6);
    unknown_eval["conditions"][0]["evaluation"] = json!("not-coded");
    let mut bad_setting = rule(6);
    bad_setting["conditions"][0]["setting"]["value"] = json!("six");
    let rules = json!({"good":rule(6),"unknown-probe":unknown_probe,"bad-input":bad_input,"unknown-eval":unknown_eval,"bad-setting":bad_setting,"bad-shape":[],"empty-conditions":{"conditions":[]}});
    let org = org(
        rules,
        vec![
            "good",
            "unknown-probe",
            "bad-input",
            "unknown-eval",
            "bad-setting",
            "bad-shape",
            "empty-conditions",
            "undefined",
        ],
    );
    let (report, facts) = run(
        &org,
        input(Some(
            json!({"good":{"reason":"Cannot use this to bypass a parent."}}),
        )),
        5,
    )
    .await;
    assert_eq!(report.repositories[0].rules.len(), 8);
    for result in &report.repositories[0].rules {
        assert_eq!(result.result, ResultKind::Fail);
        assert_eq!(result.flavor, Flavor::NotEvaluated);
        assert!(result.instances.iter().any(|i| i
            .diagnostic
            .as_ref()
            .is_some_and(|d| d.code == "invalid-rule")));
    }
    let good = report.repositories[0]
        .rules
        .iter()
        .find(|r| r.id == "good")
        .unwrap();
    assert_eq!(good.instances[0].mode, Mode::Value);
    assert_eq!(good.instances[0].flavor, Flavor::Gap);
    assert_eq!(facts.calls.len(), 1);
}

#[tokio::test]
async fn unassigned_repo_is_report_only_even_with_local_rules() {
    let mut org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    org.document
        .assignments
        .get_mut("selected")
        .unwrap()
        .conditions[0]
        .setting = Setting {
        floor: json!("false"),
        value: json!("false"),
    };
    let (report, facts) = run(&org, input(Some(json!({"local":rule(6)}))), 5).await;
    assert_eq!(report.unassigned_repositories, vec!["sample/sample-kit"]);
    assert!(report.repositories[0].rules.is_empty());
    assert_eq!(facts.calls.len(), 1);
}

#[tokio::test]
async fn assignment_observation_failure_is_visible_and_never_claims_unassigned() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    for bad_output in [false, true] {
        let mut facts = Facts {
            broken: !bad_output,
            bad_output,
            ..Facts::default()
        };
        let report = audit(
            "sample",
            &org,
            &[input(None)],
            &mut facts,
            &Evaluations::built_in(),
        )
        .await
        .unwrap();
        assert!(report.unassigned_repositories.is_empty());
        assert!(report.repositories[0].rules.is_empty());
        assert_eq!(report.repositories[0].assignments[0].matched, None);
        assert_eq!(
            report.repositories[0].assignments[0]
                .diagnostic
                .as_ref()
                .unwrap()
                .code,
            if bad_output {
                "invalid-probe-output"
            } else {
                "probe-failed"
            }
        );
    }
}

#[tokio::test]
async fn assignments_match_globs_and_arbitrary_fact_paths() {
    let mut org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    org.document
        .assignments
        .get_mut("selected")
        .unwrap()
        .conditions
        .push(
            serde_json::from_value(condition(
                "/name",
                "glob",
                json!("sample-*"),
                json!("sample-*"),
            ))
            .unwrap(),
        );
    let (report, _) = run(&org, input(None), 7).await;
    assert_eq!(report.repositories[0].assignments[0].matched, Some(true));
    assert_eq!(only(&report).flavor, Flavor::Passed);
}

#[tokio::test]
async fn maturity_selects_configured_severity_without_config_edit() {
    let mut r = rule(6);
    r["severity"] = json!({"seeded":{"floor":"none","value":"advisory"},"building":{"floor":"advisory","value":"advisory"},"released":{"floor":"blocking","value":"blocking"},"stable":{"floor":"blocking","value":"blocking"}});
    let org = org(json!({"sample-measure":r}), vec!["sample-measure"]);
    let (building, _) = run(&org, input(None), 5).await;
    let mut released = input(None);
    released.target.maturity = Lifecycle::Released;
    let (released, _) = run(&org, released, 5).await;
    assert_eq!(only(&building).severity, Severity::Advisory);
    assert_eq!(only(&released).severity, Severity::Blocking);
    assert_eq!(
        building.organization_config.commit,
        released.organization_config.commit
    );
}

struct Counting {
    calls: Arc<Mutex<Vec<usize>>>,
    wrong_size: bool,
}
impl Evaluation for Counting {
    fn input_schema(&self) -> Value {
        json!({"type":"number"})
    }
    fn batch_capable(&self) -> bool {
        true
    }
    fn evaluate(
        &self,
        output: &Value,
        requests: &[EvaluationInput],
    ) -> Vec<Result<Decision, String>> {
        self.calls.lock().unwrap().push(requests.len());
        if self.wrong_size {
            return vec![];
        }
        requests
            .iter()
            .map(|r| {
                Ok(Decision {
                    passed: output.pointer(&r.pointer) == Some(&r.expected),
                    reason: "batch result".into(),
                })
            })
            .collect()
    }
    fn relaxes(&self, parent: &Value, child: &Value) -> Option<bool> {
        if parent == child {
            Some(false)
        } else {
            None
        }
    }
}

#[tokio::test]
async fn evaluation_batches_same_output_and_type_and_routes_each_answer() {
    let mut a = rule(5);
    a["conditions"][0] = condition("/score", "counting", json!(5), json!(5));
    let mut b = rule(6);
    b["conditions"][0] = condition("/score", "counting", json!(6), json!(6));
    let org = org(json!({"first":a,"second":b}), vec!["first", "second"]);
    for wrong_size in [false, true] {
        let calls = Arc::new(Mutex::new(vec![]));
        let mut evaluations = Evaluations::built_in();
        evaluations.register(
            "counting",
            Box::new(Counting {
                calls: calls.clone(),
                wrong_size,
            }),
        );
        let mut facts = Facts {
            score: 5,
            ..Facts::default()
        };
        let report = audit("sample", &org, &[input(None)], &mut facts, &evaluations)
            .await
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![2]);
        if wrong_size {
            assert!(report.repositories[0]
                .rules
                .iter()
                .all(|r| r.flavor == Flavor::NotEvaluated));
        } else {
            assert_eq!(report.repositories[0].rules[0].flavor, Flavor::Passed);
            assert_eq!(report.repositories[0].rules[1].flavor, Flavor::Gap);
        }
    }
}

#[tokio::test]
async fn org_repo_override_can_waive_with_reason_but_invalid_override_keeps_parent() {
    let mut org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut waived = rule(6);
    waived["reason"] = json!("Temporary small sample.");
    waived["severity"] = json!({"floor":"none","value":"none"});
    org.document.repositories.insert(
        "sample/sample-kit".into(),
        BTreeMap::from([("sample-measure".into(), waived)]),
    );
    let (report, _) = run(&org, input(None), 5).await;
    assert_eq!(only(&report).flavor, Flavor::Waived);
    org.document
        .repositories
        .get_mut("sample/sample-kit")
        .unwrap()
        .get_mut("sample-measure")
        .unwrap()["reason"] = Value::Null;
    let (report, _) = run(&org, input(None), 5).await;
    assert_eq!(only(&report).instances.len(), 2);
    assert!(only(&report)
        .instances
        .iter()
        .any(|i| i.flavor == Flavor::Gap));
    assert!(only(&report).instances.iter().any(|i| i
        .diagnostic
        .as_ref()
        .is_some_and(|d| d.code == "invalid-rule")));
}

#[tokio::test]
async fn scope_failures_make_no_probe_calls() {
    let org = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut foreign = input(None);
    foreign.target.owner = "another".into();
    let mut facts = Facts::default();
    assert!(audit(
        "sample",
        &org,
        &[foreign],
        &mut facts,
        &Evaluations::built_in()
    )
    .await
    .is_err());
    let mut wrong_source = input(Some(json!({})));
    wrong_source.config.as_mut().unwrap().source.repository = "sample/another-repo".into();
    assert!(audit(
        "sample",
        &org,
        &[wrong_source],
        &mut facts,
        &Evaluations::built_in()
    )
    .await
    .is_err());
    assert!(facts.calls.is_empty());
}

#[test]
fn config_loader_reuses_duplicate_key_and_budget_guards() {
    let bad = "rules: {}\nrules: {}\nassignments: {}\n";
    assert!(ConfigSnapshot::<OrganizationConfig>::load(
        source("sample/.github", "a"),
        bad,
        DEFAULT_YAML_LIMITS
    )
    .unwrap_err()
    .contains("duplicate"));
    let mut limits = DEFAULT_YAML_LIMITS;
    limits.max_bytes = 1;
    assert!(ConfigSnapshot::<OrganizationConfig>::load(
        source("sample/.github", "a"),
        "rules: {}\nassignments: {}",
        limits
    )
    .is_err());
}

fn file_rule(pointer: &str, expected: Value) -> Value {
    let mut rule = rule(6);
    rule["probes"] =
        json!({"observed":{"kind":"file-content","input":{"path":"assets/handbook.txt"}}});
    rule["conditions"] = json!([condition(pointer, "equal", expected.clone(), expected)]);
    rule
}
fn catch_all(rules: Value, refs: Vec<&str>) -> ConfigSnapshot<OrganizationConfig> {
    let mut result = org(rules, refs);
    let assignment = result.document.assignments.get_mut("selected").unwrap();
    assignment.probes.clear();
    assignment.conditions.clear();
    result
}
fn api_client(server: &wiremock::MockServer) -> airlock_core::github::RestClient {
    airlock_core::github::RestClient::new(
        "ghu_fixture_token",
        airlock_core::github::RestClientConfig {
            base_url: server.uri(),
            max_rate_limit_retries: 0,
            ..Default::default()
        },
    )
    .unwrap()
}
async fn tree_mock(server: &wiremock::MockServer, entries: Value, truncated: bool) {
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, ResponseTemplate,
    };
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/sample/sample-kit/git/trees/{}",
            "c".repeat(40)
        )))
        .and(query_param("recursive", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"sha":"c".repeat(40),"tree":entries,"truncated":truncated})),
        )
        .expect(1)
        .mount(server)
        .await;
}
async fn blob_mock(server: &wiremock::MockServer, bytes: &[u8]) {
    use base64::Engine;
    use wiremock::{
        matchers::{method, path},
        Mock, ResponseTemplate,
    };
    Mock::given(method("GET")).and(path(format!("/repos/sample/sample-kit/git/blobs/{}","d".repeat(40))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sha":"d".repeat(40),"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(bytes),"size":bytes.len()}))).expect(1).mount(server).await;
}

#[tokio::test]
async fn github_file_content_derives_a_coded_fix_and_uses_only_pinned_reads() {
    use airlock_core::configurable::probe::GitHubProbes;
    let server = wiremock::MockServer::start().await;
    tree_mock(&server,json!([{"path":"assets/handbook.txt","mode":"100644","type":"blob","sha":"d".repeat(40),"size":6}]),false).await;
    blob_mock(&server, b"sample").await;
    let org = catch_all(
        json!({"handbook":file_rule("/contents",json!("expected sample"))}),
        vec!["handbook"],
    );
    let client = api_client(&server);
    let mut probes = GitHubProbes::new(&client, Default::default());
    let report = audit(
        "sample",
        &org,
        &[input(None)],
        &mut probes,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    assert_eq!(only(&report).flavor, Flavor::Gap);
    assert!(
        matches!(&only(&report).instances[0].fixes[0],Fix::Action { fixer:Fixer::Airlock,action,input } if action=="set-file-content" && input["path"]=="assets/handbook.txt" && input["contents"]=="expected sample")
    );
    assert!(only(&report).instances[0].conditions[0]
        .observed_digest
        .is_some());
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("ghu_fixture_token"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn missing_file_is_a_gap_but_truncation_and_unreadable_content_are_not_evaluated() {
    use airlock_core::configurable::probe::GitHubProbes;
    for truncated in [false, true] {
        let server = wiremock::MockServer::start().await;
        tree_mock(&server, json!([]), truncated).await;
        let org = catch_all(
            json!({"handbook":file_rule("/contents",json!("expected sample"))}),
            vec!["handbook"],
        );
        let client = api_client(&server);
        let mut probes = GitHubProbes::new(&client, Default::default());
        let report = audit(
            "sample",
            &org,
            &[input(None)],
            &mut probes,
            &Evaluations::built_in(),
        )
        .await
        .unwrap();
        assert_eq!(
            only(&report).flavor,
            if truncated {
                Flavor::NotEvaluated
            } else {
                Flavor::Gap
            }
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    let server = wiremock::MockServer::start().await;
    tree_mock(&server,json!([{"path":"assets/handbook.txt","mode":"100644","type":"blob","sha":"d".repeat(40),"size":6}]),false).await;
    let org = catch_all(
        json!({"handbook":file_rule("/contents",json!("expected sample"))}),
        vec!["handbook"],
    );
    let client = api_client(&server);
    let mut probes = GitHubProbes::new(&client, Default::default());
    let report = audit(
        "sample",
        &org,
        &[input(None)],
        &mut probes,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    assert_eq!(only(&report).flavor, Flavor::NotEvaluated);
    assert_eq!(
        only(&report).instances[0].conditions[0]
            .diagnostic
            .as_ref()
            .unwrap()
            .code,
        "probe-failed"
    );
}

#[tokio::test]
async fn byte_budget_and_symlink_do_not_read_blobs_or_follow_links() {
    use airlock_core::configurable::probe::GitHubProbes;
    for (mode, size) in [("100644", 100_u64), ("120000", 4)] {
        let server = wiremock::MockServer::start().await;
        tree_mock(&server,json!([{"path":"assets/handbook.txt","mode":mode,"type":"blob","sha":"d".repeat(40),"size":size}]),false).await;
        let org = catch_all(
            json!({"handbook":file_rule("/exists",json!(true))}),
            vec!["handbook"],
        );
        let client = api_client(&server);
        let mut probes = GitHubProbes::new(
            &client,
            airlock_core::limits::Limits {
                max_blob_bytes: 10,
                ..Default::default()
            },
        );
        let report = audit(
            "sample",
            &org,
            &[input(None)],
            &mut probes,
            &Evaluations::built_in(),
        )
        .await
        .unwrap();
        assert_eq!(
            only(&report).flavor,
            if mode == "120000" {
                Flavor::Gap
            } else {
                Flavor::NotEvaluated
            }
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn source_loader_reads_the_named_commit_and_preserves_config_provenance() {
    let server = wiremock::MockServer::start().await;
    let bytes = b"rules: {}\nassignments: {}\n";
    tree_mock(&server,json!([{"path":"config/rules.yml","mode":"100644","type":"blob","sha":"d".repeat(40),"size":bytes.len()}]),false).await;
    blob_mock(&server, bytes).await;
    let source = ConfigSource {
        repository: "sample/sample-kit".into(),
        path: "config/rules.yml".into(),
        commit: "c".repeat(40),
    };
    let loaded = ConfigSnapshot::<OrganizationConfig>::read_at(
        &api_client(&server),
        source.clone(),
        Default::default(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(loaded.source, source);
    assert!(loaded.document.rules.is_empty());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn fix_declaration_replaces_completes_blocks_or_rejects_unknown_actions() {
    let server = wiremock::MockServer::start().await;
    tree_mock(&server, json!([]), false).await;
    let mut rules = serde_json::Map::new();
    for (id, fix) in [
        ("default", Value::Null),
        (
            "complete",
            json!({"mode":"complete","input":{"contents":"completed sample"}}),
        ),
        (
            "agent",
            json!({"mode":"agent","guidance":"Write a short sample handbook."}),
        ),
        (
            "block",
            json!({"mode":"block","reason":"This sample is retained for comparison."}),
        ),
        (
            "action",
            json!({"mode":"action","action":"set-file-content","input":{"path":"assets/handbook.txt","contents":"declared sample"}}),
        ),
        (
            "unknown",
            json!({"mode":"action","action":"execute-program","input":{}}),
        ),
    ] {
        let mut rule = file_rule("/contents", json!("expected sample"));
        rule["fix"] = fix;
        rules.insert(id.into(), rule);
    }
    let org = catch_all(
        Value::Object(rules),
        vec!["default", "complete", "agent", "block", "action", "unknown"],
    );
    let client = api_client(&server);
    let mut probes =
        airlock_core::configurable::probe::GitHubProbes::new(&client, Default::default());
    let report = audit(
        "sample",
        &org,
        &[input(None)],
        &mut probes,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    let by_id: BTreeMap<_, _> = report.repositories[0]
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();
    assert!(
        matches!(&by_id["default"].instances[0].fixes[0],Fix::Action { action,.. } if action=="set-file-content")
    );
    assert!(
        matches!(&by_id["complete"].instances[0].fixes[0],Fix::Action { input,.. } if input["contents"]=="completed sample")
    );
    assert!(
        matches!(&by_id["agent"].instances[0].fixes[0],Fix::Agent {guidance} if guidance=="Write a short sample handbook.")
    );
    assert!(
        matches!(&by_id["block"].instances[0].fixes[0],Fix::NotFixable {reason} if reason=="This sample is retained for comparison.")
    );
    assert!(
        matches!(&by_id["action"].instances[0].fixes[0],Fix::Action { input,.. } if input["contents"]=="declared sample")
    );
    assert_eq!(by_id["unknown"].flavor, Flavor::NotEvaluated);
    assert_eq!(
        by_id["unknown"].instances[0]
            .diagnostic
            .as_ref()
            .unwrap()
            .code,
        "invalid-rule"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn new_config_commit_changes_audit_without_a_binary_change() {
    let first = org(json!({"sample-measure":rule(6)}), vec!["sample-measure"]);
    let mut next = first.clone();
    next.source.commit = "d".repeat(40);
    next.document.rules.insert("sample-measure".into(), rule(4));
    let (a, _) = run(&first, input(None), 5).await;
    let (b, _) = run(&next, input(None), 5).await;
    assert_eq!(only(&a).flavor, Flavor::Gap);
    assert_eq!(only(&b).flavor, Flavor::Passed);
    assert_ne!(a.organization_config.commit, b.organization_config.commit);
}

#[tokio::test]
async fn local_only_rule_has_no_invented_parent_but_cannot_fill_undefined_org_reference() {
    let organization = org(json!({"assigned":rule(6)}), vec!["assigned"]);
    let (report, _) = run(&organization, input(Some(json!({"local":rule(4)}))), 5).await;
    let local = report.repositories[0]
        .rules
        .iter()
        .find(|r| r.id == "local")
        .unwrap();
    assert_eq!(local.instances.len(), 1);
    assert_eq!(local.instances[0].source, Source::Repository);
    assert_eq!(local.flavor, Flavor::Passed);
    let organization = org(json!({}), vec!["local"]);
    let (report, _) = run(&organization, input(Some(json!({"local":rule(4)}))), 5).await;
    assert_eq!(only(&report).instances.len(), 2);
    assert_eq!(only(&report).flavor, Flavor::NotEvaluated);
}

#[test]
fn built_in_ordering_preserves_large_integers_and_requires_integer_inputs() {
    let evaluations = Evaluations::built_in();
    let minimum = evaluations.get("minimum").unwrap();
    let requests = [EvaluationInput {
        pointer: "".into(),
        expected: json!(9_007_199_254_740_993_u64),
    }];
    assert!(
        !minimum.evaluate(&json!(9_007_199_254_740_992_u64), &requests)[0]
            .as_ref()
            .unwrap()
            .passed
    );
    assert!(minimum.validate_input(&json!(1.5)).is_err());
    assert!(minimum.evaluate(
        &json!(-1),
        &[EvaluationInput {
            pointer: "".into(),
            expected: json!(u64::MAX)
        }]
    )[0]
    .as_ref()
    .is_ok_and(|d| !d.passed));
}

#[tokio::test]
async fn maximum_and_required_set_floors_use_evaluation_order() {
    let mut maximum = rule(6);
    maximum["conditions"][0] = condition("/score", "maximum", json!(9), json!(4));
    let organization = org(json!({"measure":maximum.clone()}), vec!["measure"]);
    let mut child = maximum;
    child["conditions"][0] = condition("/score", "maximum", json!(9), json!(7));
    child["reason"] = json!("This sample permits a wider maximum.");
    let (report, _) = run(&organization, input(Some(json!({"measure":child}))), 6).await;
    assert_eq!(only(&report).flavor, Flavor::Passed);
    assert_eq!(only(&report).instances[0].conditions[0].expected, json!(9));
    let contains = Evaluations::built_in();
    let evaluator = contains.get("contains-all").unwrap();
    assert_eq!(
        evaluator.relaxes(&json!(["a", "b"]), &json!(["a"])),
        Some(true)
    );
    assert_eq!(
        evaluator.relaxes(&json!(["a"]), &json!(["a", "b"])),
        Some(false)
    );
    assert!(evaluator.evaluate(
        &json!(["a"]),
        &[EvaluationInput {
            pointer: "".into(),
            expected: json!(["a", "b"])
        }]
    )[0]
    .as_ref()
    .is_ok_and(|d| !d.passed));
}

#[tokio::test]
async fn metadata_fixes_name_the_person_and_undisclosed_settings_are_not_evaluated() {
    use wiremock::{
        matchers::{method, path},
        Mock, ResponseTemplate,
    };
    let server = wiremock::MockServer::start().await;
    Mock::given(method("GET")).and(path("/repos/sample/sample-kit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"full_name":"sample/sample-kit","id":1,"name":"sample-kit","owner":{"login":"sample"},"default_branch":"main","visibility":"public","has_wiki":true,"has_projects":false,"has_discussions":false,"has_issues":true}))).expect(1).mount(&server).await;
    let mut wiki = rule(6);
    wiki["probes"] = json!({"observed":{"kind":"repository","input":{}}});
    wiki["conditions"] = json!([condition("/has-wiki", "equal", json!(false), json!(false))]);
    let mut merge = wiki.clone();
    merge["conditions"] = json!([condition(
        "/allow-merge-commit",
        "equal",
        json!(false),
        json!(false)
    )]);
    let org = catch_all(json!({"wiki":wiki,"merge":merge}), vec!["wiki", "merge"]);
    let client = api_client(&server);
    let mut probes =
        airlock_core::configurable::probe::GitHubProbes::new(&client, Default::default());
    let report = audit(
        "sample",
        &org,
        &[input(None)],
        &mut probes,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    let by_id: BTreeMap<_, _> = report.repositories[0]
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();
    assert_eq!(by_id["merge"].flavor, Flavor::NotEvaluated);
    assert_eq!(
        by_id["merge"].instances[0].conditions[0]
            .diagnostic
            .as_ref()
            .unwrap()
            .code,
        "unobserved-field"
    );
    assert_eq!(by_id["wiki"].flavor, Flavor::Gap);
    assert!(
        matches!(&by_id["wiki"].instances[0].fixes[0],Fix::Action {fixer:Fixer::Person,action,input} if action=="set-repository-setting" && input["setting"]=="has-wiki" && input["value"]==false)
    );
}

#[tokio::test]
async fn report_contract_fixture_is_serialized_by_the_real_engine() {
    let mut a = rule(6);
    a["fix"] = json!({"mode":"agent","guidance":"Expand the sample and document the result."});
    let mut invalid = rule(6);
    invalid["conditions"][0]["evaluation"] = json!("external-judgment-not-adopted");
    let mut organization = org(
        json!({"sample-measure":a,"unavailable-evaluation":invalid}),
        vec!["sample-measure", "unavailable-evaluation"],
    );
    organization
        .document
        .assignments
        .get_mut("selected")
        .unwrap()
        .conditions
        .push(
            serde_json::from_value(condition(
                "/name",
                "glob",
                json!("sample-*"),
                json!("sample-*"),
            ))
            .unwrap(),
        );
    let first = input(Some(json!({"sample-measure":rule(4)})));
    let mut second = input(None);
    second.target.name = "other-kit".into();
    let mut facts = Facts {
        score: 5,
        ..Facts::default()
    };
    let report = audit(
        "sample",
        &organization,
        &[first, second],
        &mut facts,
        &Evaluations::built_in(),
    )
    .await
    .unwrap();
    assert_eq!(report.unassigned_repositories, vec!["sample/other-kit"]);
    let primary = report
        .repositories
        .iter()
        .find(|r| r.repository == "sample/sample-kit")
        .unwrap();
    assert_eq!(primary.rules[0].flavor, Flavor::Gap);
    assert_eq!(primary.rules[0].instances.len(), 2);
    assert_eq!(primary.warnings.len(), 1);
    assert_eq!(primary.rules[1].flavor, Flavor::NotEvaluated);
    let encoded = serde_json::to_string_pretty(&report).unwrap() + "\n";
    let decoded: Report = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&report).unwrap()
    );
    if let Some(destination) = std::env::var_os("AIRLOCK_CONFIGURABLE_FIXTURE_OUTPUT") {
        std::fs::write(destination, encoded).unwrap();
    }
}
