// ---
// relationships:
//   references: rule
// ---

use super::{
    config::*,
    evaluation::{EvaluationInput, Evaluations},
    fix,
    probe::{ProbeProvider, RepositoryTarget},
    report::*,
    validate_schema,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub struct RepositoryInput {
    pub target: RepositoryTarget,
    pub config: Option<ConfigSnapshot<RepositoryConfig>>,
}

/// Audit one account. Scope and source identity errors stop before any probe.
/// A malformed rule becomes its own not-evaluated instance; siblings continue.
/// Assignment errors are explicit and never establish that a repo is unassigned.
pub async fn audit<P: ProbeProvider>(
    account: &str,
    organization: &ConfigSnapshot<OrganizationConfig>,
    repositories: &[RepositoryInput],
    provider: &mut P,
    evaluations: &Evaluations,
) -> Result<Report, String> {
    validate_scope(account, organization, repositories)?;
    let mut report = Report {
        account: account.into(),
        organization_config: organization.source.clone(),
        repositories: Vec::new(),
        unassigned_repositories: Vec::new(),
    };
    for input in repositories {
        let mut run = Run {
            provider,
            evaluations,
            target: &input.target,
            cache: Vec::new(),
        };
        let (repository, unassigned) = run.repository(organization, input).await;
        if unassigned {
            report
                .unassigned_repositories
                .push(input.target.full_name());
        }
        report.repositories.push(repository);
    }
    report
        .repositories
        .sort_by(|a, b| a.repository.cmp(&b.repository));
    report.unassigned_repositories.sort();
    Ok(report)
}

fn validate_scope(
    account: &str,
    org: &ConfigSnapshot<OrganizationConfig>,
    repositories: &[RepositoryInput],
) -> Result<(), String> {
    if account.is_empty() || account.contains('/') {
        return Err("run needs one account".into());
    }
    let source_in_scope = |source: &ConfigSource| {
        source
            .repository
            .split_once('/')
            .is_some_and(|(owner, name)| {
                owner.eq_ignore_ascii_case(account) && !name.is_empty() && !name.contains('/')
            })
            && is_commit_oid(&source.commit)
            && !source.path.trim().is_empty()
    };
    if !source_in_scope(&org.source) {
        return Err("organization config source is outside the account or unpinned".into());
    }
    if org.document.repositories.keys().any(|name| {
        !name.split_once('/').is_some_and(|(owner, repo)| {
            owner.eq_ignore_ascii_case(account) && !repo.is_empty() && !repo.contains('/')
        })
    }) {
        return Err("repository override is outside the run account".into());
    }
    let mut seen = BTreeSet::new();
    for input in repositories {
        let target = &input.target;
        if !target.owner.eq_ignore_ascii_case(account)
            || target.name.is_empty()
            || target.name.contains('/')
            || !is_commit_oid(&target.commit)
        {
            return Err("repository target is outside the account or unpinned".into());
        }
        if !seen.insert(target.full_name().to_ascii_lowercase()) {
            return Err("duplicate repository target".into());
        }
        if let Some(config) = &input.config {
            if !source_in_scope(&config.source)
                || !config
                    .source
                    .repository
                    .eq_ignore_ascii_case(&target.full_name())
            {
                return Err("repository config source does not belong to its target".into());
            }
        }
    }
    Ok(())
}

struct Run<'a, P> {
    provider: &'a mut P,
    evaluations: &'a Evaluations,
    target: &'a RepositoryTarget,
    // Per repository, per run. Reuse only exact same typed request inputs.
    // This is a reversible scheduling choice, not a cross-run cache contract.
    cache: Vec<(ProbeRequest, Result<Value, Diagnostic>)>,
}

struct Prepared {
    id: String,
    source: Source,
    commit: String,
    mode: Mode,
    relaxation_reason: Option<String>,
    rule: Result<Rule, String>,
}

struct Conditions<'a> {
    probes: &'a BTreeMap<String, ProbeRequest>,
    conditions: &'a [Condition],
    mode: Mode,
    fix: Option<&'a FixDeclaration>,
}

struct Group {
    evaluation: String,
    observed: Value,
    jobs: Vec<(usize, usize, Value)>,
}

impl<P: ProbeProvider> Run<'_, P> {
    async fn repository(
        &mut self,
        org: &ConfigSnapshot<OrganizationConfig>,
        input: &RepositoryInput,
    ) -> (RepositoryReport, bool) {
        let mut assignments = Vec::new();
        let mut selected = BTreeSet::new();
        let mut valid = Vec::new();
        for (id, assignment) in &org.document.assignments {
            match self.validate_conditions(&assignment.probes, &assignment.conditions, false) {
                Ok(()) => valid.push((id, assignment)),
                Err(reason) => assignments.push(AssignmentResult {
                    id: id.clone(),
                    matched: None,
                    diagnostic: Some(diagnostic("invalid-assignment", reason)),
                }),
            }
        }
        let sets: Vec<_> = valid
            .iter()
            .map(|(_, a)| Conditions {
                probes: &a.probes,
                conditions: &a.conditions,
                mode: Mode::Value,
                fix: None,
            })
            .collect();
        let outcomes = self.conditions(&sets).await;
        for ((id, assignment), outcomes) in valid.into_iter().zip(outcomes) {
            // A known false conjunct decides an assignment even if another
            // observation failed. With no false conjunct, uncertainty remains.
            let matched = if outcomes.iter().any(|c| c.flavor == Flavor::Gap) {
                Some(false)
            } else if outcomes.iter().any(|c| c.flavor == Flavor::NotEvaluated) {
                None
            } else {
                Some(true)
            };
            if matched == Some(true) {
                selected.extend(assignment.rules.iter().cloned());
            }
            let diagnostic = outcomes.iter().find_map(|c| c.diagnostic.clone());
            assignments.push(AssignmentResult {
                id: id.clone(),
                matched,
                diagnostic,
            });
        }
        assignments.sort_by(|a, b| a.id.cmp(&b.id));
        let assigned = assignments.iter().any(|a| a.matched == Some(true));
        let unassigned = !assigned && assignments.iter().all(|a| a.matched == Some(false));
        let mut result = RepositoryReport {
            repository: input.target.full_name(),
            audited_commit: input.target.commit.clone(),
            maturity: input.target.maturity,
            repository_config: input.config.as_ref().map(|c| c.source.clone()),
            assignments,
            rules: Vec::new(),
            warnings: Vec::new(),
        };
        if !assigned {
            return (result, unassigned);
        }

        // Repository definitions add local rules only after assignment. They
        // cannot manufacture findings for an unassigned repository.
        let assigned_ids = selected.clone();
        if let Some(config) = &input.config {
            selected.extend(config.document.rules.keys().cloned());
        }
        let mut prepared = Vec::new();
        for id in selected {
            let child = input
                .config
                .as_ref()
                .and_then(|c| c.document.rules.get(&id));
            let child = child.map(|value| self.rule(value));
            let relaxation_reason = child
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|r| r.reason.clone())
                .filter(|r| !r.trim().is_empty());
            let reason = child
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|r| r.reason.as_deref())
                .is_some_and(|r| !r.trim().is_empty());
            if let Some(raw) = org.document.rules.get(&id) {
                let mut parent = self.rule(raw);
                // An org-owned per-repo replacement may change or waive the
                // org rule, but only with a reason. Invalid override is visible
                // alongside the retained org parent, never a bypass.
                if let Some(override_raw) = org
                    .document
                    .repositories
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&input.target.full_name()))
                    .and_then(|(_, rules)| rules.get(&id))
                {
                    match self.rule(override_raw) {
                        Ok(overridden)
                            if overridden
                                .reason
                                .as_deref()
                                .is_some_and(|r| !r.trim().is_empty()) =>
                        {
                            parent = Ok(overridden)
                        }
                        override_rule => {
                            let error = match override_rule {
                                Err(e) => e,
                                Ok(_) => "organization repository override needs a reason".into(),
                            };
                            prepared.push(Prepared {
                                id: id.clone(),
                                source: Source::Organization,
                                commit: org.source.commit.clone(),
                                mode: Mode::Value,
                                relaxation_reason: None,
                                rule: Err(error),
                            });
                        }
                    }
                }
                if !reason {
                    if let (Ok(parent), Some(Ok(child))) = (&parent, &child) {
                        if let Some(detail) = self.relaxation(parent, child) {
                            result.warnings.push(Warning {
                                rule: id.clone(),
                                code: "relaxation-without-reason".into(),
                                reason: detail,
                            });
                        }
                    }
                }
                prepared.push(Prepared {
                    id: id.clone(),
                    source: Source::Organization,
                    commit: org.source.commit.clone(),
                    mode: if reason { Mode::Floor } else { Mode::Value },
                    relaxation_reason: relaxation_reason.clone(),
                    rule: parent,
                });
            } else if assigned_ids.contains(&id) {
                prepared.push(Prepared {
                    id: id.clone(),
                    source: Source::Organization,
                    commit: org.source.commit.clone(),
                    mode: Mode::Value,
                    relaxation_reason: None,
                    rule: Err("assignment references an undefined organization rule".into()),
                });
            }
            if let Some(child) = child {
                prepared.push(Prepared {
                    id,
                    source: Source::Repository,
                    commit: input
                        .config
                        .as_ref()
                        .expect("child has source")
                        .source
                        .commit
                        .clone(),
                    mode: Mode::Value,
                    relaxation_reason: None,
                    rule: child,
                });
            }
        }
        let valid: Vec<_> = prepared
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                p.rule
                    .as_ref()
                    .ok()
                    .filter(|r| severity(r, p.mode, self.target.maturity) != Severity::None)
                    .map(|rule| (i, rule, p.mode))
            })
            .collect();
        let sets: Vec<_> = valid
            .iter()
            .map(|(_, rule, mode)| Conditions {
                probes: &rule.probes,
                conditions: &rule.conditions,
                mode: *mode,
                fix: rule.fix.as_ref(),
            })
            .collect();
        let evaluated = self.conditions(&sets).await;
        let mut evaluated: BTreeMap<_, _> = valid
            .into_iter()
            .map(|(i, _, _)| i)
            .zip(evaluated)
            .collect();
        let mut grouped: BTreeMap<String, Vec<InstanceResult>> = BTreeMap::new();
        for (index, prepared) in prepared.into_iter().enumerate() {
            let instance = match prepared.rule {
                Err(reason) => InstanceResult {
                    source: prepared.source,
                    config_commit: prepared.commit,
                    mode: prepared.mode,
                    statement: None,
                    reason: None,
                    relaxation_reason: prepared.relaxation_reason,
                    severity: Severity::Blocking,
                    result: ResultKind::Fail,
                    flavor: Flavor::NotEvaluated,
                    diagnostic: Some(diagnostic("invalid-rule", reason.clone())),
                    conditions: Vec::new(),
                    fixes: vec![Fix::NotFixable { reason }],
                },
                Ok(rule) => {
                    let severity = severity(&rule, prepared.mode, self.target.maturity);
                    let conditions = evaluated.remove(&index).unwrap_or_default();
                    let flavor = if severity == Severity::None {
                        Flavor::Waived
                    } else {
                        conditions_flavor(&conditions)
                    };
                    let fixes = conditions
                        .iter()
                        .filter(|c| c.result == ResultKind::Fail)
                        .map(|c| c.fix.clone())
                        .collect();
                    InstanceResult {
                        source: prepared.source,
                        config_commit: prepared.commit,
                        mode: prepared.mode,
                        statement: Some(rule.statement),
                        reason: rule.reason.clone(),
                        relaxation_reason: prepared.relaxation_reason,
                        severity,
                        result: kind(flavor),
                        flavor,
                        diagnostic: if flavor == Flavor::Waived {
                            Some(diagnostic(
                                "waived",
                                rule.reason.unwrap_or_else(|| {
                                    "effective configured severity is none".into()
                                }),
                            ))
                        } else {
                            None
                        },
                        conditions,
                        fixes,
                    }
                }
            };
            grouped.entry(prepared.id).or_default().push(instance);
        }
        result.rules = grouped
            .into_iter()
            .map(|(id, instances)| {
                let failures: Vec<_> = instances
                    .iter()
                    .filter(|i| i.result == ResultKind::Fail)
                    .collect();
                let flavor = if failures.iter().any(|i| i.flavor == Flavor::NotEvaluated) {
                    Flavor::NotEvaluated
                } else if !failures.is_empty() {
                    Flavor::Gap
                } else if instances.iter().all(|i| i.flavor == Flavor::Waived) {
                    Flavor::Waived
                } else {
                    Flavor::Passed
                };
                let severity = if failures.is_empty() {
                    instances.iter().map(|i| i.severity).max()
                } else {
                    failures.iter().map(|i| i.severity).max()
                }
                .unwrap_or(Severity::Blocking);
                RuleResult {
                    id,
                    result: kind(flavor),
                    flavor,
                    severity,
                    instances,
                }
            })
            .collect();
        (result, unassigned)
    }

    fn rule(&self, value: &Value) -> Result<Rule, String> {
        let rule: Rule = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        if rule.statement.trim().is_empty() {
            return Err("rule needs a statement".into());
        }
        self.validate_conditions(&rule.probes, &rule.conditions, true)?;
        for maturity in Lifecycle::ALL {
            let s = rule.severity.at(*maturity);
            if s.floor > s.value {
                return Err("severity floor is stricter than its value".into());
            }
        }
        if let Some(fix) = &rule.fix {
            fix::validate(fix)?;
        }
        Ok(rule)
    }

    fn validate_conditions(
        &self,
        probes: &BTreeMap<String, ProbeRequest>,
        conditions: &[Condition],
        rule: bool,
    ) -> Result<(), String> {
        if rule && conditions.is_empty() {
            return Err("rule needs at least one condition".into());
        }
        for condition in conditions {
            if !valid_pointer(&condition.pointer) {
                return Err("condition has invalid JSON Pointer".into());
            }
            let request = probes
                .get(&condition.probe)
                .ok_or_else(|| format!("unknown probe reference {}", condition.probe))?;
            let schema = self
                .provider
                .schema(&request.kind)
                .ok_or_else(|| format!("unknown probe type {}", request.kind))?;
            validate_schema(&schema.input, &request.input)?;
            let evaluation = self
                .evaluations
                .get(&condition.evaluation)
                .ok_or_else(|| format!("unknown evaluation type {}", condition.evaluation))?;
            for setting in [&condition.setting.floor, &condition.setting.value] {
                validate_schema(&evaluation.input_schema(), setting)?;
                evaluation.validate_input(setting)?;
            }
            if condition.setting.floor != condition.setting.value
                && evaluation.relaxes(&condition.setting.value, &condition.setting.floor)
                    != Some(true)
            {
                return Err("condition floor must be demonstrably no stricter than value".into());
            }
        }
        Ok(())
    }

    fn relaxation(&self, parent: &Rule, child: &Rule) -> Option<String> {
        if child.severity.at(self.target.maturity).value
            < parent.severity.at(self.target.maturity).value
        {
            return Some("repository severity relaxes the parent without a reason; parent value remains enforced".into());
        }
        for condition in &parent.conditions {
            let compatible = child.conditions.iter().find(|c| {
                c.pointer == condition.pointer
                    && c.evaluation == condition.evaluation
                    && parent.probes.get(&condition.probe) == child.probes.get(&c.probe)
            });
            match compatible.and_then(|c| self.evaluations.get(&condition.evaluation)?.relaxes(&condition.setting.value,&c.setting.value)) {
                Some(false) => (),
                Some(true) => return Some("repository condition relaxes the parent without a reason; parent value remains enforced".into()),
                None => return Some("repository replacement is not comparable to the parent and has no reason; parent value remains enforced".into()),
            }
        }
        None
    }

    async fn observe(&mut self, request: &ProbeRequest) -> Result<Value, Diagnostic> {
        if let Some((_, value)) = self.cache.iter().find(|(key, _)| key == request) {
            return value.clone();
        }
        let result = match self.provider.observe(self.target, request).await {
            Err(reason) => Err(diagnostic("probe-failed", reason)),
            Ok(output) => {
                match self
                    .provider
                    .schema(&request.kind)
                    .ok_or_else(|| "probe schema disappeared".to_owned())
                    .and_then(|schema| validate_schema(&schema.output, &output))
                {
                    Ok(()) => Ok(output),
                    Err(reason) => Err(diagnostic("invalid-probe-output", reason)),
                }
            }
        };
        self.cache.push((request.clone(), result.clone()));
        result
    }

    async fn conditions(&mut self, sets: &[Conditions<'_>]) -> Vec<Vec<ConditionResult>> {
        let mut results: Vec<Vec<Option<ConditionResult>>> = sets
            .iter()
            .map(|s| vec![None; s.conditions.len()])
            .collect();
        let mut groups: Vec<Group> = Vec::new();
        for (set_index, set) in sets.iter().enumerate() {
            for (index, condition) in set.conditions.iter().enumerate() {
                let expected = match set.mode {
                    Mode::Value => &condition.setting.value,
                    Mode::Floor => &condition.setting.floor,
                }
                .clone();
                let request = &set.probes[&condition.probe];
                let selected = self.observe(request).await.and_then(|output| {
                    if output.pointer(&condition.pointer).is_some() {
                        Ok(output)
                    } else {
                        Err({
                            diagnostic(
                                "unobserved-field",
                                format!("probe output does not contain {}", condition.pointer),
                            )
                        })
                    }
                });
                match selected {
                    Err(error) => {
                        results[set_index][index] = Some(failed_condition(index, expected, error))
                    }
                    Ok(observed) => {
                        let evaluation = self
                            .evaluations
                            .get(&condition.evaluation)
                            .expect("validated evaluator");
                        if let Some(group) = groups.iter_mut().find(|g| {
                            evaluation.batch_capable()
                                && g.evaluation == condition.evaluation
                                && g.observed == observed
                        }) {
                            group.jobs.push((set_index, index, expected));
                        } else {
                            groups.push(Group {
                                evaluation: condition.evaluation.clone(),
                                observed,
                                jobs: vec![(set_index, index, expected)],
                            });
                        }
                    }
                }
            }
        }
        for group in groups {
            let expected: Vec<_> = group
                .jobs
                .iter()
                .map(|(s, i, v)| EvaluationInput {
                    pointer: sets[*s].conditions[*i].pointer.clone(),
                    expected: v.clone(),
                })
                .collect();
            let decisions = self
                .evaluations
                .get(&group.evaluation)
                .expect("validated evaluator")
                .evaluate(&group.observed, &expected);
            if decisions.len() != group.jobs.len() {
                for (s, i, expected) in group.jobs {
                    results[s][i] = Some(failed_condition(
                        i,
                        expected,
                        diagnostic(
                            "evaluation-failed",
                            "evaluation returned the wrong batch size",
                        ),
                    ));
                }
                continue;
            }
            for ((s, i, expected), decision) in group.jobs.into_iter().zip(decisions) {
                let result = match decision {
                    Err(reason) => {
                        failed_condition(i, expected, diagnostic("evaluation-failed", reason))
                    }
                    Ok(decision) => {
                        let condition = &sets[s].conditions[i];
                        let fix = if decision.passed {
                            Fix::NotFixable {
                                reason: "no fix needed".into(),
                            }
                        } else {
                            fix::apply(
                                fix::derive(
                                    &sets[s].probes[&condition.probe],
                                    condition,
                                    &expected,
                                ),
                                sets[s].fix,
                            )
                        };
                        ConditionResult {
                            index: i,
                            result: if decision.passed {
                                ResultKind::Pass
                            } else {
                                ResultKind::Fail
                            },
                            flavor: if decision.passed {
                                Flavor::Passed
                            } else {
                                Flavor::Gap
                            },
                            diagnostic: None,
                            expected,
                            probe: condition.probe.clone(),
                            pointer: condition.pointer.clone(),
                            evaluation: condition.evaluation.clone(),
                            observed_digest: group.observed.pointer(&condition.pointer).map(digest),
                            reason: decision.reason,
                            fix,
                        }
                    }
                };
                results[s][i] = Some(result);
            }
        }
        results
            .into_iter()
            .enumerate()
            .map(|(set_index, items)| {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(index, item)| {
                        let mut item = item.expect("every condition has an outcome");
                        let condition = &sets[set_index].conditions[index];
                        item.probe = condition.probe.clone();
                        item.pointer = condition.pointer.clone();
                        item.evaluation = condition.evaluation.clone();
                        item
                    })
                    .collect()
            })
            .collect()
    }
}

fn valid_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let mut chars = pointer.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}
fn severity(rule: &Rule, mode: Mode, maturity: Lifecycle) -> Severity {
    let setting = rule.severity.at(maturity);
    match mode {
        Mode::Value => setting.value,
        Mode::Floor => setting.floor,
    }
}
fn diagnostic(code: &str, reason: impl Into<String>) -> Diagnostic {
    Diagnostic {
        code: code.into(),
        reason: reason.into(),
    }
}
fn kind(flavor: Flavor) -> ResultKind {
    match flavor {
        Flavor::Gap | Flavor::NotEvaluated => ResultKind::Fail,
        _ => ResultKind::Pass,
    }
}
fn conditions_flavor(conditions: &[ConditionResult]) -> Flavor {
    if conditions.iter().any(|c| c.flavor == Flavor::NotEvaluated) {
        Flavor::NotEvaluated
    } else if conditions.iter().any(|c| c.flavor == Flavor::Gap) {
        Flavor::Gap
    } else {
        Flavor::Passed
    }
}
fn failed_condition(index: usize, expected: Value, error: Diagnostic) -> ConditionResult {
    ConditionResult {
        index,
        result: ResultKind::Fail,
        flavor: Flavor::NotEvaluated,
        reason: error.reason.clone(),
        diagnostic: Some(error.clone()),
        expected,
        probe: String::new(),
        pointer: String::new(),
        evaluation: String::new(),
        observed_digest: None,
        fix: Fix::NotFixable {
            reason: error.reason,
        },
    }
}

fn digest(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("JSON value serializes"),
    ))
}
