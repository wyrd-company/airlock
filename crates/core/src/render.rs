//! Human-readable renderings of the machine documents.
//!
//! The JSON is the contract. Everything here is a view of exactly the same
//! data, so a human and a pipeline never see different answers.

use std::fmt::Write as _;

use crate::findings::{RemediationClass, Report, Status};
use crate::plan::{self, Plan};
use crate::registry::{self, CheckDefinition};
use crate::remediation::{self, Classification};
use crate::worklist::AgentWorkList;

/// Render an audit report for a terminal.
#[must_use]
pub fn report_text(report: &Report) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} at {}",
        report.repository.full_name,
        short(&report.repository.audited_commit)
    );
    let _ = writeln!(
        out,
        "policy {} from {} (bundle {})",
        report.policy.name,
        report.policy.source,
        short_digest(&report.policy.bundle_digest)
    );
    for source in &report.policy.sources {
        let pinned = match (&source.commit, &source.blob_sha) {
            (Some(commit), Some(blob)) => {
                format!("{}@{} blob {}", source.source, short(commit), short(blob))
            }
            (Some(commit), None) => format!("{}@{}", source.source, short(commit)),
            _ => format!(
                "{} ({})",
                source.source,
                short_digest(&source.content_digest)
            ),
        };
        let _ = writeln!(out, "  {:<12} {pinned}", source.name);
    }
    let _ = writeln!(
        out,
        "registry {} ({})",
        report.airlock.registry_version,
        short_digest(&report.airlock.registry_digest)
    );
    let _ = writeln!(
        out,
        "waived: {}, routed: {}, unbuilt: {}, run errors: {}",
        report.summary.waived,
        report.summary.routed,
        report.summary.unbuilt,
        report.summary.run_errors
    );
    out.push('\n');

    for finding in report.entries() {
        let _ = writeln!(
            out,
            "{:<13} {:<13} {} | {}",
            finding.status_code(),
            finding.severity,
            finding.rule,
            finding.statement
        );
        if let Some(evidence) = &finding.evidence {
            let _ = writeln!(out, "              {}", evidence.detail);
        }
        if let Some(error) = &finding.error {
            let _ = writeln!(
                out,
                "              {} on {}{}",
                error.cause,
                error.endpoint,
                error
                    .message
                    .as_ref()
                    .map(|message| format!(": {message}"))
                    .unwrap_or_default()
            );
        }
        if let Some(route) = &finding.routing {
            let _ = writeln!(
                out,
                "              {} — {}",
                route.reason, route.settling_surface
            );
        }
        if let Some(suppression) = &finding.suppression {
            let _ = writeln!(
                out,
                "              waived by {} — {}",
                suppression.authorized_by,
                suppression
                    .policy_reason
                    .as_ref()
                    .or(suppression.requested_reason.as_ref())
                    .map_or("", String::as_str)
            );
        }
        if finding.status == Some(Status::Gap) {
            if let Some(remediation) = &finding.remediation {
                let _ = writeln!(out, "              → {}", remediation.detail);
            }
        }
    }

    if !report.policy_observations.is_empty() {
        out.push('\n');
        for observation in &report.policy_observations {
            let _ = writeln!(out, "note: {}", observation.detail);
        }
    }

    out.push('\n');
    // Derived from the taxonomy rather than restated, so a status added to
    // `Status::ALL` cannot quietly vanish from what a human reads.
    let counts: Vec<String> = Status::ALL
        .iter()
        .map(|status| format!("{} {}", report.summary.count(*status), status.code()))
        .collect();
    let _ = writeln!(out, "{}", counts.join(", "));
    let _ = writeln!(
        out,
        "{} — complete: {}, conformant: {}",
        report.outcome.code(),
        report.complete,
        report.conformant
    );
    // A structurally admin-only rule leaves the run complete, so nothing
    // above this line would tell a reader it exists. It is named here for the
    // same reason it is never a pass: the assertion is still open, and the
    // surface that can settle it is not this one.
    let admin_only = report
        .routed
        .iter()
        .filter(|f| registry::find(&f.rule).is_some_and(|d| d.disclosure_gate().is_some()))
        .count();
    if admin_only > 0 {
        let _ = writeln!(
            out,
            "{admin_only} rule(s) require admin access to verify — named, never gating, \
             and never a pass."
        );
        for surface in verification_surfaces(report) {
            let _ = writeln!(out, "  {}: {}", surface.code(), surface.guidance());
        }
    }

    out
}

/// Render the agent-lane definition-of-done result for a terminal.
#[must_use]
pub fn agent_work_list_text(list: &AgentWorkList) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} at {} — agent lane only; not repository conformance",
        list.repository.full_name,
        short(&list.repository.audited_commit)
    );
    let _ = writeln!(
        out,
        "sources: files {}, platform {}",
        list.observation.file_source,
        list.observation
            .platform_source
            .as_deref()
            .unwrap_or("not observed")
    );
    if let Some(tree) = &list.observation.working_tree {
        let dirtiness = tree.dirty.map_or(
            "undetermined",
            |dirty| if dirty { "dirty" } else { "clean" },
        );
        let _ = writeln!(
            out,
            "working tree: {} at {} ({dirtiness}, includes uncommitted files)",
            tree.root,
            short(&tree.head_commit)
        );
    }

    render_work_group(&mut out, "agent work", &list.agent_lane);
    let _ = writeln!(
        out,
        "\noperator deferred (never gates) ({})",
        list.operator_deferred.count
    );
    for item in &list.operator_deferred.items {
        let work = match (&item.remediation_code, &item.change) {
            (Some(code), Some(change)) => format!("{code} — {change}"),
            _ => item
                .none_reason
                .clone()
                .unwrap_or_else(|| "a person must settle this gap".to_owned()),
        };
        let _ = writeln!(
            out,
            "  {} [{}] {} (source: {})",
            item.rule,
            item.lane.as_deref().unwrap_or("needs-judgment"),
            work,
            item.source.as_deref().unwrap_or("not observed")
        );
    }

    render_unsettled_group(&mut out, "needs a decision", &list.needs_decision);
    render_unsettled_group(&mut out, "run errors", &list.run_errors);
    render_unsettled_group(&mut out, "routed (exit code unchanged)", &list.routed);
    render_unsettled_group(&mut out, "unbuilt (exit code unchanged)", &list.unbuilt);
    render_attention_group(&mut out, "waived (not evaluated)", &list.waived);

    let gating_unsettled = list
        .needs_decision
        .items
        .iter()
        .chain(&list.run_errors.items)
        .filter(|item| item.gating)
        .count();
    let _ = writeln!(out, "\nunsettled gating questions: {gating_unsettled}");
    let _ = writeln!(
        out,
        "routed: {}, unbuilt: {}, waived: {}",
        list.routed.count, list.unbuilt.count, list.waived.count
    );
    let _ = writeln!(
        out,
        "\n{} — this is not a repository conformance verdict",
        list.outcome.code()
    );
    out
}

fn render_unsettled_group(
    out: &mut String,
    heading: &str,
    group: &crate::worklist::WorkGroup<crate::worklist::UnsettledItem>,
) {
    let _ = writeln!(out, "\n{heading} ({})", group.count);
    for item in &group.items {
        let _ = writeln!(
            out,
            "  {} [{}] {} ({}, evidence: {}, source: {})",
            item.rule,
            item.severity,
            item.status.map_or(
                if item.gating {
                    "run-error"
                } else if heading.starts_with("unbuilt") {
                    "unbuilt"
                } else {
                    "routed"
                },
                Status::code
            ),
            if item.gating { "gating" } else { "non-gating" },
            item.evidence_code.as_deref().unwrap_or("none"),
            item.source.as_deref().unwrap_or("not observed")
        );
        // Where the answer is taken, when the registry named a surface that
        // can take it. The wording is the declaration's, not this renderer's.
        if let Some(reason) = &item.reason {
            let _ = writeln!(out, "      reason: {reason}");
        }
        if let Some(surface) = item.verified_by.as_deref() {
            let guidance = registry::VerificationSurface::ALL
                .iter()
                .find(|declared| declared.code() == surface)
                .map(|declared| declared.guidance());
            match guidance {
                Some(guidance) => {
                    let _ = writeln!(out, "      {surface}: {guidance}");
                }
                None => {
                    let _ = writeln!(out, "      {surface}");
                }
            }
        }
    }
}

fn render_attention_group(
    out: &mut String,
    heading: &str,
    group: &crate::worklist::WorkGroup<crate::worklist::AttentionItem>,
) {
    let _ = writeln!(out, "\n{heading} ({})", group.count);
    for item in &group.items {
        let _ = writeln!(
            out,
            "  {} [{}] {} (source: {})",
            item.rule,
            item.severity,
            item.status.map_or("waived", Status::code),
            item.source.as_deref().unwrap_or("not observed")
        );
        if let Some(reason) = &item.reason {
            let _ = writeln!(out, "      reason: {reason}");
        }
    }
}

fn render_work_group(
    out: &mut String,
    heading: &str,
    group: &crate::worklist::WorkGroup<crate::worklist::WorkItem>,
) {
    let _ = writeln!(out, "\n{heading} ({})", group.count);
    for item in &group.items {
        let _ = writeln!(
            out,
            "  {} [{}] {} — {} (source: {})",
            item.rule,
            item.lane,
            item.remediation_code,
            item.change,
            item.source.as_deref().unwrap_or("not observed")
        );
    }
}

/// Render, for a terminal, the changes a report implies.
///
/// The rendering says what it is: a display, computed from the observation
/// above it and true only of that observation. Nothing reads it back. Aligning
/// re-observes each rule as it reaches it, so a plan cannot go stale between
/// being printed and being acted on — there is nothing to go stale.
#[must_use]
pub fn plan_text(report: &Report) -> String {
    let plan = Plan::derive(report);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} at {}",
        report.repository.full_name,
        short(&report.repository.audited_commit)
    );
    let _ = writeln!(
        out,
        "policy {} from {} (bundle {})",
        report.policy.name,
        report.policy.source,
        short_digest(&report.policy.bundle_digest)
    );
    let _ = writeln!(
        out,
        "registry {} ({})",
        report.airlock.registry_version,
        short_digest(&report.airlock.registry_digest)
    );
    out.push('\n');
    let _ = writeln!(
        out,
        "This is what airlock would change, as observed just now. It is a \
         display,\nnot a work order: aligning re-observes each rule before it \
         acts, and never\napplies a plan computed earlier."
    );

    if plan.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "No change is proposed for the evaluated standards.");
    }

    for lane in plan::DISPLAY_ORDER {
        let changes: Vec<_> = plan.in_lane(*lane).collect();
        if changes.is_empty() {
            continue;
        }
        out.push('\n');
        let _ = writeln!(
            out,
            "{} ({}) — {}",
            lane.code(),
            changes.len(),
            plan::lane_gloss(*lane)
        );
        for change in changes {
            let _ = writeln!(
                out,
                "  {:<16} {:<13} {}",
                change.rule, change.severity, change.code
            );
            let _ = writeln!(out, "      {}", change.change);
            if let Some(detail) = change.detail {
                let _ = writeln!(out, "      observed: {detail}");
            }
            let _ = writeln!(
                out,
                "      {}",
                if change.reversible {
                    "reversible"
                } else {
                    "not reversible — there is no undo for this one"
                }
            );
        }
    }

    if !plan.unclosable.is_empty() {
        out.push('\n');
        let _ = writeln!(
            out,
            "no remediation ({}) — airlock offers none; the only move left is a \
             person's",
            plan.unclosable.len()
        );
        for gap in &plan.unclosable {
            let _ = writeln!(
                out,
                "  {:<16} {:<13} {}",
                gap.rule,
                gap.severity,
                gap.status.map_or("run-error", Status::code)
            );
            let _ = writeln!(out, "      {}", gap.reason);
        }
    }

    let _ = writeln!(out, "\nwaived ({})", plan.waived.len());
    for finding in &plan.waived {
        let reason = finding
            .suppression
            .as_ref()
            .and_then(|w| w.policy_reason.as_ref().or(w.requested_reason.as_ref()))
            .map_or("not configured", String::as_str);
        let _ = writeln!(out, "  {} — {}", finding.rule, reason);
    }
    for (heading, unbuilt) in [("routed", false), ("unbuilt", true)] {
        let rules: Vec<_> = plan
            .routed
            .iter()
            .filter(|r| (r.reason == "unbuilt") == unbuilt)
            .collect();
        let _ = writeln!(
            out,
            "\n{heading} ({}) — no Met or Gap outcome; exit code unchanged",
            rules.len()
        );
        for rule in rules {
            let _ = writeln!(
                out,
                "  {} [{}] {} — {}",
                rule.rule, rule.severity, rule.reason, rule.settling_surface
            );
            if let Some(detail) = rule.detail {
                let _ = writeln!(out, "      {detail}");
            }
            if let Some(surface) = rule.verified_by {
                let _ = writeln!(out, "      {}: {}", surface.code(), surface.guidance());
            }
        }
    }
    let _ = writeln!(out, "\nrun errors ({})", plan.run_errors.len());
    for error in &plan.run_errors {
        let _ = writeln!(
            out,
            "  run-error: {} [{}] — makes the run incomplete",
            error.rule, error.severity
        );
    }
    if plan.is_incomplete() {
        let _ = writeln!(
            out,
            "The run is incomplete; no audit result can be certified."
        );
    } else if plan.routed.is_empty() && plan.waived.is_empty() {
        let _ = writeln!(
            out,
            "Every standard was evaluated; this names each observed gap."
        );
    } else {
        let _ = writeln!(out, "No run errors. The waived, routed, and unbuilt standards above have no Met or Gap outcome.");
    }

    out
}

/// Render the check registry for a terminal.
#[must_use]
pub fn list_checks_text() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "registry {} ({})",
        registry::REGISTRY_VERSION,
        registry::digest()
    );
    let _ = writeln!(out);
    for section in registry::Section::ALL {
        let _ = writeln!(out, "[{section}]");
        for check in registry::in_section(*section) {
            let _ = writeln!(
                out,
                "  {:<16} {:<12} {:<14} {}",
                check.id,
                check.severity.code(),
                if check.unbuilt_reason().is_some() {
                    "unbuilt gate"
                } else {
                    "compiled"
                },
                check.statement
            );
            // The declared remediation is printed with the rule so an adopter
            // can read what airlock would do to their repository before
            // running it against one. It is read from the same table the
            // findings document quotes, so the catalogue cannot drift from
            // what a run reports.
            match remediation::classify(check.id) {
                Some(Classification::Remediation(definition)) => {
                    let _ = writeln!(
                        out,
                        "  {:<16} → {} [{}, {}] {}",
                        "",
                        definition.code,
                        definition.lane.code(),
                        if definition.reversible {
                            "reversible"
                        } else {
                            "not reversible"
                        },
                        definition.change
                    );
                }
                Some(Classification::NotRemediable { reason, .. }) => {
                    let _ = writeln!(out, "  {:<16} → no remediation: {reason}", "");
                }
                None => {}
            }
            // A policy author has to be able to see, before running anything,
            // which rules require admin access and where they are verified.
            if let Some(gate) = check.disclosure_gate() {
                let _ = writeln!(
                    out,
                    "  {:<16} ⊗ requires {} — {}; verified by {}",
                    "",
                    gate.requires,
                    gate.rationale(),
                    gate.verified_by.code()
                );
            }
        }
        let _ = writeln!(out);
    }
    out
}

/// Render the check registry as JSON.
#[must_use]
pub fn list_checks_json() -> serde_json::Value {
    serde_json::json!({
        "registry_version": registry::REGISTRY_VERSION,
        "registry_digest": registry::digest(),
        "checks": registry::CHECKS.iter().map(check_json).collect::<Vec<_>>(),
    })
}

fn check_json(check: &CheckDefinition) -> serde_json::Value {
    serde_json::json!({
        "id": check.id,
        "statement": check.statement,
        "severity": check.severity.code(),
        "section": check.section.code(),
        "remediation_class": RemediationClass::for_rule(check.id),
        "evaluation": if check.unbuilt_reason().is_some() { "unbuilt gate" } else { "compiled" },
        "unbuilt_reason": check.unbuilt_reason(),
        "disclosure_gate": check.disclosure_gate().map(|gate| serde_json::json!({
            "fact": gate.fact,
            "evidence_code": gate.evidence_code,
            "requires": gate.requires.code(),
            "insufficient": gate
                .insufficient
                .iter()
                .map(|grant| grant.code())
                .collect::<Vec<_>>(),
            "verified_by": gate.verified_by.code(),
            "rationale": gate.rationale(),
        })),
        "needs_github_api": check.needs_github_api(),
        "params": check.params.iter().map(|parameter| parameter.name).collect::<Vec<_>>(),
    })
}

/// The surfaces that verify what this run could not observe, in declaration
/// order and named once each.
///
/// Read from the gate each rule declares, so no renderer writes the guidance
/// sentence itself.
fn verification_surfaces(report: &Report) -> Vec<registry::VerificationSurface> {
    registry::VerificationSurface::ALL
        .iter()
        .copied()
        .filter(|surface| {
            report.entries().any(|finding| {
                finding.routing.is_some()
                    && registry::find(&finding.rule)
                        .and_then(registry::CheckDefinition::disclosure_gate)
                        .is_some_and(|gate| gate.verified_by == *surface)
            })
        })
        .collect()
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

fn short_digest(digest: &str) -> String {
    match digest.split_once(':') {
        Some((algorithm, value)) => format!("{algorithm}:{}", short(value)),
        None => digest.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        AirlockIdentity, AuditedRepository, Evidence, Finding, ObservationRecord, PolicyIdentity,
        Remediation, RemediationClass,
    };
    use crate::ActionGroup;

    fn report() -> Report {
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "owner/name".to_owned(),
                id: Some(1),
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            ObservationRecord::api(),
            PolicyIdentity {
                name: "test".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                sources: vec![crate::findings::PolicySourceIdentity {
                    name: "topics".to_owned(),
                    source: "owner/.github:airlock/topics.yml".to_owned(),
                    commit: Some("c".repeat(40)),
                    blob_sha: Some("d".repeat(40)),
                    content_digest: format!("sha256:{}", "e".repeat(64)),
                }],
                bundle_digest: format!("sha256:{}", "b".repeat(64)),
            },
            Vec::new(),
            Vec::new(),
            vec![Finding {
                rule: "REPO-LIC-01".to_owned(),
                statement: "A `LICENSE` file exists".to_owned(),
                severity: "blocking".to_owned(),
                status: Some(Status::Gap),
                evidence: Some(Evidence::at("file_missing", "LICENSE", "LICENSE is absent")),
                remediation: Some(Remediation::new(ActionGroup::ADD_FILE, "Add LICENSE.")),
                remediation_class: RemediationClass::for_rule("REPO-LIC-01"),
                suppression: None,
                source: Some("api".to_owned()),
                error: None,
                routing: None,
            }],
        )
    }

    #[test]
    fn the_text_report_shows_the_rule_its_statement_and_the_remedy() {
        let text = report_text(&report());
        assert!(text.contains("REPO-LIC-01 | A `LICENSE` file exists"));
        assert!(text.contains("gap"));
        assert!(text.contains("Add LICENSE."));
        assert!(text.contains("nonconformant"));
    }

    #[test]
    fn the_text_report_names_what_each_policy_source_pinned_to() {
        let text = report_text(&report());
        assert!(text.contains("topics"));
        assert!(text.contains("owner/.github:airlock/topics.yml@cccccccccccc"));
        assert!(text.contains("blob dddddddddddd"));
    }

    #[test]
    fn the_text_report_shortens_digests_rather_than_dropping_them() {
        let text = report_text(&report());
        assert!(text.contains("sha256:bbbbbbbbbbbb"));
        assert!(!text.contains(&"b".repeat(64)));
    }

    #[test]
    fn the_summary_line_names_every_status_in_the_taxonomy() {
        let text = report_text(&report());
        for status in Status::ALL {
            assert!(
                text.contains(status.code()),
                "{} is missing from the summary line",
                status.code()
            );
        }
        assert!(text.contains("1 gap"));
        assert!(text.contains("0 met"));
    }

    #[test]
    fn the_plan_names_the_change_its_code_and_its_reversibility() {
        let text = plan_text(&report());
        assert!(text.contains("add-license-file"));
        assert!(text.contains("Add a `LICENSE` file"));
        assert!(text.contains("not reversible"));
        assert!(text.contains("deterministic-file (1)"));
    }

    #[test]
    fn the_plan_says_it_is_a_display_and_not_a_stored_work_order() {
        let text = plan_text(&report());
        assert!(text.contains("display"));
        assert!(text.contains("re-observes each rule before it"));
        assert!(text.contains("never\napplies a plan computed earlier"));
    }

    #[test]
    fn the_plan_reports_the_completeness_of_the_observation_it_came_from() {
        let text = plan_text(&report());
        assert!(text.contains("Every standard was evaluated"));
    }

    #[test]
    fn a_plan_holding_an_admin_only_rule_never_claims_everything_was_decided() {
        let mut source = report();
        source.findings[0].rule = "REPO-GIT-04".to_owned();
        source.findings[0] = crate::findings::fixtures::routed(source.findings[0].clone());
        let admin_only = crate::findings::Report::assemble(
            source.airlock.clone(),
            source.repository.clone(),
            source.observation.clone(),
            source.policy.clone(),
            Vec::new(),
            Vec::new(),
            source.findings.clone(),
        );

        let text = plan_text(&admin_only);
        assert!(
            !text.contains("Every standard was evaluated"),
            "one rule is undecided, and the plan has just said so: {text}"
        );
        assert!(text.contains("No run errors"), "{text}");
        assert!(
            text.contains("no Met or Gap outcome"),
            "the plan states the limit of what it names: {text}"
        );
    }

    #[test]
    fn the_plan_names_an_advisory_run_error_as_incomplete() {
        let mut error = report();
        error.findings[0].status = None;
        error.findings[0].severity = "advisory".to_owned();
        let text = plan_text(&error);
        assert!(text.contains("REPO-LIC-01"));
        assert!(text.contains("makes the run incomplete"));
    }

    #[test]
    fn the_report_and_plan_both_name_a_rule_that_requires_admin_access() {
        // A rule the registry declares gated, so the guidance the surfaces
        // print has a declaration to come from.
        let mut source = report();
        source.findings[0].rule = "REPO-GIT-04".to_owned();
        source.findings[0] = crate::findings::fixtures::routed(source.findings[0].clone());
        let admin_only = crate::findings::Report::assemble(
            source.airlock.clone(),
            source.repository.clone(),
            source.observation.clone(),
            source.policy.clone(),
            Vec::new(),
            Vec::new(),
            source.findings.clone(),
        );
        let surface = registry::MERGE_SETTINGS_DISCLOSURE.verified_by;

        assert!(
            admin_only.complete,
            "a structural gap leaves the run complete"
        );
        let text = report_text(&admin_only);
        assert!(text.contains("routed: 1"), "{text}");
        assert!(
            text.contains("never gating, and never a pass"),
            "the run is complete, so the report itself must name the gap: {text}"
        );
        assert!(
            text.contains(surface.guidance()),
            "the report takes its guidance from the declaration: {text}"
        );

        let plan = plan_text(&admin_only);
        assert!(plan.contains("routed (1)"), "{plan}");
        assert!(plan.contains("REPO-GIT-04"), "{plan}");
        assert!(plan.contains(surface.code()), "{plan}");
        assert!(
            plan.contains(surface.guidance()),
            "the plan says where the answer lives, in the declaration's words: {plan}"
        );
        assert!(
            !plan.contains("undecided: REPO-GIT-04"),
            "it is not filed with the questions a retry here could answer: {plan}"
        );
    }

    #[test]
    fn a_structural_gap_no_rule_declares_promises_no_destination() {
        // The checks make this unreachable, and if it ever happened the
        // surfaces must say what they know and no more: the gap is named, and
        // no destination is invented for it.
        let mut source = report();
        source.findings[0].status = None;
        let undeclared = crate::findings::Report::assemble(
            source.airlock.clone(),
            source.repository.clone(),
            source.observation.clone(),
            source.policy.clone(),
            Vec::new(),
            Vec::new(),
            source.findings.clone(),
        );

        assert!(registry::find("REPO-LIC-01")
            .and_then(registry::CheckDefinition::disclosure_gate)
            .is_none());
        let text = report_text(&undeclared);
        assert!(text.contains("run errors: 1"), "{text}");
        assert!(
            !text.contains(registry::VerificationSurface::InteractiveSession.guidance()),
            "no surface was declared, so none is promised: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("interactive")
                && !text.to_ascii_lowercase().contains("admin mode"),
            "the report must not invent destination prose: {text}"
        );
        let plan = plan_text(&undeclared);
        assert!(plan.contains("run-error"), "{plan}");
        assert!(plan.contains("REPO-LIC-01"), "{plan}");
        assert!(
            !plan.contains(registry::VerificationSurface::InteractiveSession.code()),
            "{plan}"
        );
        assert!(
            !plan.to_ascii_lowercase().contains("interactive")
                && !plan.to_ascii_lowercase().contains("admin mode"),
            "the plan must not invent destination prose: {plan}"
        );
    }

    #[test]
    fn the_check_listing_publishes_every_declared_disclosure_gate() {
        let text = list_checks_text();
        let json = list_checks_json();
        let gate = &registry::MERGE_SETTINGS_DISCLOSURE;

        // A policy author reads this before pointing airlock at anything, so
        // which rules require admin access has to be in it.
        assert!(text.contains(gate.requires.code()), "{text}");
        assert!(text.contains(gate.verified_by.code()), "{text}");
        assert!(
            text.contains(registry::Grant::ADMINISTRATION_READ.code()),
            "the grant that looks sufficient and is not must be named: {text}"
        );

        let checks = json["checks"].as_array().expect("checks are an array");
        let git04 = checks
            .iter()
            .find(|check| check["id"] == "REPO-GIT-04")
            .expect("REPO-GIT-04 is registered");
        assert_eq!(git04["disclosure_gate"]["requires"], "contents:write");
        assert_eq!(
            git04["disclosure_gate"]["verified_by"],
            "interactive-session"
        );
        assert_eq!(
            git04["disclosure_gate"]["evidence_code"],
            "merge_settings_unavailable"
        );
        let lic01 = checks
            .iter()
            .find(|check| check["id"] == "REPO-LIC-01")
            .expect("REPO-LIC-01 is registered");
        assert!(lic01["disclosure_gate"].is_null());
    }

    #[test]
    fn the_plan_says_when_an_undecided_rule_stops_the_run() {
        let mut gated = report();
        gated.findings[0].status = None;
        let text = plan_text(&gated);

        assert!(text.contains("run-error: REPO-LIC-01"), "{text}");
        assert!(text.contains("makes the run incomplete"), "{text}");
        assert!(text.contains("no audit result can be certified"), "{text}");
    }

    #[test]
    fn a_plan_with_nothing_to_propose_says_so_rather_than_rendering_empty() {
        let mut clean = report();
        clean.findings[0].status = Some(Status::Met);
        let text = plan_text(&clean);
        assert!(text.contains("No change is proposed"));
        assert!(!text.contains("add-license-file"));
    }

    #[test]
    fn every_registered_check_appears_in_the_listing() {
        let text = list_checks_text();
        for check in registry::CHECKS {
            assert!(text.contains(check.id), "{} is missing", check.id);
        }
    }

    #[test]
    fn the_listing_says_what_closing_every_rule_would_take() {
        let text = list_checks_text();
        for classification in crate::remediation::CLASSIFICATIONS {
            match classification {
                Classification::Remediation(definition) => {
                    assert!(
                        text.contains(definition.code),
                        "{} is listed without its remediation code",
                        definition.rule
                    );
                    assert!(
                        text.contains(definition.lane.code()),
                        "{} is listed without its lane",
                        definition.rule
                    );
                }
                Classification::NotRemediable { rule, reason } => {
                    assert!(
                        text.contains(reason),
                        "{rule} is listed without the reason airlock offers no remediation"
                    );
                }
            }
        }
    }

    #[test]
    fn the_json_listing_publishes_the_remediation_model_verbatim() {
        // Compared against the model itself, not against the helper the
        // listing is built with — comparing the listing to a second call of
        // its own builder would pass even if both stopped saying anything.
        // That the listing agrees with a real *run* is proved in
        // `tests/remediation_catalogue.rs`, which audits a repository.
        let json = list_checks_json();
        let listed: std::collections::BTreeMap<&str, &serde_json::Value> = json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| (check["id"].as_str().unwrap(), &check["remediation_class"]))
            .collect();

        assert_eq!(listed.len(), crate::remediation::CLASSIFICATIONS.len());
        for classification in crate::remediation::CLASSIFICATIONS {
            let rule = classification.rule();
            let entry = listed
                .get(rule)
                .unwrap_or_else(|| panic!("{rule} is missing from the listing"));
            match classification {
                Classification::Remediation(definition) => {
                    assert_eq!(entry["code"], definition.code, "{rule}");
                    assert_eq!(entry["lane"], definition.lane.code(), "{rule}");
                    assert_eq!(entry["change"], definition.change, "{rule}");
                    assert_eq!(entry["reversible"], definition.reversible, "{rule}");
                    assert!(entry["none_reason"].is_null(), "{rule}");
                }
                Classification::NotRemediable { reason, .. } => {
                    assert_eq!(entry["none_reason"], *reason, "{rule}");
                    assert!(entry["code"].is_null(), "{rule}");
                }
            }
        }
    }

    #[test]
    fn the_json_listing_marks_unimplemented_checks() {
        let json = list_checks_json();
        let checks = json["checks"].as_array().unwrap();
        assert_eq!(checks.len(), registry::CHECKS.len());
        let unimplemented = checks
            .iter()
            .filter(|check| check["unbuilt_reason"].is_string())
            .count();
        assert_eq!(
            unimplemented,
            registry::CHECKS
                .iter()
                .filter(|check| check.unbuilt_reason().is_some())
                .count()
        );
    }
}
