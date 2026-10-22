// ---
// relationships:
//   implements: terminal-interface
//   references: release-process-conformance
// ---

//! Human-readable renderings of the machine documents.
//!
//! The JSON is the contract. Everything here is a view of exactly the same
//! data, so a human and a pipeline never see different answers.

use std::fmt::Write as _;

use crate::findings::{FixClass, Report, Status};
use crate::fix::{self, FixAvailability};
use crate::rules::{self, RuleDefinition};
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
        "rules {} ({})",
        report.airlock.rules_version,
        short_digest(&report.airlock.rules_digest)
    );
    let _ = writeln!(
        out,
        "waived: {}, routed: {}, unbuilt: {}, out-of-scope: {}, run errors: {}",
        report.summary.waived,
        report.summary.routed,
        report.summary.unbuilt,
        report.summary.out_of_scope,
        report.summary.run_errors
    );
    if let Some(maturity) = &report.maturity {
        if let Some(observed) = &maturity.observed {
            let _ = writeln!(out, "maturity: {}", observed.rung.code());
            for transition in &maturity.transitions {
                let _ = writeln!(
                    out,
                    "  {} adds {} rules; {} already pass",
                    transition.rung.code(),
                    transition.adds,
                    transition.already_met
                );
            }
        } else if let Some(error) = &maturity.error {
            let _ = writeln!(out, "maturity: unobserved — {error}");
        }
    }
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
        if finding.new {
            let _ = writeln!(out, "              new rule; generation not accepted");
        }
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
            let class = &finding.fix_class;
            if let (Some(code), Some(change), Some(kind)) =
                (&class.code, &class.change, &class.fix_kind)
            {
                let _ = writeln!(out, "              fix {code} [{kind}] — {change}");
                if let Some(reversible) = class.reversible {
                    let _ = writeln!(
                        out,
                        "              {}",
                        if reversible {
                            "reversible"
                        } else {
                            "not reversible — there is no undo for this one"
                        }
                    );
                }
            } else if let Some(reason) = &class.none_reason {
                let _ = writeln!(out, "              no fix — {reason}");
            }
            if let Some(fix) = &finding.fix {
                let _ = writeln!(out, "              → {}", fix.detail);
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
        .filter(|f| rules::find(&f.rule).is_some_and(|d| d.disclosure_gate().is_some()))
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

    let _ = writeln!(out, "Fixes are a display. Airlock re-observes each rule before it acts; it never applies a remembered observation.");
    out
}

/// Render the agent-work definition-of-done result for a terminal.
#[must_use]
pub fn agent_work_list_text(list: &AgentWorkList) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} at {} — agent work only; not repository conformance",
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

    render_work_group(&mut out, "agent work", &list.agent_work);
    let _ = writeln!(
        out,
        "\noperator deferred (never gates) ({})",
        list.operator_deferred.count
    );
    for item in &list.operator_deferred.items {
        let work = match (&item.fix_code, &item.change) {
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
            item.fix_kind.as_deref().unwrap_or("needs-judgment"),
            work,
            item.source.as_deref().unwrap_or("not observed")
        );
    }

    render_deferred_group(&mut out, "run errors", &list.run_errors);
    render_deferred_group(&mut out, "routed (exit code unchanged)", &list.routed);
    render_deferred_group(&mut out, "unbuilt (exit code unchanged)", &list.unbuilt);
    render_deferred_group(
        &mut out,
        "out-of-scope (exit code unchanged)",
        &list.out_of_scope,
    );
    render_attention_group(&mut out, "waived (not evaluated)", &list.waived);

    let gating_unsettled = list
        .run_errors
        .items
        .iter()
        .filter(|item| item.gating)
        .count();
    let _ = writeln!(
        out,
        "\nrun errors blocking completeness: {gating_unsettled}"
    );
    let _ = writeln!(
        out,
        "routed: {}, unbuilt: {}, out-of-scope: {}, waived: {}",
        list.routed.count, list.unbuilt.count, list.out_of_scope.count, list.waived.count
    );
    let _ = writeln!(
        out,
        "\n{} — this is not a repository conformance verdict",
        list.outcome.code()
    );
    out
}

fn render_deferred_group(
    out: &mut String,
    heading: &str,
    group: &crate::worklist::WorkGroup<crate::worklist::DeferredRule>,
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
                } else if heading.starts_with("out-of-scope") {
                    "out-of-scope"
                } else {
                    "routed"
                },
                Status::code
            ),
            if item.gating { "gating" } else { "non-gating" },
            item.evidence_code.as_deref().unwrap_or("none"),
            item.source.as_deref().unwrap_or("not observed")
        );
        // Where the answer is taken, when the rules named a surface that
        // can take it. The wording is the declaration's, not this renderer's.
        if let Some(reason) = &item.reason {
            let _ = writeln!(out, "      reason: {reason}");
        }
        if let Some(surface) = item.verified_by.as_deref() {
            let guidance = rules::VerificationSurface::ALL
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
            item.fix_kind,
            item.fix_code,
            item.change,
            item.source.as_deref().unwrap_or("not observed")
        );
    }
}

/// Render the rules for a terminal.
#[must_use]
pub fn list_rules_text() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "rules {} ({})", rules::RULES_VERSION, rules::digest());
    let _ = writeln!(out);
    for section in rules::Section::ALL {
        let _ = writeln!(out, "[{section}]");
        for check in rules::in_section(*section) {
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
            // The declared fix is printed with the rule so an adopter
            // can read what airlock would do to their repository before
            // running it against one. It is read from the same table the
            // findings document quotes, so the catalogue cannot drift from
            // what a run reports.
            match fix::classify(check.id) {
                Some(FixAvailability::Fix(definition)) => {
                    let _ = writeln!(
                        out,
                        "  {:<16} → {} [{}, {}] {}",
                        "",
                        definition.code,
                        definition.fix_kind.code(),
                        if definition.reversible {
                            "reversible"
                        } else {
                            "not reversible"
                        },
                        definition.change
                    );
                }
                Some(FixAvailability::NotFixable { reason, .. }) => {
                    let _ = writeln!(out, "  {:<16} → no fix: {reason}", "");
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

/// Render the rules as JSON.
#[must_use]
pub fn list_rules_json() -> serde_json::Value {
    serde_json::json!({
        "rules_version": rules::RULES_VERSION,
        "rules_digest": rules::digest(),
        "rules": rules::RULES.iter().map(check_json).collect::<Vec<_>>(),
    })
}

fn check_json(check: &RuleDefinition) -> serde_json::Value {
    serde_json::json!({
        "id": check.id,
        "statement": check.statement,
        "severity": check.severity.code(),
        "section": check.section.code(),
        "lifecycle": check.lifecycle.code(),
        "fix_class": FixClass::for_rule(check.id),
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
        "needs_release_units": check.needs_release_units(),
        "required_topic_categories": check.required_topic_categories(),
        "params": check.params.iter().map(|parameter| parameter.name).collect::<Vec<_>>(),
    })
}

/// The surfaces that verify what this run could not observe, in declaration
/// order and named once each.
///
/// Read from the gate each rule declares, so no renderer writes the guidance
/// sentence itself.
fn verification_surfaces(report: &Report) -> Vec<rules::VerificationSurface> {
    rules::VerificationSurface::ALL
        .iter()
        .copied()
        .filter(|surface| {
            report.entries().any(|finding| {
                finding.routing.is_some()
                    && rules::find(&finding.rule)
                        .and_then(rules::RuleDefinition::disclosure_gate)
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
        AirlockIdentity, AuditedRepository, Evidence, Finding, Fix, FixClass, ObservationRecord,
        PolicyIdentity,
    };
    use crate::FixGroup;

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
                new: false,
                rule: "REPO-LIC-01".to_owned(),
                statement: "A `LICENSE` file exists".to_owned(),
                severity: "blocking".to_owned(),
                status: Some(Status::Gap),
                evidence: Some(Evidence::at("file_missing", "LICENSE", "LICENSE is absent")),
                fix: Some(Fix::new(FixGroup::ADD_FILE, "Add LICENSE.")),
                fix_class: FixClass::for_rule("REPO-LIC-01"),
                suppression: None,
                source: Some("api".to_owned()),
                error: None,
                routing: None,
            }],
        )
    }

    #[test]
    fn a_new_rule_reports_its_gap_without_binding_until_accepted() {
        let before = report();
        let mut finding = before.findings[0].clone();
        finding.new = true;
        let after = Report::assemble(
            before.airlock,
            before.repository,
            before.observation,
            before.policy,
            Vec::new(),
            Vec::new(),
            vec![finding.clone()],
        );
        assert_eq!(after.exit_code(), 0);
        assert_eq!(after.findings[0].status, Some(Status::Gap));
        assert!(report_text(&after).contains("new rule; generation not accepted"));
        finding.new = false;
        let accepted = Report::assemble(
            after.airlock,
            after.repository,
            after.observation,
            after.policy,
            Vec::new(),
            Vec::new(),
            vec![finding],
        );
        assert_eq!(accepted.exit_code(), 1);
    }

    #[test]
    fn a_new_rule_run_error_still_makes_the_audit_incomplete() {
        let before = report();
        let mut finding = before.findings[0].clone();
        finding.new = true;
        finding.status = None;
        let after = Report::assemble(
            before.airlock,
            before.repository,
            before.observation,
            before.policy,
            Vec::new(),
            Vec::new(),
            vec![finding],
        );
        assert_eq!(after.exit_code(), 2);
        assert!(!after.complete);
        assert_eq!(after.run_errors.len(), 1);
    }

    #[test]
    fn audit_displays_declared_fix_only_for_an_observed_gap() {
        let mut source = report();
        let text = report_text(&source);
        assert!(text.contains("fix add-license-file [airlock]"));
        assert!(text.contains("not reversible"));
        assert!(text.contains("re-observes each rule before it acts"));
        for status in [Some(Status::Met), None] {
            source.findings[0].status = status;
            assert!(!report_text(&source).contains("fix add-license-file"));
        }
    }

    #[test]
    fn audit_keeps_the_no_fix_reason_and_contextual_detail() {
        let mut source = report();
        source.findings[0].fix_class = FixClass::for_rule("REPO-GIT-08");
        source.findings[0].fix = Some(crate::findings::Fix::new(
            crate::FixGroup::CORRECT_MERGE_SETTINGS,
            "contextual instruction",
        ));
        let text = report_text(&source);
        assert!(text.contains("no fix —"));
        assert!(text.contains("history surgery"));
        assert!(text.contains("contextual instruction"));
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
    fn the_report_names_a_rule_that_requires_admin_access() {
        // A rule the rules declare gated, so the guidance the surfaces
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
        let surface = rules::MERGE_SETTINGS_DISCLOSURE.verified_by;

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

        assert!(rules::find("REPO-LIC-01")
            .and_then(rules::RuleDefinition::disclosure_gate)
            .is_none());
        let text = report_text(&undeclared);
        assert!(text.contains("run errors: 1"), "{text}");
        assert!(
            !text.contains(rules::VerificationSurface::InteractiveSession.guidance()),
            "no surface was declared, so none is promised: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("interactive")
                && !text.to_ascii_lowercase().contains("admin mode"),
            "the report must not invent destination prose: {text}"
        );
    }

    #[test]
    fn the_check_listing_publishes_every_declared_disclosure_gate() {
        let text = list_rules_text();
        let json = list_rules_json();
        let gate = &rules::MERGE_SETTINGS_DISCLOSURE;

        // A policy author reads this before pointing airlock at anything, so
        // which rules require admin access has to be in it.
        assert!(text.contains(gate.requires.code()), "{text}");
        assert!(text.contains(gate.verified_by.code()), "{text}");
        assert!(
            text.contains(rules::Grant::ADMINISTRATION_READ.code()),
            "the grant that looks sufficient and is not must be named: {text}"
        );

        let checks = json["rules"].as_array().expect("checks are an array");
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
    fn every_registered_check_appears_in_the_listing() {
        let text = list_rules_text();
        for check in rules::RULES {
            assert!(text.contains(check.id), "{} is missing", check.id);
        }
    }

    #[test]
    fn the_listing_says_what_closing_every_rule_would_take() {
        let text = list_rules_text();
        for classification in crate::fix::CLASSIFICATIONS {
            match classification {
                FixAvailability::Fix(definition) => {
                    assert!(
                        text.contains(definition.code),
                        "{} is listed without its fix code",
                        definition.rule
                    );
                    assert!(
                        text.contains(definition.fix_kind.code()),
                        "{} is listed without its fix kind",
                        definition.rule
                    );
                }
                FixAvailability::NotFixable { rule, reason } => {
                    assert!(
                        text.contains(reason),
                        "{rule} is listed without the reason airlock offers no fix"
                    );
                }
            }
        }
    }

    #[test]
    fn the_json_listing_publishes_the_fix_model_verbatim() {
        // Compared against the model itself, not against the helper the
        // listing is built with — comparing the listing to a second call of
        // its own builder would pass even if both stopped saying anything.
        // That the listing agrees with a real *run* is proved in
        // `tests/fix_catalogue.rs`, which audits a repository.
        let json = list_rules_json();
        let listed: std::collections::BTreeMap<&str, &serde_json::Value> = json["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| (check["id"].as_str().unwrap(), &check["fix_class"]))
            .collect();

        assert_eq!(listed.len(), crate::fix::CLASSIFICATIONS.len());
        for classification in crate::fix::CLASSIFICATIONS {
            let rule = classification.rule();
            let entry = listed
                .get(rule)
                .unwrap_or_else(|| panic!("{rule} is missing from the listing"));
            match classification {
                FixAvailability::Fix(definition) => {
                    assert_eq!(entry["code"], definition.code, "{rule}");
                    assert_eq!(entry["fix_kind"], definition.fix_kind.code(), "{rule}");
                    assert_eq!(entry["change"], definition.change, "{rule}");
                    assert_eq!(entry["reversible"], definition.reversible, "{rule}");
                    assert!(entry["none_reason"].is_null(), "{rule}");
                }
                FixAvailability::NotFixable { reason, .. } => {
                    assert_eq!(entry["none_reason"], *reason, "{rule}");
                    assert!(entry["code"].is_null(), "{rule}");
                }
            }
        }
    }

    #[test]
    fn the_json_listing_marks_unimplemented_checks() {
        let json = list_rules_json();
        let checks = json["rules"].as_array().unwrap();
        assert_eq!(checks.len(), rules::RULES.len());
        let unimplemented = checks
            .iter()
            .filter(|check| check["unbuilt_reason"].is_string())
            .count();
        assert_eq!(
            unimplemented,
            rules::RULES
                .iter()
                .filter(|check| check.unbuilt_reason().is_some())
                .count()
        );
    }
}
