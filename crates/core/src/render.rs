//! Human-readable renderings of the machine documents.
//!
//! The JSON is the contract. Everything here is a view of exactly the same
//! data, so a human and a pipeline never see different answers.

use std::fmt::Write as _;

use crate::findings::{Report, Status};
use crate::registry::{self, CheckDef};

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
    let _ = writeln!(
        out,
        "registry {} ({}), gate {}",
        report.airlock.registry_version,
        short_digest(&report.airlock.registry_digest),
        report.policy.gate.code()
    );
    out.push('\n');

    for finding in &report.findings {
        let _ = writeln!(
            out,
            "{:<13} {:<13} {} | {}",
            finding.status.code(),
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
        if let Some(suppression) = &finding.suppression {
            let _ = writeln!(
                out,
                "              suppressed by {} — {}",
                suppression.authorized_by,
                suppression
                    .policy_reason
                    .as_ref()
                    .or(suppression.requested_reason.as_ref())
                    .map_or("", String::as_str)
            );
        }
        if finding.status == Status::Fail {
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
    let summary = &report.summary;
    let _ = writeln!(
        out,
        "{} pass, {} fail, {} manual, {} suppressed, {} skipped, {} unimplemented, {} \
         inconclusive, {} error",
        summary.pass,
        summary.fail,
        summary.manual,
        summary.suppressed,
        summary.skipped,
        summary.unimplemented,
        summary.inconclusive,
        summary.error
    );
    let _ = writeln!(
        out,
        "{} — complete: {}, conformant: {}",
        report.outcome.code(),
        report.complete,
        report.conformant
    );

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
                check.evaluation.code(),
                check.statement
            );
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

fn check_json(check: &CheckDef) -> serde_json::Value {
    serde_json::json!({
        "id": check.id,
        "statement": check.statement,
        "severity": check.severity.code(),
        "section": check.section.code(),
        "evaluation": check.evaluation.code(),
        "implemented": check.evaluation != registry::Evaluation::Unimplemented,
        "params": check.params,
    })
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
        AirlockIdentity, AuditedRepository, Evidence, Finding, Gate, PolicyIdentity, Remediation,
    };

    fn report() -> Report {
        Report::assemble(
            AirlockIdentity::current("0.1.0"),
            AuditedRepository {
                full_name: "owner/name".to_owned(),
                id: 1,
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: None,
            },
            PolicyIdentity {
                name: "test".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                bundle_digest: format!("sha256:{}", "b".repeat(64)),
                gate: Gate::Blocking,
            },
            Vec::new(),
            Vec::new(),
            vec![Finding {
                rule: "REPO-LIC-01".to_owned(),
                statement: "A `LICENSE` file exists".to_owned(),
                severity: "blocking".to_owned(),
                status: Status::Fail,
                evidence: Some(Evidence::at("file_missing", "LICENSE", "LICENSE is absent")),
                remediation: Some(Remediation::new("add_file", "Add LICENSE.")),
                suppression: None,
                error: None,
            }],
        )
    }

    #[test]
    fn the_text_report_shows_the_rule_its_statement_and_the_remedy() {
        let text = report_text(&report());
        assert!(text.contains("REPO-LIC-01 | A `LICENSE` file exists"));
        assert!(text.contains("fail"));
        assert!(text.contains("Add LICENSE."));
        assert!(text.contains("nonconformant"));
    }

    #[test]
    fn the_text_report_shortens_digests_rather_than_dropping_them() {
        let text = report_text(&report());
        assert!(text.contains("sha256:bbbbbbbbbbbb"));
        assert!(!text.contains(&"b".repeat(64)));
    }

    #[test]
    fn every_registered_check_appears_in_the_listing() {
        let text = list_checks_text();
        for check in registry::CHECKS {
            assert!(text.contains(check.id), "{} is missing", check.id);
        }
    }

    #[test]
    fn the_json_listing_marks_unimplemented_checks() {
        let json = list_checks_json();
        let checks = json["checks"].as_array().unwrap();
        assert_eq!(checks.len(), registry::CHECKS.len());
        let unimplemented = checks
            .iter()
            .filter(|check| check["implemented"] == false)
            .count();
        assert_eq!(
            unimplemented,
            registry::CHECKS
                .iter()
                .filter(|check| check.evaluation == registry::Evaluation::Unimplemented)
                .count()
        );
    }
}
