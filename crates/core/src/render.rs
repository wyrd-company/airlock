//! Human-readable renderings of the machine documents.
//!
//! The JSON is the contract. Everything here is a view of exactly the same
//! data, so a human and a pipeline never see different answers.

use std::fmt::Write as _;

use crate::findings::{Report, Status};
use crate::registry::{self, CheckDefinition};

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

fn check_json(check: &CheckDefinition) -> serde_json::Value {
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
        AirlockIdentity, AuditedRepository, Evidence, Finding, Gate, ObservationRecord,
        PolicyIdentity, Remediation, RemediationClass,
    };

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
                remediation_class: RemediationClass::for_rule("REPO-LIC-01"),
                suppression: None,
                source: Some("api".to_owned()),
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
        assert!(text.contains("1 fail"));
        assert!(text.contains("0 pass"));
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
