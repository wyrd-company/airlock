//! Template configuration regression coverage.
//
// relationships:
//   implements: release-process-conformance

#[cfg(test)]
mod tests {
    use super::super::*;

    fn compile(extra: &str) -> Result<ResolvedPolicy> {
        let text = format!("version: 0.6.0\n{extra}");
        let document = yaml::parse_mapping(&text, Limits::default().yaml).unwrap();
        compilation::compile(
            &PolicySource::Local("policy.yml".into()),
            &document,
            Vec::new(),
        )
    }
    use crate::template_identity::config::{self, RULE};
    const VALID: &str = "exceptions:\n  REPO-TPL-01:\n    reason: Expected process\n    templates: [{source: 'gh:example-org/catalog#bundle', ref: main, parts: [alpha]}]\n";

    #[test]
    fn template_exception_applies_compiled_defaults_and_organization_severity() {
        let policy = compile(VALID).unwrap();
        let rule = policy.rule(RULE).unwrap();
        assert_eq!(rule.severity, Severity::Blocking);
        assert!(!rule.def.allow_override());
        assert_eq!(rule.def.lifecycle, rules::Lifecycle::Building);
        assert!(rule.def.needs_github_api());
        assert_eq!(config::record_path(rule), ".toha.json");
        assert_eq!(config::expected(rule).unwrap()[0].target, ".");
        let policy =
            compile(&VALID.replace("    reason:", "    severity: advisory\n    reason:")).unwrap();
        assert_eq!(policy.rule(RULE).unwrap().severity, Severity::Advisory);
    }

    #[test]
    fn absent_or_empty_templates_are_not_configured() {
        for extra in [
            "",
            "exceptions:\n  REPO-TPL-01:\n    reason: Empty\n    templates: []\n",
        ] {
            assert_eq!(
                compile(extra).unwrap().rule(RULE).unwrap().severity,
                Severity::None
            );
        }
    }

    #[test]
    fn template_configuration_refuses_malformed_inputs() {
        for text in [
            VALID.replace("    reason: Expected process\n", ""),
            VALID.replace("reason: Expected process", "reason: ' '"),
            VALID.replace("ref: main", "unknown: main"),
            VALID.replace("ref: main", "ref: main, unknown: extra"),
            VALID.replace("ref: main", "ref: main, target: ''"),
            VALID.replace("ref: main", "ref: main, target: .git/record"),
            VALID.replace("ref: main", "ref: main, target: folder//record"),
            VALID.replace("ref: main", "ref: main, target: 'C:/record'"),
            VALID.replace("ref: main", "ref: main, target: 'folder\\record'"),
            VALID.replace("ref: main", "ref: ''"),
            VALID.replace(
                "gh:example-org/catalog#bundle",
                "https://example.invalid/catalog",
            ),
            VALID.replace(
                "gh:example-org/catalog#bundle",
                "gh:example-org/catalog@main",
            ),
            VALID.replace("ref: main", "ref: main, target: ../elsewhere"),
            VALID.replace("ref: main", "ref: main, target: /absolute"),
            VALID.replace("parts: [alpha]", "parts: [alpha, alpha]"),
            VALID.replace("parts: [alpha]", "parts: [Invalid]"),
            VALID.replace("parts: [alpha]", "parts: ['']"),
            VALID.replace("ref: main", "ref: main, minimum: ''"),
            VALID.replace("ref: main", "ref: main, minimum: null"),
            VALID.replace(
                "    templates:",
                "    record-path: ../record.json\n    templates:",
            ),
            VALID.replace(
                "    templates:",
                "    record-path: /record.json\n    templates:",
            ),
            VALID.replace("    templates:", "    record-path: false\n    templates:"),
            VALID.replace("    templates:", "    surprise: value\n    templates:"),
            VALID.replace(
                "parts: [alpha]",
                "parts: [alpha]}, {source: 'gh:example-org/catalog#bundle', ref: main",
            ),
        ] {
            assert!(compile(&text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn template_expectations_cannot_use_legacy_refinements_or_repository_overrides() {
        assert!(compile("checks:\n  REPO-TPL-01:\n    severity: none\n").is_err());
        assert!(compile("suppressions:\n  allow-repo-requests: [REPO-TPL-01]\n").is_err());
        let document = yaml::parse_mapping("version: 0.6.0\n", Limits::default().yaml).unwrap();
        let policy = compilation::compile(
            &PolicySource::Local("policy.yml".into()),
            &document,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(policy.rule(RULE).unwrap().severity, Severity::None);
    }
}
