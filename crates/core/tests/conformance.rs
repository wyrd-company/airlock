//! The registry is a copy of the conformance checklist, and this is what keeps
//! it one.
//!
//! `fixtures/conformance.md` is a committed copy of the authoritative
//! checklist from the `repository-standards` skill. Every rule in it must
//! appear in the registry with a byte-identical statement, the same severity,
//! section, and evaluation mode — and the registry must contain nothing else.
//! Drift in either direction fails here rather than silently changing what an
//! audit means.

use std::collections::BTreeMap;

use airlock_core::registry::{Evaluation, Section, Severity, CHECKS};

const CONFORMANCE: &str = include_str!("fixtures/conformance.md");

struct Rule {
    statement: String,
    severity: Severity,
    section: Section,
    evaluation: Evaluation,
    method: String,
}

fn section_for_heading(heading: &str) -> Option<Section> {
    match heading {
        "Identity" => Some(Section::Identity),
        "Licensing" => Some(Section::Licensing),
        "Files" => Some(Section::Files),
        "README" => Some(Section::Readme),
        "Git configuration" => Some(Section::Git),
        "Automation" => Some(Section::Automation),
        "Agent affordances" => Some(Section::Agent),
        "Documentation" => Some(Section::Docs),
        "Release" => Some(Section::Release),
        "Classification" => Some(Section::Classification),
        _ => None,
    }
}

/// Parse the checklist's rule tables.
fn parse_checklist() -> BTreeMap<String, Rule> {
    let mut rules = BTreeMap::new();
    let mut section = None;

    for line in CONFORMANCE.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = section_for_heading(heading.trim());
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }

        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        let Some(id) = cells[0]
            .strip_prefix('`')
            .and_then(|rest| rest.strip_suffix('`'))
        else {
            continue;
        };
        if !id.starts_with("REPO-") {
            continue;
        }

        let severity = Severity::parse(&cells[2].replace('*', "").trim().to_lowercase())
            .unwrap_or_else(|| panic!("{id} has an unreadable severity: {}", cells[2]));
        let evaluation = if cells[3].starts_with("Manual") {
            Evaluation::Manual
        } else if cells[3].starts_with("Unimplemented") {
            Evaluation::Unimplemented
        } else {
            Evaluation::Mechanical
        };
        let section = section.unwrap_or_else(|| panic!("{id} appears outside a known section"));

        rules.insert(
            id.to_owned(),
            Rule {
                statement: cells[1].to_owned(),
                severity,
                section,
                evaluation,
                method: cells[3].to_owned(),
            },
        );
    }

    rules
}

#[test]
fn the_checklist_fixture_parses() {
    let rules = parse_checklist();
    assert_eq!(
        rules.len(),
        109,
        "the committed checklist should carry 109 rules"
    );
}

#[test]
fn every_registered_rule_matches_the_checklist() {
    let rules = parse_checklist();
    for check in CHECKS {
        let rule = rules
            .get(check.id)
            .unwrap_or_else(|| panic!("{} is registered but not in the checklist", check.id));
        assert_eq!(
            check.statement, rule.statement,
            "{} statement drifted from the checklist",
            check.id
        );
        assert_eq!(
            check.severity, rule.severity,
            "{} severity drifted from the checklist",
            check.id
        );
        assert_eq!(
            check.section, rule.section,
            "{} section drifted from the checklist",
            check.id
        );
        assert_eq!(
            check.evaluation, rule.evaluation,
            "{} evaluation mode drifted from checklist method `{}`",
            check.id, rule.method
        );
    }
}

#[test]
fn every_checklist_rule_is_registered_exactly_once() {
    let rules = parse_checklist();
    for id in rules.keys() {
        let matches = CHECKS.iter().filter(|check| check.id == id).count();
        assert_eq!(matches, 1, "{id} is registered {matches} times");
    }
    assert_eq!(CHECKS.len(), rules.len());
}
