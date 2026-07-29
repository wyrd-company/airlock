//! The emitted conformance checklist is a projection of the registry.
//!
//! These tests parse that projection independently and prove the generated
//! document retains every registry-owned field. There is no second checklist
//! fixture whose rule prose can drift.
//! The table parser is intentionally independent of the generator: sharing the
//! production parser would only prove that one implementation agrees with
//! itself. Its delimiter-first implementation differs from the generator's
//! streaming parser so escaping regressions require both paths to agree.

use std::collections::BTreeMap;

use airlock_core::registry::{Evaluation, Section, Severity, CHECKS};

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
    let conformance = airlock_core::skill::conformance().unwrap();
    let mut rules = BTreeMap::new();
    let mut section = None;

    for line in conformance.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = section_for_heading(heading.trim());
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }

        let cells = split_table_row(line);
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

fn split_table_row(line: &str) -> Vec<String> {
    let line = line.trim_matches('|');
    let mut cells = Vec::new();
    let mut start = 0;
    for (index, character) in line.char_indices() {
        if character == '|' {
            let preceding_slashes = line[..index]
                .chars()
                .rev()
                .take_while(|character| *character == '\\')
                .count();
            if preceding_slashes % 2 == 0 {
                cells.push(unescape_cell(line[start..index].trim()));
                start = index + character.len_utf8();
            }
        }
    }
    cells.push(unescape_cell(line[start..].trim()));
    cells
}

fn unescape_cell(cell: &str) -> String {
    let mut output = String::new();
    let mut characters = cell.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            output.push(characters.next().unwrap_or('\\'));
        } else {
            output.push(character);
        }
    }
    output
}

#[test]
fn the_generated_checklist_parses() {
    let rules = parse_checklist();
    assert_eq!(rules.len(), CHECKS.len());
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
