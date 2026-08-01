//! The policy inspector: the effective policy, and where each rule came from.
//!
//! The findings screen answers what the run concluded. This answers what the
//! run asked, which is the prior question: a verdict over a policy nobody can
//! read is a number. Every rule the run asked about is listed with its
//! severity, its evaluation mode, and its provenance; the registry digest is
//! printed in full with a statement of what it proves; and the sources block
//! says where the rules came from, including the material the policy supplied
//! rather than the registry.
//!
//! Evaluation is a property of the rule and not of the run. A manual rule
//! reports its judgment mode every time it is listed and never becomes
//! mechanical, so the column is read from the compiled registry rather than
//! from anything this run observed.
//!
//! The digest, the sources, the provenance, and the table are one reading and
//! scroll as one. None of them is a decoration of the others.

use ratatui::text::{Line, Span};

use airlock_core::findings::{Report, SuppressionSource};
use airlock_core::registry::{self, Applicability, Severity};

use crate::admin::text::sanitize;

use super::chrome::fit;
use super::lane;
use super::panel::{self, field_at, heading, Provenance, Scroll};
use super::theme::{Role, Styles};

/// The column every labelled value on this screen starts in.
pub const LABEL_WIDTH: usize = 16;

/// The most any one value may be.
const VALUE_LIMIT: usize = 400;

/// How much of a digest the status line quotes.
///
/// Enough to tell two registries apart at a glance, never enough to be mistaken
/// for the digest itself — which is why the abbreviation is marked, and why the
/// screen prints the whole of it above.
const DIGEST_PREFIX: usize = 8;

/// The indent every table row carries, so the table reads as one block.
const INDENT: &str = "  ";

/// The width the rule id column is printed in.
const RULE_WIDTH: usize = 16;

/// The width the severity bar and its name are printed in.
const SEVERITY_WIDTH: usize = 15;

/// The width the evaluation column is printed in.
const EVALUATION_WIDTH: usize = 14;

/// Everything a table row spends before its provenance.
const SPENT: usize = INDENT.len() + RULE_WIDTH + SEVERITY_WIDTH + EVALUATION_WIDTH;

/// One rule of the effective policy, as this screen draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The rule id.
    pub rule: String,
    /// The severity that applies after refinement, which is what the run used.
    pub severity: Severity,
    /// How the rule is evaluated. A property of the rule, read from the
    /// registry, so it cannot change with what a run happened to observe.
    pub evaluation: &'static str,
    /// The section the registry gives the rule.
    pub section: String,
    /// The run's own record of where the rule came from.
    pub provenance: String,
}

/// One place rules or policy material came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// What it is.
    pub name: String,
    /// What it was resolved from.
    pub reference: String,
    /// What identifies the bytes, or the statement that there are none to
    /// identify because the material is policy-sourced.
    pub blob: String,
}

/// The whole screen's read model, built once from one run.
///
/// The second of the interface's two sanitizing boundaries, and it holds to the
/// same rule as the first: a [`Report`] carries strings a server supplied, and
/// nothing built here does. No `Report` is retained anywhere the renderer can
/// reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspector {
    /// Every rule the run asked about, in rule-id order.
    pub rules: Vec<Rule>,
    /// How many distinct sections those rules fall into.
    pub sections: usize,
    /// Where the rules and the policy material came from.
    pub sources: Vec<Source>,
    /// What produced the reading, and what it was of.
    pub provenance: Provenance,
}

impl Inspector {
    /// Build the screen's read model from one run.
    #[must_use]
    pub fn of(report: &Report) -> Self {
        let mut rules: Vec<Rule> = report
            .effective_policy
            .iter()
            .map(|entry| {
                let definition = registry::find(&entry.rule);
                Rule {
                    rule: sanitize(&entry.rule, VALUE_LIMIT),
                    severity: Severity::parse(&entry.severity).unwrap_or(Severity::Observation),
                    evaluation: definition
                        .map_or("not registered", |check| check.evaluation.code()),
                    section: definition.map_or_else(
                        || "not registered".to_owned(),
                        |check| check.section.code().to_owned(),
                    ),
                    provenance: sanitize(&entry.provenance, VALUE_LIMIT),
                }
            })
            .collect();
        rules.sort_by(|left, right| left.rule.cmp(&right.rule));
        let mut sections: Vec<&str> = rules.iter().map(|rule| rule.section.as_str()).collect();
        sections.sort_unstable();
        sections.dedup();
        Self {
            sections: sections.len(),
            sources: sources(report, &rules),
            provenance: Provenance::of(report),
            rules,
        }
    }

    /// The digest as the status line quotes it.
    #[must_use]
    pub fn abbreviated_digest(&self) -> String {
        let digest = &self.provenance.registry_digest;
        let (algorithm, value) = digest.split_once(':').unwrap_or(("", digest.as_str()));
        if value.chars().count() <= DIGEST_PREFIX {
            return digest.clone();
        }
        let head: String = value.chars().take(DIGEST_PREFIX).collect();
        if algorithm.is_empty() {
            format!("{head}\u{2026}")
        } else {
            format!("{algorithm}:{head}\u{2026}")
        }
    }
}

/// Where the rules came from: the policy, its references, and the material the
/// policy supplied rather than the registry.
///
/// Policy-sourced material is marked as such rather than being listed beside a
/// blob identity it does not have. A suppression has no bytes in the registry
/// to point at, and printing a digest next to one would say it did.
fn sources(report: &Report, rules: &[Rule]) -> Vec<Source> {
    let mut sources = vec![Source {
        name: sanitize(&report.policy.name, VALUE_LIMIT),
        reference: reference(&report.policy.source, report.policy.commit.as_deref()),
        blob: sanitize(&report.policy.bundle_digest, VALUE_LIMIT),
    }];
    for source in &report.policy.sources {
        sources.push(Source {
            name: sanitize(&source.name, VALUE_LIMIT),
            reference: reference(&source.source, source.commit.as_deref()),
            // The blob identity is server-supplied like every other string
            // here, and a digest is a plausible place to hide an escape
            // sequence precisely because a reader skims it. Length is not the
            // only thing wrong with an unexamined value.
            blob: sanitize(
                source.blob_sha.as_deref().unwrap_or(&source.content_digest),
                VALUE_LIMIT,
            ),
        });
    }
    // Suppressions the policy authorized. Gathered by what authorized them,
    // because the authorization is the source and one clause commonly covers
    // more than one rule.
    let mut authorizations: Vec<(String, usize)> = Vec::new();
    for finding in &report.findings {
        let Some(suppression) = finding.suppression.as_ref() else {
            continue;
        };
        if suppression.source != SuppressionSource::Policy {
            continue;
        }
        let authorized_by = sanitize(&suppression.authorized_by, VALUE_LIMIT);
        match authorizations
            .iter_mut()
            .find(|(named, _)| *named == authorized_by)
        {
            Some((_, count)) => *count += 1,
            None => authorizations.push((authorized_by, 1)),
        }
    }
    for (authorized_by, count) in authorizations {
        sources.push(Source {
            name: "suppressions".to_owned(),
            reference: format!("{authorized_by} \u{b7} {count} rule(s)"),
            blob: "\u{2014} policy-sourced, not registry".to_owned(),
        });
    }
    // Rules the registry enables only under a declared repository state. They
    // are in the effective policy and they are not unconditional, and a reader
    // who cannot tell the two apart cannot tell why a rule was asked about.
    let mut conditions: Vec<(Applicability, usize)> = Vec::new();
    for rule in rules {
        let applicability = registry::find(&rule.rule).map_or(
            Applicability::Always,
            registry::CheckDefinition::applicability,
        );
        if applicability == Applicability::Always {
            continue;
        }
        match conditions
            .iter_mut()
            .find(|(declared, _)| *declared == applicability)
        {
            Some((_, count)) => *count += 1,
            None => conditions.push((applicability, 1)),
        }
    }
    for (applicability, count) in conditions {
        sources.push(Source {
            name: "conditional".to_owned(),
            reference: format!("{count} rule(s) enabled by {}", applicability.code()),
            blob: "\u{2014} registry-declared applicability".to_owned(),
        });
    }
    sources
}

/// A source and, where it was pinned to one, the commit it was pinned to.
fn reference(source: &str, commit: Option<&str>) -> String {
    match commit {
        Some(commit) => sanitize(&format!("{source} @ {commit}"), VALUE_LIMIT),
        None => sanitize(source, VALUE_LIMIT),
    }
}

/// The whole screen, windowed to the rows it has.
#[must_use]
pub fn body(
    styles: Styles,
    width: u16,
    height: u16,
    inspector: &Inspector,
    state: &Scroll,
) -> Vec<Line<'static>> {
    let width = width as usize;
    state.window(regions(styles, width, inspector), height as usize, styles)
}

/// Every region, in order.
fn regions(styles: Styles, width: usize, inspector: &Inspector) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("EFFECTIVE POLICY", styles.bold(Role::Accent)),
            Span::raw("  "),
            Span::styled(
                format!(
                    "{} rules \u{b7} {} sections",
                    inspector.rules.len(),
                    inspector.sections
                ),
                styles.of(Role::Dim),
            ),
        ]),
        Line::default(),
    ];
    lines.extend(digest_region(styles, width, inspector));
    lines.push(Line::default());
    lines.extend(sources_region(styles, width, inspector));
    lines.push(Line::default());
    lines.extend(inspector.provenance.lines(styles, width, LABEL_WIDTH));
    lines.push(Line::default());
    lines.extend(table(styles, width, inspector));
    lines
}

/// The digest, and what it proves.
fn digest_region(styles: Styles, width: usize, inspector: &Inspector) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "REGISTRY DIGEST")];
    // In full. An abbreviated digest cannot be compared against another run's,
    // and comparing them is the only thing a digest is for.
    lines.extend(value(
        styles,
        width,
        "digest",
        &inspector.provenance.registry_digest,
    ));
    lines.extend(value(
        styles,
        width,
        "computed over",
        "every rule the compiled registry declares: its id, its statement, its \
         default severity, its section, and its evaluation mode.",
    ));
    lines.extend(value(
        styles,
        width,
        "means",
        "two runs quoting the same digest asked the same questions.",
    ));
    lines.extend(value(
        styles,
        width,
        "excludes",
        "remediation classification. Two binaries that agree on the digest agree \
         on what every rule means, and may still differ on how they would close a \
         gap.",
    ));
    lines
}

/// Where the rules came from.
fn sources_region(styles: Styles, width: usize, inspector: &Inspector) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "SOURCES")];
    if inspector.sources.is_empty() {
        lines.extend(empty(
            styles,
            width,
            "each policy source with its reference and its blob identity, and the \
             material the policy supplied rather than the registry.",
            "the run recorded no policy identity at all, which happens when a report \
             is read from a document that predates the field.",
        ));
        return lines;
    }
    for source in &inspector.sources {
        lines.extend(value(
            styles,
            width,
            &source.name,
            &format!("{} \u{b7} {}", source.reference, source.blob),
        ));
    }
    lines
}

/// Every rule the run asked about.
fn table(styles: Styles, width: usize, inspector: &Inspector) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "RULES")];
    if inspector.rules.is_empty() {
        lines.extend(empty(
            styles,
            width,
            "every rule the run asked about, with its severity, its evaluation mode, \
             and where it came from.",
            "the run recorded no effective policy. Either no capability selected any \
             rule, or the report was read from a document that carries no \
             effective_policy.",
        ));
        return lines;
    }
    lines.push(Line::from(Span::styled(
        format!(
            "{INDENT}{:<RULE_WIDTH$}{:<SEVERITY_WIDTH$}{:<EVALUATION_WIDTH$}{}",
            "rule", "severity", "evaluation", "provenance"
        ),
        styles.of(Role::Faint),
    )));
    let room = width.saturating_sub(SPENT).max(1);
    for rule in &inspector.rules {
        let mut spans = vec![
            Span::raw(INDENT),
            Span::styled(
                format!("{:<RULE_WIDTH$}", fit(&rule.rule, RULE_WIDTH)),
                styles.of(Role::Text),
            ),
        ];
        spans.extend(lane::severity_spans(rule.severity, styles));
        spans.push(Span::raw(" ".repeat(
            SEVERITY_WIDTH.saturating_sub(4 + rule.severity.code().chars().count()),
        )));
        spans.push(Span::styled(
            format!(
                "{:<EVALUATION_WIDTH$}",
                fit(rule.evaluation, EVALUATION_WIDTH)
            ),
            styles.of(Role::Dim),
        ));
        spans.push(Span::styled(
            fit(&rule.provenance, room),
            styles.of(Role::Faint),
        ));
        lines.push(Line::from(spans));
    }
    lines
}

/// The status line: the registry version, the abbreviated digest, the rule
/// count, and the section count.
#[must_use]
pub fn status(inspector: &Inspector) -> String {
    format!(
        "registry {} \u{b7} {} \u{b7} {} rules \u{b7} {} sections",
        inspector.provenance.registry_version,
        inspector.abbreviated_digest(),
        inspector.rules.len(),
        inspector.sections
    )
}

/// What the status line says after `y`.
#[must_use]
pub fn copied() -> String {
    "the registry digest was offered to the terminal's clipboard \u{b7} a terminal \
     that does not take it ignores it, and the digest is above in full"
        .to_owned()
}

/// What the status line says when `y` was pressed and there is no digest.
#[must_use]
pub fn nothing_to_copy() -> String {
    "no policy is on screen \u{b7} the effective policy is a property of a run, and \
     nothing has been observed yet"
        .to_owned()
}

/// The screen before a run has been observed.
#[must_use]
pub fn nothing_observed(styles: Styles, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![heading(styles, "NO POLICY OBSERVED")];
    lines.extend(empty(
        styles,
        width,
        "every rule the run asked about, the registry digest and what it proves, \
         where the rules came from, and the run's provenance.",
        "the effective policy is a property of a run, and no repository has been \
         observed in this session.",
    ));
    lines.extend(panel::field(
        styles,
        "next",
        "press esc to return to the queue, and observe a repository.",
        width,
    ));
    lines
}

/// An empty region, in the terms the emptiness rule requires.
fn empty(styles: Styles, width: usize, would_show: &str, because: &str) -> Vec<Line<'static>> {
    let mut lines = panel::field(styles, "would show", would_show, width);
    lines.extend(panel::field(styles, "empty because", because, width));
    lines
}

fn value(styles: Styles, width: usize, label: &str, text: &str) -> Vec<Line<'static>> {
    field_at(styles, label, text, width, LABEL_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::chrome::{FLOOR_WIDTH, REFERENCE_WIDTH};
    use crate::tui::findings::fixture;
    use crate::tui::theme::{ColorMode, Theme};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn drawn(report: &Report, width: u16) -> String {
        text(&regions(styles(), width as usize, &Inspector::of(report)))
    }

    #[test]
    fn every_rule_the_run_asked_about_is_listed_with_its_severity_and_evaluation() {
        let report = fixture::mixed();
        let inspector = Inspector::of(&report);
        assert!(!inspector.rules.is_empty());
        let rendered = drawn(&report, REFERENCE_WIDTH);
        for rule in &inspector.rules {
            assert!(rendered.contains(&rule.rule), "{}: {rendered}", rule.rule);
            assert!(rendered.contains(rule.evaluation), "{}", rule.rule);
        }
        assert!(rendered.contains("provenance"), "{rendered}");
    }

    #[test]
    fn evaluation_is_a_property_of_the_rule_and_never_of_the_run() {
        // The same rule, observed twice with different statuses. What the run
        // concluded does not touch how the rule is evaluated.
        let manual = fixture::report(
            airlock_core::findings::Gate::Required,
            vec![fixture::finding(
                "REPO-DOCS-05",
                Severity::Required,
                airlock_core::findings::Status::Manual,
            )],
        );
        let failed = fixture::report(
            airlock_core::findings::Gate::Required,
            vec![fixture::finding(
                "REPO-DOCS-05",
                Severity::Required,
                airlock_core::findings::Status::Fail,
            )],
        );
        assert_eq!(
            Inspector::of(&manual).rules[0].evaluation,
            Inspector::of(&failed).rules[0].evaluation
        );
        assert_eq!(Inspector::of(&failed).rules[0].evaluation, "manual");
    }

    #[test]
    fn the_digest_is_printed_in_full_with_what_it_proves() {
        let report = fixture::mixed();
        let rendered = drawn(&report, REFERENCE_WIDTH);
        let digest = Inspector::of(&report).provenance.registry_digest;
        // Compared without the spaces the wrapping put in: the digest is one
        // token, and a width that broke it did not shorten it.
        assert!(
            rendered.replace(' ', "").contains(&digest.replace(' ', "")),
            "{rendered}"
        );
        assert!(rendered.contains("same questions"), "{rendered}");
        assert!(
            rendered.contains("remediation classification"),
            "the digest says what it does not cover: {rendered}"
        );
    }

    #[test]
    fn the_abbreviated_digest_is_marked_and_keeps_its_algorithm() {
        let mut report = fixture::mixed();
        report.airlock.registry_digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            Inspector::of(&report).abbreviated_digest(),
            "sha256:aaaaaaaa\u{2026}"
        );
        report.airlock.registry_digest = "sha256:abcd".to_owned();
        assert_eq!(Inspector::of(&report).abbreviated_digest(), "sha256:abcd");
    }

    /// A string carrying everything a terminal reads as an instruction.
    fn hostile() -> String {
        "\u{1b}[2Jwiped\u{202e}reversed\u{200b}hidden".to_owned()
    }

    #[test]
    fn every_server_supplied_string_is_examined_before_it_reaches_a_cell() {
        // A policy identity is as server-supplied as a finding is: it is read
        // from a document a repository controls, and the sources block draws
        // every field of it.
        let mut report = fixture::mixed();
        report.policy.name = hostile();
        report.policy.source = hostile();
        report.policy.bundle_digest = hostile();
        report.policy.sources[0].name = hostile();
        report.policy.sources[0].source = hostile();
        report.policy.sources[0].blob_sha = Some(hostile());
        report.policy.sources[0].commit = Some(hostile());
        let mut second = report.policy.sources[0].clone();
        // The other arm of the identity: no blob sha, so the content digest is
        // what is drawn, and it is examined on that path too.
        second.blob_sha = None;
        second.content_digest = hostile();
        report.policy.sources.push(second);

        let rendered = drawn(&report, REFERENCE_WIDTH);
        for refused in ['\u{1b}', '\u{202e}', '\u{200b}'] {
            assert!(
                !rendered.contains(refused),
                "{refused:?} reached a cell: {rendered:?}"
            );
        }
        // Refused rather than dropped: a character that vanished silently would
        // leave the operator no sign that anything was removed.
        assert!(rendered.contains('\u{fffd}'), "{rendered:?}");
    }

    #[test]
    fn the_shared_provenance_block_carries_its_facts_whole_and_safe() {
        // The block is shared with the finding detail, which promises to carry
        // what it shows whole. A bound applied where it is built would break
        // that promise for both screens at once, so it is asserted from both.
        let report = fixture::hostile();
        let inspector = Inspector::of(&report);
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            let block = text(
                &inspector
                    .provenance
                    .lines(styles(), width as usize, LABEL_WIDTH),
            );
            let stripped = block.replace(' ', "");
            for (label, value) in inspector.provenance.fields() {
                assert!(
                    stripped.contains(&crate::admin::text::drawable(&value).replace(' ', "")),
                    "{label} was shortened at {width}"
                );
            }
            assert!(!block.contains('\u{2026}'), "at {width}: {block}");
            for refused in ['\u{1b}', '\u{202e}', '\u{200b}'] {
                assert!(!block.contains(refused), "{refused:?} at {width}");
            }
            assert!(block.contains('\u{fffd}'), "at {width}");
        }
    }

    #[test]
    fn the_abbreviated_digest_is_the_one_place_the_screen_shortens_on_purpose() {
        // The status line has one row and abbreviates the digest to fit it. It
        // is not the defect the block avoids: it is marked as an abbreviation,
        // and the whole digest is above it on the screen.
        let report = fixture::hostile();
        let inspector = Inspector::of(&report);
        assert!(status(&inspector).contains('\u{2026}'));
        assert!(inspector.abbreviated_digest().ends_with('\u{2026}'));
        assert!(
            text(&regions(styles(), REFERENCE_WIDTH as usize, &inspector))
                .replace(' ', "")
                .contains(&inspector.provenance.registry_digest.replace(' ', "")),
            "the whole digest is on the screen the abbreviation summarises"
        );
    }

    #[test]
    fn policy_sourced_material_is_marked_as_such_rather_than_given_a_blob() {
        let report = fixture::mixed();
        let inspector = Inspector::of(&report);
        let suppression = inspector
            .sources
            .iter()
            .find(|source| source.name == "suppressions")
            .expect("the run carries a policy-authorized suppression");
        assert!(
            suppression.blob.contains("policy-sourced, not registry"),
            "{}",
            suppression.blob
        );
        assert!(suppression.reference.contains("policy"));
    }

    #[test]
    fn a_conditionally_enabled_rule_is_named_as_conditional() {
        let report = fixture::report(
            airlock_core::findings::Gate::Required,
            vec![fixture::finding(
                "REPO-GIT-09",
                Severity::Required,
                airlock_core::findings::Status::Pass,
            )],
        );
        let inspector = Inspector::of(&report);
        let conditional = inspector
            .sources
            .iter()
            .find(|source| source.name == "conditional")
            .expect("REPO-GIT-09 is enabled only where release units are declared");
        assert!(
            conditional.reference.contains("release-units-declared"),
            "{}",
            conditional.reference
        );
    }

    #[test]
    fn the_run_provenance_is_on_the_screen() {
        let report = fixture::mixed();
        let rendered = drawn(&report, REFERENCE_WIDTH);
        assert!(rendered.contains("RUN PROVENANCE"), "{rendered}");
        for (_, expected) in Provenance::of(&report).fields() {
            assert!(
                rendered
                    .replace(' ', "")
                    .contains(&expected.replace(' ', "")),
                "{expected} is missing: {rendered}"
            );
        }
    }

    #[test]
    fn the_status_line_carries_the_four_facts_the_specification_names() {
        let report = fixture::mixed();
        let inspector = Inspector::of(&report);
        let line = status(&inspector);
        assert!(
            line.contains(&inspector.provenance.registry_version),
            "{line}"
        );
        assert!(line.contains(&inspector.abbreviated_digest()), "{line}");
        assert!(
            line.contains(&format!("{} rules", inspector.rules.len())),
            "{line}"
        );
        assert!(
            line.contains(&format!("{} sections", inspector.sections)),
            "{line}"
        );
    }

    #[test]
    fn no_line_overflows_at_either_size() {
        let report = fixture::mixed();
        let inspector = Inspector::of(&report);
        for width in [REFERENCE_WIDTH, FLOOR_WIDTH] {
            for line in regions(styles(), width as usize, &inspector) {
                let rendered: String = line
                    .spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect();
                assert!(
                    rendered.chars().count() <= width as usize,
                    "at {width}: {rendered:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_table_states_what_would_have_populated_it() {
        let mut report = fixture::mixed();
        report.effective_policy.clear();
        let rendered = drawn(&report, REFERENCE_WIDTH);
        assert!(rendered.contains("would show"), "{rendered}");
        assert!(rendered.contains("empty because"), "{rendered}");
    }

    #[test]
    fn an_unobserved_screen_states_what_would_have_populated_it() {
        let rendered = text(&nothing_observed(styles(), 120));
        assert!(rendered.contains("would show"), "{rendered}");
        assert!(rendered.contains("empty because"), "{rendered}");
        assert!(rendered.contains("next"), "{rendered}");
    }

    #[test]
    fn a_copy_reports_the_asking_and_says_the_digest_is_on_screen_anyway() {
        let note = copied();
        assert!(note.contains("clipboard"), "{note}");
        assert!(note.contains("ignores it"), "{note}");
        assert!(note.contains("in full"), "{note}");
    }
}
