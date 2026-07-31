//! The findings screen: the whole standard as a work queue.
//!
//! Every rule the policy enables produces exactly one finding, and every
//! finding is either aligned or it is not. Nothing is triaged away as
//! unimportant, because an unimportant rule would not be in the policy. What
//! differs between findings is how much reading each one needs before it can be
//! closed, and who can close it — so the queue is ordered by the work, in eight
//! groups, and only the last of them is done.
//!
//! Grouping layers on top of the three-lane status model and does not replace
//! it. Every row still shows its status glyph in its lane, its severity bar, and
//! a solid left rail when it actually gates, so nothing standing in the
//! undecided lane can be read as a pass and no group heading decides what a row
//! does to the run.
//!
//! The screen is read-only. Settings-level actions are offered on group one and
//! carried out elsewhere; file-level gaps are displayed and nothing here offers
//! to act on them, because the interface writes no file.

use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use airlock_core::findings::{Finding, Gate, Outcome, Report, Status, Summary};
use airlock_core::registry::{self, Severity};

use crate::admin::sign_in::Density;
use crate::admin::text::{drawable, sanitize};

use super::chrome::fit;
use super::detail::Detail;
use super::lane::{self, Lane, GATING_RAIL, LANES_WIDTH};
use super::panel::{self, Provenance};
use super::theme::{Role, Styles};

/// The most a rule id may be on a line the queue writes for itself.
///
/// The registry's longest is fourteen characters. It bounds the queue's own
/// prose about a rule — a blocker banner, a repository name — and never the
/// rule id a row draws, which is bounded by the column it draws it in.
const RULE_LIMIT: usize = 24;

/// The most a reported reason may be.
const REASON_LIMIT: usize = 200;

/// The mark on the focused entry.
const FOCUSED: &str = "\u{25b8} ";

/// The mark on every other entry.
const UNFOCUSED: &str = "  ";

/// The rail beside a group the operator must close personally.
///
/// A glyph in a column of its own, so the four groups that need a person are
/// told from the four that do not by position as well as by hue.
const ATTENTION_RAIL: &str = "\u{2503}";

/// The width the rule-id column is printed in.
const RULE_WIDTH: usize = 15;

/// The width the status name is printed in. `unimplemented` is the longest.
const STATUS_WIDTH: usize = 14;

/// The width the section is printed in. `classification` is the longest.
const SECTION_WIDTH: usize = 15;

/// The fewest columns worth giving a section before it gives way entirely.
const SECTION_STUB: usize = 4;

/// The blockers named in the banner before the rest are withheld with a count.
///
/// The narrower reading names fewer, because at the floor the banner is
/// competing with the queue for rows. Withheld with a count, never dropped.
const BLOCKERS_SHOWN: usize = 4;

/// The blockers named at the floor.
const BLOCKERS_SHOWN_TIGHT: usize = 2;

/// The fewest rows the queue is ever given, whatever the head costs.
const QUEUE_FLOOR: usize = 3;

/// Where the lane strip ends and the rule id begins.
///
/// The two-line reading's second line starts here, so the section and the row's
/// own fact sit under the rule they are about rather than under the statement.
const MARKS: usize = UNFOCUSED.len() + 2 + 4 + LANES_WIDTH + 1;

/// Everything a row spends before its section, on the line the statement is on.
const SPENT: usize = MARKS + RULE_WIDTH + STATUS_WIDTH;

/// One of the eight groups the queue is ordered into.
///
/// The order is the work: what airlock closes, what an agent closes, what only
/// a person can close, what nothing can close yet, and what is already done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Settings-level changes applied directly from the interface.
    Settings,
    /// File-level gaps, delivered as a pull request by an agent. Display only.
    AgentWork,
    /// The repository has not declared what it is.
    Decision,
    /// Rules a person must attest to.
    Judgment,
    /// The undecided lane.
    Unanswered,
    /// Facts the registry declares behind a disclosure gate.
    AdminOnly,
    /// Suppressed failures: standing debt.
    Authorized,
    /// Passing rules, and rules a capability condition did not apply to.
    Aligned,
}

impl Group {
    /// Every group, in queue order.
    pub const ALL: [Group; 8] = [
        Group::Settings,
        Group::AgentWork,
        Group::Decision,
        Group::Judgment,
        Group::Unanswered,
        Group::AdminOnly,
        Group::Authorized,
        Group::Aligned,
    ];

    /// The group's position in the queue, counting from one.
    #[must_use]
    pub const fn number(self) -> usize {
        match self {
            Self::Settings => 1,
            Self::AgentWork => 2,
            Self::Decision => 3,
            Self::Judgment => 4,
            Self::Unanswered => 5,
            Self::AdminOnly => 6,
            Self::Authorized => 7,
            Self::Aligned => 8,
        }
    }

    /// The heading, as the specification names it.
    #[must_use]
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Settings => "AIRLOCK CLOSES THIS",
            Self::AgentWork => "CLOSES BY PULL REQUEST \u{2014} AGENT WORK",
            Self::Decision => "NEEDS A DECISION",
            Self::Judgment => "NEEDS A JUDGMENT",
            Self::Unanswered => "AIRLOCK COULD NOT ANSWER",
            Self::AdminOnly => "ADMIN-ONLY",
            Self::Authorized => "AUTHORIZED BUT NOT ALIGNED",
            Self::Aligned => "ALIGNED",
        }
    }

    /// The one-line gloss of what closing this group takes.
    #[must_use]
    pub const fn gloss(self) -> &'static str {
        match self {
            Self::Settings => "settings-level changes applied from here; confirm rather than study",
            Self::AgentWork => {
                "file-level gaps an agent closes and a pull request delivers; shown only"
            }
            Self::Decision => {
                "the repository has not declared what it is, so airlock cannot know \
                 what to apply"
            }
            Self::Judgment => "rules a person must attest to",
            Self::Unanswered => "the undecided lane; the remedy often sits outside the repository",
            Self::AdminOnly => {
                "facts that require admin access to verify, answered on the surface \
                 the gate names"
            }
            Self::Authorized => {
                "the policy permitted the failure; it did not close the gap, and the \
                 remediation is still on offer"
            }
            Self::Aligned => {
                "passing rules, and rules skipped because a capability condition does \
                 not apply"
            }
        }
    }

    /// The short name the standing tally prints, so every count stays in view.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::AgentWork => "agent",
            Self::Decision => "decision",
            Self::Judgment => "judgment",
            Self::Unanswered => "unanswered",
            Self::AdminOnly => "admin-only",
            Self::Authorized => "authorized",
            Self::Aligned => "aligned",
        }
    }

    /// Whether this group is one the operator must close personally.
    ///
    /// The four that need a person, or that nothing on this surface can answer,
    /// are marked in a column of their own so they never fold into the groups
    /// that close without them.
    #[must_use]
    pub const fn needs_the_operator(self) -> bool {
        matches!(
            self,
            Self::Decision | Self::Judgment | Self::Unanswered | Self::AdminOnly
        )
    }

    /// Whether the group opens collapsed.
    ///
    /// Collapsing is screen space and never a judgment. Only the aligned group
    /// starts collapsed, because it is the one group that needs no action.
    #[must_use]
    pub const fn starts_collapsed(self) -> bool {
        matches!(self, Self::Aligned)
    }

    /// What an empty group states, which is never "nothing here" by itself.
    #[must_use]
    pub const fn emptiness(self) -> &'static str {
        match self {
            Self::Settings => "no failing rule closes by a setting",
            Self::AgentWork => "no failing rule closes by a file change",
            Self::Decision => "the repository declared everything airlock asked",
            Self::Judgment => "no rule is waiting on a person's attestation",
            Self::Unanswered => "every rule this run asked was answered",
            Self::AdminOnly => {
                "no rule was withheld by a disclosure gate; this session's \
                 credential is write-capable, so gated facts resolve under it"
            }
            Self::Authorized => "the policy authorized no failure",
            Self::Aligned => "no rule passed and none was skipped",
        }
    }
}

/// Whether a pull request is open against a file-level gap.
///
/// Three values rather than a boolean, because the observation may not have
/// established it and an unestablished fact is not the absence of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum Delivery {
    /// A pull request is open against this gap.
    Open,
    /// No pull request is open against this gap.
    None,
    /// The observation did not establish it.
    #[default]
    Unknown,
}

impl Delivery {
    /// What the row prints. `unknown` never renders as `none`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "pull request open",
            Self::None => "no pull request open",
            Self::Unknown => "pull request state not established",
        }
    }
}

/// What the observation established about pull requests open against gaps.
///
/// A side table rather than a field on the finding: the delivery state is a
/// fact about work in flight, not about the rule, and the headless audit
/// document does not carry it. A rule the table does not name is
/// [`Delivery::Unknown`], which is what not having asked looks like.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deliveries(Vec<(String, Delivery)>);

impl Deliveries {
    /// Build the table from what an observation established.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn of(entries: Vec<(String, Delivery)>) -> Self {
        Self(entries)
    }

    /// What is known about one rule, which may be nothing.
    #[must_use]
    pub fn get(&self, rule: &str) -> Delivery {
        self.0
            .iter()
            .find(|(named, _)| named == rule)
            .map_or(Delivery::Unknown, |(_, delivery)| *delivery)
    }
}

/// The five named sets the filter selects between.
///
/// A choice among named sets rather than a text entry: nothing here types, so
/// no key is captured and both chrome surfaces keep offering everything they
/// offer. The whole working set is the default, because a default that narrowed
/// what the operator saw first would hide part of the standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterSet {
    /// Every finding, which is what the screen opens on.
    #[default]
    Everything,
    /// Failures at a severity the effective gate enforces.
    GatingFailures,
    /// Everything in the undecided lane.
    Undecided,
    /// Every failure, whatever its severity.
    AllFailures,
    /// Everything in the inert lane.
    Inert,
}

impl FilterSet {
    /// Every set, in the order `f` moves through them.
    pub const ALL: [FilterSet; 5] = [
        FilterSet::Everything,
        FilterSet::GatingFailures,
        FilterSet::Undecided,
        FilterSet::AllFailures,
        FilterSet::Inert,
    ];

    /// The name the screen prints for the set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Everything => "the whole working set",
            Self::GatingFailures => "gating failures",
            Self::Undecided => "undecided",
            Self::AllFailures => "all failures",
            Self::Inert => "inert",
        }
    }

    /// The next set `f` selects.
    #[must_use]
    pub fn next(self) -> Self {
        let index = Self::ALL
            .iter()
            .position(|set| *set == self)
            .unwrap_or_default();
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    /// Whether a row is in this set.
    #[must_use]
    pub fn holds(self, row: &Row) -> bool {
        match self {
            Self::Everything => true,
            Self::GatingFailures => row.status == Status::Fail && row.gate.enforces(row.severity),
            Self::Undecided => row.status.undecided().is_some(),
            Self::AllFailures => row.status == Status::Fail,
            Self::Inert => lane::lane_of(row.status) == Lane::Inert,
        }
    }
}

/// One finding, as this screen draws it.
///
/// Everything here was taken from the run at the one boundary that builds a
/// [`Queue`], and every string the run did not write itself was sanitized
/// there. A row is a value the renderer can draw without asking anything else a
/// question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The rule id.
    pub rule: String,
    /// The rule statement, verbatim.
    pub statement: String,
    /// The severity the effective policy gave the rule.
    pub severity: Severity,
    /// What the audit concluded.
    pub status: Status,
    /// The section the registry gives the rule.
    pub section: String,
    /// The gate in force, carried so a row can say what it does to the run.
    pub gate: Gate,
    /// The group this row takes.
    pub group: Group,
    /// Whether a pull request is open against this gap, for a file-level gap.
    pub delivery: Delivery,
    /// What this row says beyond its statement, where the group requires it.
    pub note: Option<String>,
    /// Everything else airlock knows about the finding, for the screen that
    /// reads one rule in full.
    ///
    /// Carried on the row rather than looked up again, so a row and its detail
    /// are one value built at one boundary: they sanitize together, they sort
    /// together, and no second path exists by which a server-supplied string
    /// could reach a cell.
    pub detail: Detail,
    /// The compiled remediation code, when one is declared.
    pub remediation: Option<String>,
    /// What the compiled remediation would change.
    pub change: Option<String>,
    /// Whether a later operation can reverse it.
    pub reversible: Option<bool>,
    /// The custom-property declaration offered by a decision row.
    pub capability: Option<(String, String)>,
}

impl Row {
    /// Whether this row actually gates the run.
    ///
    /// Severity times status, never status alone: a failure at a severity the
    /// gate does not enforce stops nothing, and neither does an undecided
    /// result there. Only rows that gate carry the solid left rail.
    #[must_use]
    pub fn gates(&self) -> bool {
        if !self.gate.enforces(self.severity) {
            return false;
        }
        self.status == Status::Fail
            || self.status.undecided() == Some(airlock_core::findings::Undecided::Circumstantial)
    }
}

/// One rule the run fell short of evaluating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    /// The rule id.
    pub rule: String,
    /// The undecided status it ended in.
    pub status: Status,
    /// What stopped it.
    pub why: String,
}

/// The verdict, and the facts it is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The overall conclusion.
    pub outcome: Outcome,
    /// Whether every rule at a gating severity was decided.
    pub complete: bool,
    /// Whether the gate is satisfied.
    pub conformant: bool,
}

/// The whole screen's read model, built once from one run.
///
/// This is the sanitizing boundary. A [`Report`] is what an observation
/// produces and carries strings a server supplied; a `Queue` carries only
/// strings that have been made safe to draw, so there is no second path by
/// which server text could reach a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queue {
    /// The repository the run is about.
    pub repository: String,
    /// The verdict and its two facts.
    pub verdict: Verdict,
    /// Counts per status.
    pub summary: Summary,
    /// The rules this run fell short of evaluating.
    pub blockers: Vec<Blocker>,
    /// Every finding, ordered by group and then by rule id.
    pub rows: Vec<Row>,
    /// The gate the effective policy declared.
    pub gate: Gate,
    /// The registry version the run attests to.
    pub registry_version: String,
    /// What produced the reading, and what it was of.
    pub provenance: Provenance,
}

impl Queue {
    /// Build the screen's read model from one run.
    #[must_use]
    pub fn of(report: &Report, deliveries: &Deliveries) -> Self {
        let gate = report.policy.gate;
        let mut rows: Vec<Row> = report
            .findings
            .iter()
            .map(|finding| row(finding, gate, deliveries, &report.effective_policy))
            .collect();
        // Grouped by the work, and by rule id inside each group: the audit's
        // own order is what makes a rule findable, and the group is what makes
        // the queue a queue.
        rows.sort_by(|left, right| {
            left.group
                .number()
                .cmp(&right.group.number())
                .then_with(|| left.rule.cmp(&right.rule))
        });
        let blockers = report
            .findings
            .iter()
            .filter(|finding| finding.blocks_completeness(gate))
            .map(|finding| Blocker {
                rule: sanitize(&finding.rule, RULE_LIMIT),
                status: finding.status,
                why: why(finding),
            })
            .collect();
        Self {
            repository: drawable(&report.repository.full_name),
            verdict: Verdict {
                outcome: report.outcome,
                complete: report.complete,
                conformant: report.conformant,
            },
            summary: report.summary.clone(),
            blockers,
            rows,
            gate,
            registry_version: sanitize(&report.airlock.registry_version, RULE_LIMIT),
            provenance: Provenance::of(report),
        }
    }

    /// How many rows a group holds, whatever the filter is.
    ///
    /// A group heading states the group, not the view: the filter changes what
    /// is shown and never a count in a heading.
    #[must_use]
    pub fn count(&self, group: Group) -> usize {
        self.rows.iter().filter(|row| row.group == group).count()
    }

    /// The indices of the rows a filter shows, in queue order.
    #[must_use]
    pub fn shown(&self, filter: FilterSet) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| filter.holds(row))
            .map(|(index, _)| index)
            .collect()
    }

    /// The rows in rule-id order, which is the lookup view.
    #[must_use]
    pub fn by_rule_id(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.rows.len()).collect();
        order.sort_by(|left, right| self.rows[*left].rule.cmp(&self.rows[*right].rule));
        order
    }
}

/// Which group a finding takes, tested in the specification's order.
///
/// First match wins, and the tests are ordered so that a finding can never be
/// read as more settled than it is: suppressed before anything that could make
/// it look inert, admin-only before the rest of the undecided lane, and the
/// undecided lane before every decided status.
#[must_use]
fn group_of(finding: &Finding) -> Group {
    let evidence = finding
        .evidence
        .as_ref()
        .map(|evidence| evidence.code.as_str());
    match finding.status {
        Status::Suppressed => Group::Authorized,
        Status::AdminOnly => Group::AdminOnly,
        Status::Inconclusive if evidence == Some("capability_undeclared") => Group::Decision,
        Status::Unimplemented | Status::Inconclusive | Status::Error => Group::Unanswered,
        Status::Manual => Group::Judgment,
        Status::Pass | Status::Skipped => Group::Aligned,
        // A failure is grouped by what closing its gap takes, which is the
        // rule's declared remediation lane. A failure airlock declares no
        // remediation for — and one whose rule the registry does not classify
        // at all — has a person as its only remaining move, so it stands with
        // the judgments and the row says which of the two it is.
        Status::Fail => match finding.remediation_class.lane.as_deref() {
            Some("operator-setting") => Group::Settings,
            Some("deterministic-file" | "judgment-file") => Group::AgentWork,
            _ => Group::Judgment,
        },
    }
}

/// What the row says beyond its statement, where its group requires something.
fn note_of(finding: &Finding, group: Group, gate: Gate, severity: Severity) -> Option<String> {
    match group {
        // The grant the fact requires and the surface the gate names, both read
        // from the registry declaration rather than composed here.
        Group::AdminOnly => registry::find(&finding.rule)
            .and_then(registry::CheckDefinition::disclosure_gate)
            .map(|declared| {
                format!(
                    "grant {} \u{b7} verified by {}",
                    declared.requires.code(),
                    declared.verified_by.code()
                )
            }),
        // A row in this group that does not block says so on the row: it is
        // still an unanswered question, and it is not a pass.
        Group::Unanswered if !gate.enforces(severity) => Some(format!(
            "does not block: the {} gate does not enforce {}",
            gate.code(),
            severity.code()
        )),
        // The only remaining move is a person's, so the declared reason is what
        // says why airlock is not the one making it.
        Group::Judgment if finding.status == Status::Fail => {
            Some(finding.remediation_class.none_reason.as_ref().map_or_else(
                || "airlock declares no remediation classification for this rule".to_owned(),
                |reason| format!("no remediation: {}", sanitize(reason, REASON_LIMIT)),
            ))
        }
        // Standing debt keeps its remediation: authorizing a failure does not
        // delete the fix for it.
        Group::Authorized => finding
            .remediation_class
            .change
            .as_ref()
            .map(|change| format!("still on offer: {}", sanitize(change, REASON_LIMIT))),
        _ => None,
    }
}

fn row(
    finding: &Finding,
    gate: Gate,
    deliveries: &Deliveries,
    effective_policy: &[airlock_core::findings::EffectiveRule],
) -> Row {
    let severity = Severity::parse(&finding.severity).unwrap_or(Severity::Observation);
    let group = group_of(finding);
    let declaration = finding
        .evidence
        .as_ref()
        .and_then(|evidence| evidence.capability.as_ref());
    Row {
        // Whole in the model and shortened only where a column requires it.
        // The row has one line and bounds these at the moment it draws them;
        // the finding detail has the whole screen and carries them whole, and
        // it reads them from here.
        rule: drawable(&finding.rule),
        statement: drawable(&finding.statement),
        severity,
        status: finding.status,
        section: registry::find(&finding.rule).map_or_else(
            || "not registered".to_owned(),
            |check| check.section.code().to_owned(),
        ),
        gate,
        group,
        delivery: deliveries.get(&finding.rule),
        note: note_of(finding, group, gate, severity),
        detail: Detail::of(finding, effective_policy),
        remediation: declaration.map_or_else(
            || {
                finding
                    .remediation_class
                    .code
                    .as_ref()
                    .map(|value| drawable(value))
            },
            |_| Some("declare-capability-property".to_owned()),
        ),
        change: declaration.map_or_else(
            || {
                finding
                    .remediation_class
                    .change
                    .as_ref()
                    .map(|value| sanitize(value, REASON_LIMIT))
            },
            |declaration| {
                Some(format!(
                    "set organization custom property `{}` to `{}` for this repository",
                    drawable(&declaration.property),
                    drawable(&declaration.value)
                ))
            },
        ),
        reversible: declaration.map_or(finding.remediation_class.reversible, |_| Some(false)),
        capability: declaration.map(|value| (drawable(&value.property), drawable(&value.value))),
    }
}

/// What stopped a rule the run fell short of evaluating.
fn why(finding: &Finding) -> String {
    if let Some(error) = &finding.error {
        return sanitize(
            &format!("{} on {}", error.cause, error.endpoint),
            REASON_LIMIT,
        );
    }
    finding.evidence.as_ref().map_or_else(
        || lane::gloss_of(finding.status).to_owned(),
        |evidence| {
            sanitize(
                &format!("{}: {}", evidence.code, evidence.detail),
                REASON_LIMIT,
            )
        },
    )
}

/// Where the operator is in the queue, and what the queue is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// Which entry is focused.
    selected: usize,
    /// Which groups are collapsed, indexed by [`Group::number`] minus one.
    collapsed: [bool; 8],
    /// The set the filter has selected.
    filter: FilterSet,
    /// Whether the flat lookup view is open.
    flat: bool,
}

impl Default for State {
    fn default() -> Self {
        let mut collapsed = [false; 8];
        for group in Group::ALL {
            collapsed[group.number() - 1] = group.starts_collapsed();
        }
        Self {
            selected: 0,
            collapsed,
            filter: FilterSet::default(),
            flat: false,
        }
    }
}

impl State {
    /// Which entry is focused.
    #[must_use]
    pub const fn selected(&self) -> usize {
        self.selected
    }

    /// Whether a group is collapsed.
    #[must_use]
    pub const fn is_collapsed(&self, group: Group) -> bool {
        self.collapsed[group.number() - 1]
    }

    /// The set the filter has selected.
    #[must_use]
    pub const fn filter(&self) -> FilterSet {
        self.filter
    }

    /// Whether the flat lookup view is open.
    #[must_use]
    pub const fn flat(&self) -> bool {
        self.flat
    }

    /// Select the next of the five named sets.
    ///
    /// The selection moves back to the top, because the set under the old
    /// position is not the set under the new one.
    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
    }

    /// Open or close the flat lookup view.
    pub fn toggle_flat(&mut self) {
        self.flat = !self.flat;
        self.selected = 0;
    }

    /// Collapse or expand a group, and keep the focus somewhere it exists.
    ///
    /// Collapsing a group the focus was inside puts the focus on its heading,
    /// because that is where the group now is.
    pub fn toggle(&mut self, group: Group, heading: usize) {
        let slot = group.number() - 1;
        self.collapsed[slot] = !self.collapsed[slot];
        if self.collapsed[slot] {
            self.selected = heading;
        }
    }

    /// Move the focus, stopping at both ends.
    pub fn move_selection(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.selected = 0;
            return;
        }
        let last = len - 1;
        self.selected = if delta < 0 {
            self.selected.saturating_sub(1)
        } else {
            (self.selected + 1).min(last)
        }
        .min(last);
    }

    /// Keep the focus inside a queue that has changed shape under it.
    pub fn clamp(&mut self, len: usize) {
        self.selected = self.selected.min(len.saturating_sub(1));
    }
}

/// One line of the queue: a group heading, or a row inside a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// A group heading, always drawn whether or not the group holds anything.
    Heading(Group),
    /// A row, by its index into [`Queue::rows`].
    Row(usize),
}

/// The entries the queue draws, in order.
///
/// Every group heading is present whatever the filter and whatever is
/// collapsed, so the whole standard is always addressable and every count is
/// always in view.
#[must_use]
pub fn entries(queue: &Queue, state: &State) -> Vec<Entry> {
    if state.flat() {
        // The lookup view is every finding, ordered by rule id, and it is not
        // narrowed: a predictable address for every rule is only predictable if
        // every rule has one.
        return queue.by_rule_id().into_iter().map(Entry::Row).collect();
    }
    let shown = queue.shown(state.filter());
    let mut out = Vec::with_capacity(shown.len() + Group::ALL.len());
    for group in Group::ALL {
        out.push(Entry::Heading(group));
        if state.is_collapsed(group) {
            continue;
        }
        out.extend(
            shown
                .iter()
                .filter(|index| queue.rows[**index].group == group)
                .map(|index| Entry::Row(*index)),
        );
    }
    out
}

/// The group the focused entry belongs to.
#[must_use]
pub fn focused_group(queue: &Queue, entries: &[Entry], selected: usize) -> Option<Group> {
    match entries.get(selected)? {
        Entry::Heading(group) => Some(*group),
        Entry::Row(index) => queue.rows.get(*index).map(|row| row.group),
    }
}

/// The index of a group's heading among the entries.
#[must_use]
pub fn heading_index(entries: &[Entry], group: Group) -> usize {
    entries
        .iter()
        .position(|entry| *entry == Entry::Heading(group))
        .unwrap_or_default()
}

/// The row the focus is on, when it is on one.
#[must_use]
pub fn focused_row<'a>(queue: &'a Queue, entries: &[Entry], selected: usize) -> Option<&'a Row> {
    match entries.get(selected)? {
        Entry::Heading(_) => None,
        Entry::Row(index) => queue.rows.get(*index),
    }
}

/// The status line: the verdict, `complete` as its own boolean, the rule count,
/// the registry version, and the gate in force.
#[must_use]
pub fn status(queue: &Queue) -> String {
    format!(
        "{} \u{b7} complete {} \u{b7} {} rules \u{b7} registry {} \u{b7} gate {}",
        queue.verdict.outcome.code(),
        queue.verdict.complete,
        queue.rows.len(),
        queue.registry_version,
        queue.gate.code()
    )
}

/// What the status line says when `a` was pressed somewhere it does nothing.
///
/// Said rather than silently ignored: a key that is listed and does nothing is
/// a key the operator will press again.
#[must_use]
pub fn inert_apply() -> String {
    format!(
        "a applies a setting, and only on a row in group {} \u{b7} airlock closes this. \
         File-level gaps close by pull request and are shown here only; nothing on this \
         screen writes a file.",
        Group::Settings.number()
    )
}

/// The whole screen.
#[must_use]
pub fn body(
    styles: Styles,
    width: u16,
    height: u16,
    queue: &Queue,
    state: &State,
) -> Vec<Line<'static>> {
    let width = width as usize;
    let density = panel::density(width);
    let mut head = head(styles, width, queue, state, density);
    let entries = entries(queue, state);
    let heights: Vec<usize> = entries
        .iter()
        .map(|entry| entry_height(queue, entry, width, density))
        .collect();
    let room = (height as usize)
        .saturating_sub(head.len() + 1)
        .max(QUEUE_FLOOR);
    let (start, end) = window(&heights, state.selected(), room);
    for (index, entry) in entries.iter().enumerate().take(end).skip(start) {
        head.extend(draw(
            styles,
            width,
            queue,
            state,
            *entry,
            index == state.selected(),
            density,
        ));
    }
    head.push(scroll(styles, width, &entries, start, end, queue, state));
    head
}

/// How many lines an entry costs.
///
/// A heading is one line at both widths. A row is one line where the width
/// carries the whole reading, and two where it does not: the section and the
/// row's note are load-bearing, and eliding a statement to nothing to keep them
/// on one line would leave a row that says what kind of rule it is without
/// saying what the rule is.
fn entry_height(queue: &Queue, entry: &Entry, width: usize, density: Density) -> usize {
    match entry {
        Entry::Heading(_) => 1,
        Entry::Row(index) => queue
            .rows
            .get(*index)
            .map_or(1, |row| usize::from(!one_line(row, width, density)) + 1),
    }
}

/// Whether the row's whole reading fits on one line.
///
/// One line where the width carries everything, two where it does not — and
/// what decides that is the row's own fact, because the fact is the one field
/// that is never shortened. A row whose fact will not fit beside the statement
/// takes the second line rather than withholding a fact the same terminal could
/// have shown, which is what keeps a wider screen from ever showing less of a
/// fact than a narrower one across the change of reading.
fn one_line(row: &Row, width: usize, density: Density) -> bool {
    density == Density::Full && tail_of(row).chars().count() <= width.saturating_sub(SPENT)
}

/// The slice of the queue that fits, with the focused entry always inside it.
fn window(heights: &[usize], selected: usize, room: usize) -> (usize, usize) {
    if heights.is_empty() || room == 0 {
        return (0, 0);
    }
    let selected = selected.min(heights.len() - 1);
    let mut start = selected;
    let mut end = selected + 1;
    let mut used = heights[selected];
    // Grown outward from the focused entry rather than sliced from a computed
    // offset, so an entry that costs two lines cannot push the focus out of the
    // window it is the centre of.
    loop {
        let before = end < heights.len() && used + heights[end] <= room;
        if before {
            used += heights[end];
            end += 1;
        }
        let after = start > 0 && used + heights[start - 1] <= room;
        if after {
            used += heights[start - 1];
            start -= 1;
        }
        if !before && !after {
            break;
        }
    }
    (start, end)
}

/// Everything above the queue, which nothing below it changes.
fn head(
    styles: Styles,
    width: usize,
    queue: &Queue,
    state: &State,
    density: Density,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.extend(blockers(styles, width, queue, density));
    lines.extend(verdict(styles, width, queue));
    lines.extend(summary(styles, width, queue, density));
    // The lookup view has no groups in it, so it carries its own label where
    // the queue carries the standing tally. Neither view is ever unlabelled.
    if state.flat() {
        lines.push(Line::from(vec![
            Span::styled("LOOKUP  ", styles.bold(Role::Text)),
            Span::styled(
                fit(
                    "every finding, ordered by rule id \u{2014} the predictable \
                     address for every rule",
                    width.saturating_sub(8),
                ),
                styles.of(Role::Faint),
            ),
        ]));
    } else {
        lines.extend(tally(styles, width, queue, density));
    }
    lines.extend(filter_line(styles, width, queue, state, density));
    lines
}

/// The banner an incomplete run opens with.
///
/// Above the verdict, because it is what says the verdict cannot be certified.
/// A rule its declared disclosure gate withholds is never named here: that run
/// is complete, and the admin-only group is where it is accounted for.
fn blockers(styles: Styles, width: usize, queue: &Queue, density: Density) -> Vec<Line<'static>> {
    if queue.blockers.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![Line::from(vec![
        Span::styled("RUN INCOMPLETE  ", styles.bold(Role::Status(Status::Error))),
        Span::styled(
            fit(
                "complete is false, and no verdict below it can be certified",
                width.saturating_sub(16),
            ),
            styles.of(Role::Text),
        ),
    ])];
    let most = match density {
        Density::Full => BLOCKERS_SHOWN,
        Density::Tight => BLOCKERS_SHOWN_TIGHT,
    };
    let shown = most.min(queue.blockers.len());
    for blocker in queue.blockers.iter().take(shown) {
        let prefix = format!(
            "  {} {:<RULE_WIDTH$}{:<STATUS_WIDTH$}",
            lane::glyph_of(blocker.status),
            blocker.rule,
            blocker.status.code()
        );
        let room = width.saturating_sub(prefix.chars().count());
        lines.push(Line::from(vec![
            Span::styled(prefix, styles.of(Role::Status(blocker.status))),
            Span::styled(fit(&blocker.why, room), styles.of(Role::Dim)),
        ]));
    }
    let withheld = queue.blockers.len() - shown;
    if withheld > 0 {
        lines.push(Line::from(Span::styled(
            format!("  {withheld} more blockers withheld for room"),
            styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
    }
    if density == Density::Full {
        lines.push(Line::default());
    }
    lines
}

/// The verdict, its two facts stated separately, and the score.
fn verdict(styles: Styles, width: usize, queue: &Queue) -> Vec<Line<'static>> {
    let outcome = queue.verdict.outcome;
    let glyph = match outcome {
        Outcome::Conformant => Status::Pass,
        Outcome::Nonconformant => Status::Fail,
        Outcome::Incomplete => Status::Inconclusive,
    };
    let aligned = queue.count(Group::Aligned);
    let total = queue.rows.len();
    let mut lines = vec![Line::from(vec![
        Span::styled("VERDICT  ", styles.bold(Role::Text)),
        Span::styled(
            format!("{} {}", lane::glyph_of(glyph), outcome.code()),
            styles.bold(Role::Status(glyph)),
        ),
        Span::styled("   ", styles.of(Role::Faint)),
        Span::styled(
            format!("ALIGNED {aligned} of {total}"),
            styles.bold(Role::Status(Status::Pass)),
        ),
        Span::styled(
            if aligned == total && total > 0 {
                "  the repository is aligned".to_owned()
            } else {
                String::new()
            },
            styles.of(Role::Status(Status::Pass)),
        ),
    ])];
    for (label, value, reason) in [
        (
            "complete",
            queue.verdict.complete,
            if queue.verdict.complete {
                "every rule at a gating severity was decided".to_owned()
            } else {
                format!(
                    "{} rules at a gating severity ended undecided because this run \
                     fell short",
                    queue.blockers.len()
                )
            },
        ),
        (
            "conformant",
            queue.verdict.conformant,
            if queue.verdict.conformant {
                "no rule at a gating severity ended in fail".to_owned()
            } else {
                format!(
                    "{} rules at a gating severity ended in fail",
                    queue
                        .rows
                        .iter()
                        .filter(|row| row.status == Status::Fail && row.gate.enforces(row.severity))
                        .count()
                )
            },
        ),
    ] {
        let prefix = format!("  {label:<12}{value:<7}");
        let room = width.saturating_sub(prefix.chars().count());
        lines.push(Line::from(vec![
            Span::styled(prefix, styles.of(Role::Text)),
            Span::styled(fit(&reason, room), styles.of(Role::Dim)),
        ]));
    }
    // A conformant verdict is never read as every rule having been decided.
    let unanswered = queue.summary.count(Status::AdminOnly);
    if unanswered > 0 {
        let prefix = format!("  {:<12}{unanswered:<7}", "unanswered");
        let room = width.saturating_sub(prefix.chars().count());
        lines.push(Line::from(vec![
            Span::styled(prefix, styles.of(Role::Status(Status::AdminOnly))),
            Span::styled(
                fit(
                    "ended admin-only and are still undecided, so this verdict is not \
                     every rule having been decided",
                    room,
                ),
                styles.of(Role::Dim),
            ),
        ]));
    }
    lines
}

/// The status summary: every one of the nine statuses, under its lane.
fn summary(styles: Styles, width: usize, queue: &Queue, density: Density) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for lane in Lane::ALL {
        let counts: Vec<String> = Status::ALL
            .iter()
            .filter(|status| lane::lane_of(**status) == lane)
            .map(|status| {
                format!(
                    "{} {} {}",
                    lane::glyph_of(*status),
                    status.code(),
                    queue.summary.count(*status)
                )
            })
            .collect();
        let heading = format!("{:<20}", lane.heading());
        let counts = counts.join(" \u{b7} ");
        // The counts are never elided: a status whose count was cut is a status
        // the summary did not report. Where the width cannot carry the heading
        // and the counts on one line, the counts take the next one.
        if heading.chars().count() + counts.chars().count() <= width {
            lines.push(Line::from(vec![
                Span::styled(heading, styles.bold(Role::Dim)),
                Span::styled(counts, styles.of(Role::Text)),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                lane.heading(),
                styles.bold(Role::Dim),
            )));
            lines.push(Line::from(Span::styled(
                format!("  {}", fit(&counts, width.saturating_sub(2))),
                styles.of(Role::Text),
            )));
        }
        // The undecided qualifier is printed at every width, because an
        // undecided result at a severity the gate does not enforce leaves the
        // run complete and the heading alone does not say so.
        if density == Density::Full || lane == Lane::Undecided {
            lines.push(Line::from(Span::styled(
                format!("  {}", fit(lane.qualifier(), width.saturating_sub(2))),
                styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
            )));
        }
    }
    lines
}

/// The standing tally: every group's count, whatever is collapsed or filtered.
///
/// The narrower reading keys the counts by group number alone. Nothing is
/// dropped — every group is still counted — and the number is the address every
/// heading below already carries, so the line stays readable against the queue
/// rather than costing it a second row.
fn tally(styles: Styles, width: usize, queue: &Queue, density: Density) -> Vec<Line<'static>> {
    let counts: Vec<String> = Group::ALL
        .iter()
        .map(|group| match density {
            Density::Full => format!("{} {} {}", group.number(), group.tag(), queue.count(*group)),
            Density::Tight => format!("{}:{}", group.number(), queue.count(*group)),
        })
        .collect();
    panel::field(styles, "groups", &counts.join(" \u{b7} "), width)
}

/// The filter, what it is showing, and the gate that decides what gates.
fn filter_line(
    styles: Styles,
    width: usize,
    queue: &Queue,
    state: &State,
    density: Density,
) -> Vec<Line<'static>> {
    let total = queue.rows.len();
    let gate = queue.gate.code();
    let value = match (state.flat(), density) {
        (true, Density::Full) => format!(
            "lookup \u{b7} every finding ordered by rule id \u{b7} all {total} shown, \
             never narrowed \u{b7} gate {gate} \u{b7} l returns to the queue"
        ),
        (true, Density::Tight) => {
            format!("all {total} shown, never narrowed \u{b7} gate {gate} \u{b7} l returns")
        }
        (false, Density::Full) => format!(
            "{} \u{b7} {} of {total} shown \u{b7} gate {gate} \u{b7} f selects one of five sets",
            state.filter().label(),
            queue.shown(state.filter()).len()
        ),
        (false, Density::Tight) => format!(
            "{} \u{b7} {} of {total} \u{b7} gate {gate} \u{b7} f",
            state.filter().label(),
            queue.shown(state.filter()).len()
        ),
    };
    panel::field(styles, "showing", &value, width)
}

/// One entry of the queue.
fn draw(
    styles: Styles,
    width: usize,
    queue: &Queue,
    state: &State,
    entry: Entry,
    focused: bool,
    density: Density,
) -> Vec<Line<'static>> {
    match entry {
        Entry::Heading(group) => vec![heading(styles, width, queue, state, group, focused)],
        Entry::Row(index) => queue.rows.get(index).map_or_else(Vec::new, |row| {
            row_lines(styles, width, row, focused, density)
        }),
    }
}

/// A group heading: its number, its name, its count, and its gloss.
fn heading(
    styles: Styles,
    width: usize,
    queue: &Queue,
    state: &State,
    group: Group,
    focused: bool,
) -> Line<'static> {
    let count = queue.count(group);
    let fold = if state.is_collapsed(group) { "+" } else { "-" };
    let rail = if group.needs_the_operator() {
        ATTENTION_RAIL
    } else {
        " "
    };
    let prefix = format!(
        "{}{rail}{fold} {} {}",
        if focused { FOCUSED } else { UNFOCUSED },
        group.number(),
        group.heading()
    );
    let counted = format!("  {count}  ");
    let room = width.saturating_sub(prefix.chars().count() + counted.chars().count());
    let tail = if count == 0 {
        group.emptiness()
    } else {
        group.gloss()
    };
    let name = if group.needs_the_operator() {
        styles.bold(Role::Accent)
    } else {
        styles.bold(Role::Text)
    };
    Line::from(vec![
        Span::styled(prefix, name),
        Span::styled(counted, styles.bold(Role::Dim)),
        Span::styled(fit(tail, room), styles.of(Role::Faint)),
    ])
}

/// One row, at whichever of the two readings the width carries.
fn row_lines(
    styles: Styles,
    width: usize,
    row: &Row,
    focused: bool,
    density: Density,
) -> Vec<Line<'static>> {
    let mut spans = vec![
        Span::styled(
            if focused { FOCUSED } else { UNFOCUSED },
            styles.bold(Role::Accent),
        ),
        // The rail is the one mark that says this row gates the run, and it is
        // drawn from severity times status rather than from the group.
        Span::styled(
            if row.gates() { GATING_RAIL } else { " " },
            styles.of(Role::Status(Status::Fail)),
        ),
        Span::raw(" "),
        Span::styled(lane::severity_bar(row.severity), styles.of(Role::Text)),
        Span::raw(" "),
    ];
    spans.extend(lane::lanes_spans(Some(row.status), styles));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format!("{:<RULE_WIDTH$}", fit(&row.rule, RULE_WIDTH - 1)),
        if focused {
            styles.bold(Role::Text)
        } else {
            styles.of(Role::Text)
        },
    ));
    spans.push(Span::styled(
        format!("{:<STATUS_WIDTH$}", row.status.code()),
        styles.of(Role::Status(row.status)),
    ));
    let room = width.saturating_sub(SPENT);
    if one_line(row, width, density) {
        // The fact is allocated out of everything the row has left, before the
        // section takes its column: the section is bounded registry vocabulary
        // and elides the way every bounded field here does, and the fact is
        // what the group exists to carry.
        let fact = fact(row, room);
        let taken = fact.as_ref().map_or(0, |fact| fact.chars().count());
        let section = SECTION_WIDTH.min(room.saturating_sub(taken));
        spans.push(Span::styled(
            format!(
                "{:<section$}",
                fit(&row.section, section.saturating_sub(1)),
                section = section
            ),
            styles.of(Role::Faint),
        ));
        spans.push(Span::styled(
            detail(fact, &row.statement, room - section),
            styles.of(Role::Dim),
        ));
        return vec![Line::from(spans)];
    }
    spans.push(Span::styled(
        fit(&row.statement, room),
        styles.of(Role::Dim),
    ));
    // The second line, where the fact has the whole width less the marks. It is
    // allocated first and the section takes what is left. Neither is
    // half-printed: the fact is whole or it is the notice that it was withheld.
    let room = width.saturating_sub(MARKS);
    let tail = match fact(row, room) {
        None => fit(&row.section, room),
        Some(fact) => {
            let left = room.saturating_sub(fact.chars().count() + 3);
            // A section cut to a character and an ellipsis tells a reader
            // nothing and reads as a fault, so below that it gives way
            // altogether. It is bounded registry vocabulary and the finding
            // detail carries it; the fact is what the row cannot lose.
            if left < SECTION_STUB {
                fact
            } else {
                format!("{} \u{b7} {fact}", fit(&row.section, left))
            }
        }
    };
    vec![
        Line::from(spans),
        Line::from(Span::styled(
            format!("{:<MARKS$}{tail}", ""),
            styles.of(Role::Faint),
        )),
    ]
}

/// What a row says after its section: its own fact, then its statement.
///
/// The fact arrives already allocated, because which of the two is allocated
/// first is the whole question: the fact is what the group exists to carry —
/// the delivery state of a file-level gap, the grant an admin-only fact
/// requires, or why airlock declares no remediation. A statement the width
/// cannot hold is shortened; a fact is never shortened to make room for one.
fn detail(fact: Option<String>, statement: &str, room: usize) -> String {
    let Some(fact) = fact else {
        return fit(statement, room);
    };
    let left = room.saturating_sub(fact.chars().count());
    if left <= 4 {
        return fact;
    }
    format!("{fact} \u{b7} {}", fit(statement, left - 3))
}

/// What the row prints where its own fact will not fit at all.
///
/// Short by construction, so the notice fits wherever the fact did not. It
/// names the key that opens the finding detail, which is where the fact is
/// carried whole.
const FACT_WITHHELD: &str = "fact withheld for width \u{b7} \u{21b5} shows it whole";

/// The row's own fact, whole or withheld — never part of one.
///
/// A fact the width cannot carry is not shortened into the row. Half a reason,
/// half a grant, or half a delivery state reads as the whole of it, and a
/// reader has no way to tell which they are looking at; a stated absence is
/// something they can act on. The notice itself is elided rather than dropped
/// if even it does not fit, which is safe for the one reason the fact is not:
/// a shortened notice cannot be mistaken for a fact.
fn fact(row: &Row, room: usize) -> Option<String> {
    let fact = tail_of(row);
    if fact.is_empty() {
        return None;
    }
    if fact.chars().count() <= room {
        return Some(fact);
    }
    Some(fit(FACT_WITHHELD, room))
}

/// The row's own fact, when its group gives it one.
fn tail_of(row: &Row) -> String {
    if row.group == Group::AgentWork {
        return row.delivery.label().to_owned();
    }
    row.note.clone().unwrap_or_default()
}

/// What lies above and below, and the size of the working set.
fn scroll(
    styles: Styles,
    width: usize,
    entries: &[Entry],
    start: usize,
    end: usize,
    queue: &Queue,
    state: &State,
) -> Line<'static> {
    let working = if state.flat() {
        queue.rows.len()
    } else {
        queue.shown(state.filter()).len()
    };
    let text = format!(
        "{} above \u{b7} {} below \u{b7} working set {working} of {} \u{b7} \
         \u{2191}\u{2193} moves through the rest",
        start,
        entries.len().saturating_sub(end),
        queue.rows.len()
    );
    Line::from(Span::styled(
        fit(&text, width),
        styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
    ))
}

/// The runs the suites draw.
///
/// Fixtures, and the specification says as much: illustrative values are
/// shapes. What every case asserts is that the screen prints what the run gave
/// it — there is no GitHub here to give it anything else.
#[cfg(test)]
pub mod fixture {
    use std::collections::BTreeMap;

    use super::{Deliveries, Delivery};
    use airlock_core::findings::{
        AirlockIdentity, AuditedRepository, EffectiveRule, Evidence, Finding, FindingError, Gate,
        ObservationRecord, PolicyIdentity, PolicySourceIdentity, Remediation, RemediationClass,
        Report, Status, Suppression, SuppressionSource,
    };
    use airlock_core::registry::{self, Severity};
    use airlock_core::remediation::ActionGroup;

    /// One finding, with the registry's own classification joined onto it.
    #[must_use]
    pub fn finding(rule: &str, severity: Severity, status: Status) -> Finding {
        Finding {
            rule: rule.to_owned(),
            statement: format!("the condition {rule} states"),
            severity: severity.code().to_owned(),
            status,
            evidence: None,
            remediation: None,
            remediation_class: RemediationClass::for_rule(rule),
            suppression: None,
            source: Some("api".to_owned()),
            error: None,
        }
    }

    /// A run over one repository, under one gate.
    ///
    /// The effective policy is derived from the findings rather than left
    /// empty, because a real run always carries one: a rule was asked about
    /// because a capability selected it, and a fixture without that record
    /// would make every screen that reads it look emptier than any run is.
    #[must_use]
    pub fn report(gate: Gate, findings: Vec<Finding>) -> Report {
        let mut effective_policy: Vec<EffectiveRule> = Vec::new();
        for finding in &findings {
            if effective_policy
                .iter()
                .any(|entry| entry.rule == finding.rule)
            {
                continue;
            }
            effective_policy.push(EffectiveRule {
                rule: finding.rule.clone(),
                severity: finding.severity.clone(),
                params: BTreeMap::new(),
                provenance: format!(
                    "capability:base/{}",
                    registry::find(&finding.rule)
                        .map_or("unregistered", |check| check.section.code())
                ),
            });
        }
        Report::assemble(
            AirlockIdentity::current("0.0.0"),
            AuditedRepository {
                full_name: "acme-industries/widget".to_owned(),
                id: Some(1),
                default_branch: "main".to_owned(),
                audited_commit: "a".repeat(40),
                settings_observed_at: Some("2026-01-02T03:04:05Z".to_owned()),
            },
            ObservationRecord::api(),
            PolicyIdentity {
                name: "policy".to_owned(),
                source: "./policy.yml".to_owned(),
                commit: None,
                sources: vec![PolicySourceIdentity {
                    name: "standards".to_owned(),
                    source: "acme-industries/.github:standards.yml".to_owned(),
                    commit: Some("b".repeat(40)),
                    blob_sha: Some("c".repeat(40)),
                    content_digest: "sha256:2".to_owned(),
                }],
                bundle_digest: "sha256:0".to_owned(),
                gate,
            },
            effective_policy,
            Vec::new(),
            findings,
        )
    }

    /// A failure whose declared lane is a setting: airlock closes it.
    ///
    /// It carries a contextual remediation as well as the rule's declared
    /// classification, because a real failing rule does: the classification
    /// says what the rule's gap always takes, and the remediation is what this
    /// run produced to carry out.
    #[must_use]
    pub fn settings_failure() -> Finding {
        let mut finding = finding("REPO-GIT-01", Severity::Blocking, Status::Fail);
        finding.evidence = Some(Evidence::new("branch_unprotected", "no ruleset applies"));
        finding.remediation = Some(Remediation::new(
            ActionGroup::TIGHTEN_RULESET,
            "Protect the default branch with a ruleset that requires a pull request.",
        ));
        finding
    }

    /// A settings-level failure this run produced no remedy for.
    ///
    /// The rule is classified `operator-setting` and the run offered nothing to
    /// carry out. The two facts live on different fields and a surface that
    /// reads only the classification cannot tell this apart from the case
    /// above — which is the whole reason it is a fixture.
    #[must_use]
    pub fn settings_failure_without_a_remedy() -> Finding {
        let mut finding = settings_failure();
        finding.remediation = None;
        finding
    }

    /// A failure whose declared lane is a file change: an agent closes it.
    #[must_use]
    pub fn file_failure() -> Finding {
        finding("REPO-LIC-01", Severity::Required, Status::Fail)
    }

    /// A rule the repository has not declared enough about to evaluate.
    #[must_use]
    pub fn capability_undeclared() -> Finding {
        let mut finding = finding("REPO-REL-04", Severity::Required, Status::Inconclusive);
        finding.evidence = Some(Evidence::new(
            "capability_undeclared",
            "the repository has not declared whether it publishes a package",
        ));
        finding
    }

    /// A failure the policy authorized, which is standing debt.
    #[must_use]
    pub fn suppressed() -> Finding {
        let mut finding = finding("REPO-CI-02", Severity::Blocking, Status::Suppressed);
        finding.suppression = Some(Suppression {
            source: SuppressionSource::Policy,
            requested_reason: None,
            policy_reason: Some("migration in flight".to_owned()),
            authorized_by: "policy".to_owned(),
        });
        finding
    }

    /// A rule an API failure stopped.
    #[must_use]
    pub fn errored() -> Finding {
        let mut finding = finding("REPO-GIT-09", Severity::Blocking, Status::Error);
        finding.error = Some(FindingError {
            cause: "permission".to_owned(),
            endpoint: "GET /repos/{owner}/{repo}/rulesets".to_owned(),
            status: Some(403),
            message: None,
            documentation_url: None,
            accepted_permissions: Some("administration:read".to_owned()),
            request_id: None,
            message_hints_version: 1,
        });
        finding
    }

    /// A run with every group populated.
    #[must_use]
    pub fn mixed() -> Report {
        report(
            Gate::Required,
            vec![
                settings_failure(),
                file_failure(),
                capability_undeclared(),
                finding("REPO-README-04", Severity::Required, Status::Manual),
                finding("REPO-CI-02", Severity::Blocking, Status::Unimplemented),
                finding("REPO-GIT-04", Severity::Required, Status::AdminOnly),
                suppressed(),
                finding("REPO-META-01", Severity::Blocking, Status::Pass),
                finding("REPO-META-02", Severity::Required, Status::Skipped),
            ],
        )
    }

    /// A run this session fell short of completing.
    #[must_use]
    pub fn incomplete() -> Report {
        report(
            Gate::Required,
            vec![
                errored(),
                finding("REPO-CI-02", Severity::Blocking, Status::Unimplemented),
                settings_failure(),
                finding("REPO-META-01", Severity::Blocking, Status::Pass),
            ],
        )
    }

    /// A failure whose declared reason is longer than the floor can carry.
    ///
    /// Contrived, and deliberately so: it is the length at which the two widths
    /// disagree. The floor has no reading of it to give and withholds it; the
    /// reference takes a second line and carries it whole. That is the
    /// monotonic rule in one run — widening a terminal adds the fact, and never
    /// takes one away.
    #[must_use]
    pub fn long_fact() -> Report {
        let mut unremediable = finding("REPO-DOCS-05", Severity::Required, Status::Fail);
        unremediable.remediation_class = RemediationClass {
            lane: None,
            code: None,
            change: None,
            reversible: None,
            none_reason: Some(
                "the choice of licence is the maintainer's, and airlock will not make \
                 it for them"
                    .to_owned(),
            ),
        };
        report(
            Gate::Required,
            vec![
                unremediable,
                finding("REPO-META-01", Severity::Blocking, Status::Pass),
            ],
        )
    }

    /// A run whose every server-supplied string is long and hostile.
    ///
    /// Long past any bound the queue imposes for its own layout, so a surface
    /// that promises to carry a fact whole is actually tested on one it could
    /// have shortened; and carrying the characters a terminal reads as
    /// instructions, so completeness and safety are proven on the same value
    /// rather than on two convenient ones.
    #[must_use]
    pub fn hostile() -> Report {
        // Long enough that no layout bound in the interface could have been
        // reached honestly, and seeded so no two values are prefixes of one
        // another: a test asserting a value survived would otherwise pass on a
        // different value that happened to contain it.
        let long = |seed: &str| format!("{seed}\u{1b}[2J\u{200b}\u{202e}{}", seed.repeat(120));
        let mut failed = finding("REPO-GIT-01", Severity::Blocking, Status::Fail);
        failed.statement = long("statement");
        failed.evidence = Some(Evidence::at(
            long("evidence-code"),
            long("evidence-path"),
            long("evidence-detail"),
        ));
        failed.remediation = Some(Remediation::new(
            ActionGroup::TIGHTEN_RULESET,
            long("remediation-detail"),
        ));
        failed.remediation_class = RemediationClass {
            lane: Some("operator-setting".to_owned()),
            code: Some(long("class-code")),
            change: Some(long("class-change")),
            reversible: Some(true),
            none_reason: None,
        };
        let mut errored = finding("REPO-GIT-09", Severity::Blocking, Status::Error);
        errored.statement = long("error-statement");
        errored.remediation_class = RemediationClass {
            lane: None,
            code: None,
            change: None,
            reversible: None,
            none_reason: Some(long("no-remediation-reason")),
        };
        errored.error = Some(FindingError {
            cause: long("cause"),
            endpoint: long("endpoint"),
            status: Some(403),
            message: Some(long("message")),
            documentation_url: Some(long("documentation")),
            accepted_permissions: Some(long("accepted")),
            request_id: Some(long("request")),
            message_hints_version: 1,
        });
        let mut suppressed = finding("REPO-CI-02", Severity::Blocking, Status::Suppressed);
        suppressed.statement = long("suppressed-statement");
        suppressed.remediation_class = RemediationClass {
            lane: Some("deterministic-file".to_owned()),
            code: Some(long("suppressed-class-code")),
            change: Some(long("suppressed-class-change")),
            reversible: Some(false),
            none_reason: None,
        };
        suppressed.suppression = Some(Suppression {
            source: SuppressionSource::RepositoryRequest,
            requested_reason: Some(long("requested")),
            policy_reason: Some(long("policy-reason")),
            authorized_by: long("authorized-by"),
        });
        let mut report = report(Gate::Required, vec![failed, errored, suppressed]);
        for entry in &mut report.effective_policy {
            entry.provenance = long("provenance");
        }
        // The run's own provenance is server-supplied too, and it is shared by
        // both screens that promise to carry what they show whole. It is seeded
        // here so a bound reintroduced anywhere on that path is caught by the
        // same fixture rather than by the next review.
        report.airlock.version = long("airlock-version");
        report.airlock.registry_version = long("registry-version");
        report.airlock.registry_digest = long("registry-digest");
        report.repository.audited_commit = long("audited-commit");
        report.repository.settings_observed_at = Some(long("settings-observed"));
        report.repository.full_name = long("repository-name");
        report
    }

    /// A repository with nothing left to close.
    #[must_use]
    pub fn aligned() -> Report {
        report(
            Gate::Required,
            vec![
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                finding("REPO-META-01", Severity::Required, Status::Pass),
                finding("REPO-REL-04", Severity::Required, Status::Skipped),
            ],
        )
    }

    /// What one observation established about work already in flight.
    #[must_use]
    pub fn deliveries() -> Deliveries {
        Deliveries::of(vec![("REPO-LIC-01".to_owned(), Delivery::Open)])
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{
        capability_undeclared, file_failure, finding, report, settings_failure, suppressed,
    };
    use super::*;
    use crate::tui::chrome::{FLOOR_HEIGHT, FLOOR_WIDTH, REFERENCE_HEIGHT, REFERENCE_WIDTH};
    use crate::tui::theme::{ColorMode, Theme};
    use airlock_core::findings::{Evidence, FindingError, RemediationClass};

    fn styles() -> Styles {
        Styles::new(Theme::Dark, ColorMode::Color)
    }

    fn queue(findings: Vec<Finding>) -> Queue {
        Queue::of(&report(Gate::Required, findings), &Deliveries::default())
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn rendered(queue: &Queue, state: &State, width: u16, height: u16) -> String {
        text(&body(styles(), width, height, queue, state))
    }

    // -----------------------------------------------------------------
    // Grouping
    // -----------------------------------------------------------------

    #[test]
    fn a_finding_takes_the_first_group_it_matches() {
        for (finding, expected) in [
            (suppressed(), Group::Authorized),
            (
                finding("REPO-GIT-04", Severity::Required, Status::AdminOnly),
                Group::AdminOnly,
            ),
            (capability_undeclared(), Group::Decision),
            (
                finding("REPO-CI-02", Severity::Blocking, Status::Unimplemented),
                Group::Unanswered,
            ),
            (
                finding("REPO-CI-02", Severity::Blocking, Status::Error),
                Group::Unanswered,
            ),
            (
                finding("REPO-README-04", Severity::Required, Status::Manual),
                Group::Judgment,
            ),
            (
                finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                Group::Aligned,
            ),
            (
                finding("REPO-REL-04", Severity::Blocking, Status::Skipped),
                Group::Aligned,
            ),
            (settings_failure(), Group::Settings),
            (file_failure(), Group::AgentWork),
        ] {
            assert_eq!(group_of(&finding), expected, "{}", finding.rule);
        }
    }

    #[test]
    fn an_inconclusive_finding_is_a_decision_only_when_the_evidence_says_so() {
        assert_eq!(group_of(&capability_undeclared()), Group::Decision);
        let mut other = capability_undeclared();
        other.evidence = Some(Evidence::new("tree_truncated", "the tree was truncated"));
        assert_eq!(group_of(&other), Group::Unanswered);
    }

    #[test]
    fn a_failure_with_no_declared_remediation_stands_with_the_judgments_and_says_why() {
        let mut finding = finding("REPO-XX-99", Severity::Blocking, Status::Fail);
        finding.remediation_class = RemediationClass {
            lane: None,
            code: None,
            change: None,
            reversible: None,
            none_reason: Some("the choice is the maintainer's".to_owned()),
        };
        assert_eq!(group_of(&finding), Group::Judgment);
        let queue = queue(vec![finding]);
        let note = queue.rows[0]
            .note
            .clone()
            .expect("the reason is on the row");
        assert!(note.contains("the choice is the maintainer's"), "{note}");
    }

    #[test]
    fn a_long_remediation_code_round_trips_through_the_queue_row() {
        let finding = finding("REPO-GIT-06", Severity::Blocking, Status::Fail);
        let expected = finding
            .remediation_class
            .code
            .clone()
            .expect("REPO-GIT-06 has a remediation code");

        let queue = queue(vec![finding]);

        assert_eq!(
            queue.rows[0].remediation.as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn a_long_repository_name_round_trips_through_the_queue() {
        let full_name = format!("{}/{}", "o".repeat(39), "r".repeat(100));
        let mut report = report(
            Gate::Required,
            vec![finding("REPO-GIT-04", Severity::Blocking, Status::Fail)],
        );
        report.repository.full_name.clone_from(&full_name);

        let queue = Queue::of(&report, &Deliveries::default());

        assert_eq!(queue.repository, full_name);
    }

    #[test]
    fn a_suppressed_failure_never_stands_with_the_passing_rules() {
        let queue = queue(vec![
            suppressed(),
            finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
        ]);
        let suppressed = queue
            .rows
            .iter()
            .find(|row| row.status == Status::Suppressed)
            .expect("the suppressed row");
        assert_eq!(suppressed.group, Group::Authorized);
        assert_ne!(suppressed.group, Group::Aligned);
        assert_eq!(queue.count(Group::Aligned), 1);
        assert_eq!(queue.count(Group::Authorized), 1);
    }

    #[test]
    fn every_status_lands_in_exactly_one_group_and_every_group_is_reachable() {
        let findings: Vec<Finding> = Status::ALL
            .iter()
            .enumerate()
            .map(|(index, status)| {
                finding(&format!("REPO-AA-{index:02}"), Severity::Blocking, *status)
            })
            .collect();
        let queue = queue(findings);
        assert_eq!(
            queue.rows.len(),
            Status::ALL.len(),
            "every enabled rule is accounted for"
        );
        let counted: usize = Group::ALL.iter().map(|group| queue.count(*group)).sum();
        assert_eq!(counted, queue.rows.len(), "no row is in two groups or none");
    }

    // -----------------------------------------------------------------
    // The gate
    // -----------------------------------------------------------------

    #[test]
    fn the_rail_is_severity_times_status_and_never_the_group() {
        let queue = Queue::of(
            &report(
                Gate::Blocking,
                vec![
                    finding("REPO-AA-01", Severity::Blocking, Status::Fail),
                    finding("REPO-AA-02", Severity::Observation, Status::Fail),
                    finding("REPO-AA-03", Severity::Blocking, Status::AdminOnly),
                    finding("REPO-AA-04", Severity::Blocking, Status::Inconclusive),
                    finding("REPO-AA-05", Severity::Blocking, Status::Suppressed),
                ],
            ),
            &Deliveries::default(),
        );
        let gates = |rule: &str| {
            queue
                .rows
                .iter()
                .find(|row| row.rule == rule)
                .expect("the row")
                .gates()
        };
        assert!(gates("REPO-AA-01"), "a blocking failure gates");
        assert!(!gates("REPO-AA-02"), "an observation failure stops nothing");
        assert!(
            !gates("REPO-AA-03"),
            "a fact requiring admin access to verify never gates"
        );
        assert!(gates("REPO-AA-04"), "a circumstantial gap gates");
        assert!(!gates("REPO-AA-05"), "the policy authorized this failure");
    }

    #[test]
    fn a_non_blocking_row_in_the_undecided_group_says_so_on_the_row() {
        let queue = Queue::of(
            &report(
                Gate::Blocking,
                vec![finding(
                    "REPO-AA-01",
                    Severity::Observation,
                    Status::Inconclusive,
                )],
            ),
            &Deliveries::default(),
        );
        let row = &queue.rows[0];
        assert_eq!(row.group, Group::Unanswered);
        assert!(!row.gates());
        let note = row.note.clone().expect("the row says it does not block");
        assert!(note.contains("does not block"), "{note}");
        assert!(note.contains("observation"), "{note}");
    }

    #[test]
    fn an_admin_only_row_states_the_grant_and_the_surface_the_registry_declares() {
        let queue = queue(vec![finding(
            "REPO-GIT-04",
            Severity::Required,
            Status::AdminOnly,
        )]);
        let note = queue.rows[0].note.clone().expect("the declaration");
        assert!(note.contains("contents:write"), "{note}");
        assert!(note.contains("interactive-session"), "{note}");
    }

    // -----------------------------------------------------------------
    // Delivery
    // -----------------------------------------------------------------

    #[test]
    fn an_unestablished_pull_request_state_is_never_drawn_as_none() {
        assert_ne!(Delivery::Unknown.label(), Delivery::None.label());
        assert!(!Delivery::Unknown.label().contains("no pull request"));
        let queue = Queue::of(
            &report(Gate::Required, vec![file_failure()]),
            &Deliveries::default(),
        );
        assert_eq!(queue.rows[0].delivery, Delivery::Unknown);
        let rendered = rendered(&queue, &State::default(), 120, 40);
        assert!(rendered.contains("not established"), "{rendered}");
        assert!(!rendered.contains("no pull request open"), "{rendered}");
    }

    #[test]
    fn a_file_gap_says_whether_a_pull_request_is_already_open() {
        for (delivery, expected) in [
            (Delivery::Open, "pull request open"),
            (Delivery::None, "no pull request open"),
        ] {
            let queue = Queue::of(
                &report(Gate::Required, vec![file_failure()]),
                &Deliveries::of(vec![("REPO-LIC-01".to_owned(), delivery)]),
            );
            let rendered = rendered(&queue, &State::default(), 120, 40);
            assert!(rendered.contains(expected), "{rendered}");
        }
    }

    #[test]
    fn no_row_in_the_agent_group_offers_an_action() {
        let queue = Queue::of(
            &report(Gate::Required, vec![file_failure()]),
            &Deliveries::default(),
        );
        let rendered = rendered(&queue, &State::default(), 120, 40);
        assert!(rendered.contains("shown only"), "{rendered}");
        assert!(!rendered.contains("a apply"), "{rendered}");
        assert!(inert_apply().contains("nothing on this screen writes a file"));
    }

    // -----------------------------------------------------------------
    // The screen
    // -----------------------------------------------------------------

    fn mixed() -> Queue {
        Queue::of(&super::fixture::mixed(), &super::fixture::deliveries())
    }

    #[test]
    fn every_group_heading_carries_its_count_and_its_gloss_at_both_sizes() {
        let queue = mixed();
        for (width, height) in [(120u16, 40u16), (80, 24)] {
            // Every heading is drawn, which means the window has to be walked.
            let mut seen = String::new();
            let mut state = State::default();
            for index in 0..entries(&queue, &state).len() {
                state.selected = index;
                seen.push(' ');
                seen.push_str(&rendered(&queue, &state, width, height));
            }
            for group in Group::ALL {
                assert!(seen.contains(group.heading()), "{group:?} at {width}");
            }
        }
    }

    #[test]
    fn the_counts_and_the_score_stay_in_view_whatever_is_collapsed() {
        let queue = mixed();
        let mut state = State::default();
        let expanded = rendered(&queue, &state, 120, 40);
        for group in Group::ALL {
            state.toggle(group, heading_index(&entries(&queue, &state), group));
        }
        let collapsed = rendered(&queue, &state, 120, 40);
        for reading in [&expanded, &collapsed] {
            for group in Group::ALL {
                assert!(
                    reading.contains(&format!(
                        "{} {} {}",
                        group.number(),
                        group.tag(),
                        queue.count(group)
                    )),
                    "{group:?} count is not in view: {reading}"
                );
            }
            assert!(reading.contains("ALIGNED 2 of 9"), "{reading}");
        }
    }

    #[test]
    fn only_the_aligned_group_opens_collapsed() {
        let state = State::default();
        for group in Group::ALL {
            assert_eq!(
                state.is_collapsed(group),
                group == Group::Aligned,
                "{group:?}"
            );
        }
    }

    #[test]
    fn collapsing_is_screen_space_and_the_count_does_not_move() {
        let queue = mixed();
        let mut state = State::default();
        let before = queue.count(Group::Settings);
        state.toggle(Group::Settings, 0);
        assert!(state.is_collapsed(Group::Settings));
        assert_eq!(queue.count(Group::Settings), before);
    }

    #[test]
    fn a_fully_aligned_repository_reads_as_finished_rather_than_as_an_empty_list() {
        let queue = Queue::of(
            &report(
                Gate::Required,
                vec![
                    finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                    finding("REPO-META-01", Severity::Required, Status::Pass),
                ],
            ),
            &Deliveries::default(),
        );
        let rendered = rendered(&queue, &State::default(), 120, 40);
        assert!(rendered.contains("ALIGNED 2 of 2"), "{rendered}");
        assert!(rendered.contains("the repository is aligned"), "{rendered}");
        assert!(rendered.contains("conformant"), "{rendered}");
        // Every empty group still states what would have populated it.
        assert!(rendered.contains(Group::Settings.emptiness()), "{rendered}");
    }

    #[test]
    fn an_incomplete_run_opens_with_its_blockers_above_the_verdict() {
        let mut blocked = finding("REPO-CI-02", Severity::Blocking, Status::Error);
        blocked.error = Some(FindingError {
            cause: "permission".to_owned(),
            endpoint: "GET /repos/{owner}/{repo}/rulesets".to_owned(),
            status: Some(403),
            message: None,
            documentation_url: None,
            accepted_permissions: Some("administration:read".to_owned()),
            request_id: None,
            message_hints_version: 1,
        });
        let queue = Queue::of(
            &report(
                Gate::Blocking,
                vec![
                    blocked,
                    finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                ],
            ),
            &Deliveries::default(),
        );
        let rendered = rendered(&queue, &State::default(), 120, 40);
        let banner = rendered.find("RUN INCOMPLETE").expect("the banner");
        let verdict = rendered.find("VERDICT").expect("the verdict");
        assert!(banner < verdict, "the banner opens the screen: {rendered}");
        assert!(rendered.contains("REPO-CI-02"), "{rendered}");
        assert!(rendered.contains("error"), "{rendered}");
        assert!(rendered.contains("permission"), "{rendered}");
        assert!(rendered.contains("incomplete"), "{rendered}");
    }

    #[test]
    fn a_fact_requiring_admin_access_is_never_a_blocker_and_is_still_counted() {
        let queue = Queue::of(
            &report(
                Gate::Required,
                vec![
                    finding("REPO-GIT-04", Severity::Required, Status::AdminOnly),
                    finding("REPO-LIC-01", Severity::Blocking, Status::Pass),
                ],
            ),
            &Deliveries::default(),
        );
        assert!(queue.blockers.is_empty(), "a gated fact is not a blocker");
        assert!(queue.verdict.complete);
        let rendered = rendered(&queue, &State::default(), 120, 40);
        assert!(!rendered.contains("RUN INCOMPLETE"), "{rendered}");
        assert!(rendered.contains("unanswered"), "{rendered}");
        assert!(rendered.contains("admin-only"), "{rendered}");
    }

    #[test]
    fn complete_and_conformant_are_printed_as_two_facts() {
        let queue = mixed();
        let rendered = rendered(&queue, &State::default(), 120, 40);
        assert!(rendered.contains("complete"), "{rendered}");
        assert!(rendered.contains("conformant"), "{rendered}");
        assert!(
            rendered.contains("every rule at a gating severity was decided")
                || rendered.contains("ended undecided"),
            "{rendered}"
        );
    }

    #[test]
    fn the_summary_prints_all_nine_statuses_under_their_lanes() {
        let queue = mixed();
        let rendered = rendered(&queue, &State::default(), 80, 24);
        for status in Status::ALL {
            assert!(rendered.contains(status.code()), "{status:?}: {rendered}");
        }
        for lane in Lane::ALL {
            assert!(rendered.contains(lane.heading()), "{lane:?}: {rendered}");
        }
        assert!(
            rendered.contains("makes the run incomplete at a gating severity"),
            "the undecided qualifier survives the floor: {rendered}"
        );
    }

    // -----------------------------------------------------------------
    // The filter and the lookup view
    // -----------------------------------------------------------------

    #[test]
    fn the_filter_covers_the_five_sets_and_opens_on_the_whole_working_set() {
        assert_eq!(FilterSet::default(), FilterSet::Everything);
        let queue = mixed();
        assert_eq!(
            queue.shown(FilterSet::Everything).len(),
            queue.rows.len(),
            "the default narrows nothing"
        );
        let mut seen = Vec::new();
        let mut set = FilterSet::default();
        for _ in 0..FilterSet::ALL.len() {
            seen.push(set);
            set = set.next();
        }
        assert_eq!(set, FilterSet::Everything, "the five cycle");
        assert_eq!(seen.len(), 5);
        assert_eq!(queue.shown(FilterSet::AllFailures).len(), 2);
        assert_eq!(queue.shown(FilterSet::GatingFailures).len(), 2);
        assert_eq!(queue.shown(FilterSet::Undecided).len(), 3);
        assert_eq!(queue.shown(FilterSet::Inert).len(), 3);
    }

    #[test]
    fn the_filter_changes_what_is_shown_and_never_a_count_in_a_heading() {
        let queue = mixed();
        let mut state = State::default();
        let counts: Vec<usize> = Group::ALL.iter().map(|group| queue.count(*group)).collect();
        state.cycle_filter();
        let after: Vec<usize> = Group::ALL.iter().map(|group| queue.count(*group)).collect();
        assert_eq!(counts, after);
        let rendered = rendered(&queue, &state, 120, 40);
        assert!(
            rendered.contains(FilterSet::GatingFailures.label()),
            "{rendered}"
        );
        assert!(rendered.contains("gate required"), "{rendered}");
        assert!(rendered.contains("of 9 shown"), "{rendered}");
    }

    #[test]
    fn the_lookup_view_lists_every_rule_by_id_and_is_never_narrowed() {
        let queue = mixed();
        let ordered: Vec<&str> = queue
            .by_rule_id()
            .into_iter()
            .map(|index| queue.rows[index].rule.as_str())
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted, "the lookup address is the rule id");

        let mut state = State::default();
        state.cycle_filter();
        state.toggle_flat();
        assert_eq!(
            entries(&queue, &state).len(),
            queue.rows.len(),
            "a filter never narrows a lookup"
        );
        let mut seen = String::new();
        for index in 0..queue.rows.len() {
            state.selected = index;
            seen.push_str(&rendered(&queue, &state, 120, 40));
        }
        for row in &queue.rows {
            assert!(seen.contains(&row.rule), "{} is unaddressable", row.rule);
        }
    }

    // -----------------------------------------------------------------
    // Geometry
    // -----------------------------------------------------------------

    #[test]
    fn no_line_overflows_at_either_size() {
        let queue = mixed();
        for (width, height) in [(120u16, 40u16), (80, 24)] {
            let mut state = State::default();
            for index in 0..entries(&queue, &state).len() {
                state.selected = index;
                for flat in [false, true] {
                    if state.flat() != flat {
                        state.toggle_flat();
                        state.selected = index.min(queue.rows.len().saturating_sub(1));
                    }
                    for line in body(styles(), width, height, &queue, &state) {
                        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                        assert!(
                            text.chars().count() <= width as usize,
                            "{width}x{height}: {text:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_screen_never_asks_for_more_rows_than_it_has() {
        let queue = mixed();
        let state = State::default();
        for (width, height) in [(120u16, 40u16), (80, 24)] {
            let lines = body(styles(), width, height, &queue, &state);
            assert!(
                lines.len() <= height as usize,
                "{width}x{height} drew {} lines",
                lines.len()
            );
        }
    }

    #[test]
    fn the_focused_entry_is_always_inside_the_window() {
        let heights = vec![1, 2, 2, 1, 2, 2, 1, 2];
        for selected in 0..heights.len() {
            let (start, end) = window(&heights, selected, 5);
            assert!(start <= selected && selected < end, "{selected}");
            let used: usize = heights[start..end].iter().sum();
            assert!(used <= 5, "{selected} used {used}");
        }
        assert_eq!(window(&[], 0, 5), (0, 0));
        assert_eq!(window(&[1, 1], 0, 0), (0, 0));
    }

    #[test]
    fn scrolling_states_what_lies_above_and_below_and_the_size_of_the_set() {
        let queue = mixed();
        let state = State::default();
        let rendered = rendered(&queue, &state, 80, 24);
        assert!(rendered.contains("above"), "{rendered}");
        assert!(rendered.contains("below"), "{rendered}");
        assert!(rendered.contains("working set"), "{rendered}");
    }

    // -----------------------------------------------------------------
    // The reading with colour removed
    // -----------------------------------------------------------------

    fn monochrome(queue: &Queue, state: &State, width: u16, height: u16) -> String {
        grid(
            Styles::new(Theme::Dark, ColorMode::NoColor),
            queue,
            state,
            width,
            height,
        )
    }

    /// The character grid, one line per row, which is the whole reading.
    fn grid(styles: Styles, queue: &Queue, state: &State, width: u16, height: u16) -> String {
        body(styles, width, height, queue, state)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_reading_is_the_same_text_with_colour_and_without() {
        let queue = mixed();
        let state = State::default();
        for (width, height) in [(120u16, 40u16), (80, 24)] {
            assert_eq!(
                grid(styles(), &queue, &state, width, height),
                monochrome(&queue, &state, width, height),
                "at {width}x{height}"
            );
        }
    }

    #[test]
    fn no_suppressed_or_undecided_row_can_be_read_as_a_pass_without_colour() {
        let queue = mixed();
        let mut state = State::default();
        // Every group expanded, so every row is drawable.
        state.toggle(Group::Aligned, 0);
        let mut seen = Vec::new();
        for index in 0..entries(&queue, &state).len() {
            state.selected = index;
            seen.push(monochrome(&queue, &state, 120, 40));
        }
        let seen = seen.join("\n");
        let pass = lane::glyph_of(Status::Pass);
        for line in seen.lines() {
            if line.contains("suppressed") || line.contains("admin-only") {
                assert!(
                    !line.contains(pass),
                    "a row that is not a pass carried the pass glyph: {line}"
                );
            }
        }
        assert!(seen.contains(lane::glyph_of(Status::Suppressed)));
        assert!(seen.contains(lane::glyph_of(Status::AdminOnly)));
    }

    #[test]
    fn the_groups_that_need_a_person_are_marked_in_a_column_of_their_own() {
        let queue = mixed();
        let state = State::default();
        for group in Group::ALL {
            let line = heading(styles(), 120, &queue, &state, group, false);
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            assert_eq!(
                text.contains(ATTENTION_RAIL),
                group.needs_the_operator(),
                "{group:?}: {text}"
            );
        }
    }

    #[test]
    fn every_group_states_its_emptiness_rather_than_showing_nothing() {
        for group in Group::ALL {
            assert!(!group.emptiness().is_empty(), "{group:?}");
            assert!(!group.gloss().is_empty(), "{group:?}");
            assert!(!group.heading().is_empty(), "{group:?}");
            assert!(!group.tag().is_empty(), "{group:?}");
        }
    }

    #[test]
    fn server_supplied_text_is_made_safe_at_the_one_boundary_that_builds_the_queue() {
        let mut hostile = finding("REPO-CI-02", Severity::Blocking, Status::Error);
        hostile.error = Some(FindingError {
            cause: "transport\u{1b}[2Jcleared".to_owned(),
            endpoint: "GET /repos\u{202e}".to_owned(),
            status: None,
            message: None,
            documentation_url: None,
            accepted_permissions: None,
            request_id: None,
            message_hints_version: 1,
        });
        let queue = Queue::of(
            &report(Gate::Blocking, vec![hostile]),
            &Deliveries::default(),
        );
        let why = &queue.blockers[0].why;
        assert!(!why.contains('\u{1b}'), "{why}");
        assert!(!why.contains('\u{202e}'), "{why}");
        assert!(why.contains('\u{fffd}'), "{why}");
    }

    #[test]
    fn a_fact_the_width_cannot_carry_is_withheld_rather_than_half_printed() {
        let queue = Queue::of(&super::fixture::long_fact(), &Deliveries::default());
        let row = queue
            .rows
            .iter()
            .find(|row| row.group == Group::Judgment)
            .expect("the failure with no declared remediation");
        let reason = row.note.clone().expect("the declared reason");

        // The floor has no reading of it to give, so it says so and prints no
        // part of it.
        let floor = rendered(&queue, &State::default(), FLOOR_WIDTH, FLOOR_HEIGHT);
        assert!(floor.contains("fact withheld"), "{floor}");
        let opening: String = reason.chars().take(40).collect();
        assert!(
            !floor.contains(&opening),
            "a fact was half printed: {floor}"
        );
        assert!(floor.contains("REPO-DOCS-05"), "{floor}");
        assert!(floor.contains("docs"), "{floor}");

        // The reference carries the same fact whole, which is the direction the
        // rule runs in: widening a terminal adds a fact and never takes one
        // away.
        let reference = rendered(&queue, &State::default(), REFERENCE_WIDTH, REFERENCE_HEIGHT);
        assert!(reference.contains(&reason), "{reference}");
        assert!(!reference.contains("fact withheld"), "{reference}");
    }

    /// A row carrying a fact of a chosen length, and nothing else unusual.
    fn carrying(fact: &str) -> Row {
        Row {
            rule: "REPO-DOCS-05".to_owned(),
            statement: "the condition REPO-DOCS-05 states".to_owned(),
            severity: Severity::Required,
            status: Status::Fail,
            section: "docs".to_owned(),
            gate: Gate::Required,
            group: Group::Judgment,
            delivery: Delivery::Unknown,
            note: Some(fact.to_owned()),
            detail: Detail::of(
                &finding("REPO-DOCS-05", Severity::Required, Status::Fail),
                &[],
            ),
            remediation: None,
            change: None,
            reversible: None,
            capability: None,
        }
    }

    /// The row as drawn at a width, both of its lines where it has two.
    fn drawn(row: &Row, width: u16) -> String {
        let width = width as usize;
        row_lines(styles(), width, row, false, panel::density(width))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn a_wider_screen_never_shows_less_of_a_fact_than_a_narrower_one() {
        // The property, over the whole range rather than at two chosen widths.
        // Every width from the floor to well past the reference is swept, so
        // the change of reading at 100 columns is one of the adjacent pairs
        // rather than something the endpoints stepped over, and every fact
        // length spanning both boundaries is tried. Widening a terminal may add
        // a fact to a row; it may never take one away.
        for length in 0..=140usize {
            let fact = "f".repeat(length);
            let row = carrying(&fact);
            let mut shown_at: Option<u16> = None;
            for width in FLOOR_WIDTH..=REFERENCE_WIDTH + 20 {
                let whole = length == 0 || drawn(&row, width).contains(&fact);
                match (shown_at, whole) {
                    (None, true) => shown_at = Some(width),
                    (Some(first), false) => panic!(
                        "a fact of {length} characters is whole at {first} \
                         columns and withheld at {width}"
                    ),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn a_row_takes_a_second_line_rather_than_withhold_a_fact_the_width_could_carry() {
        // What holds the property across the change of reading. The one-line
        // reading has less room for a fact than the two-line one at every
        // width, so a row whose fact does not fit beside its statement takes
        // the second line instead of withholding a fact the same terminal could
        // have shown.
        let width = REFERENCE_WIDTH as usize;
        let beside = "f".repeat(width - SPENT);
        assert!(one_line(&carrying(&beside), width, Density::Full));
        let over = "f".repeat(width - SPENT + 1);
        assert!(!one_line(&carrying(&over), width, Density::Full));
        let rendered = drawn(&carrying(&over), REFERENCE_WIDTH);
        assert!(rendered.contains(&over), "{rendered}");
        // And the queue budgets for the line it actually draws.
        let queue = Queue::of(&super::fixture::mixed(), &Deliveries::default());
        for (width, density) in [
            (FLOOR_WIDTH as usize, Density::Tight),
            (REFERENCE_WIDTH as usize, Density::Full),
        ] {
            for (index, row) in queue.rows.iter().enumerate() {
                assert_eq!(
                    entry_height(&queue, &Entry::Row(index), width, density),
                    row_lines(styles(), width, row, false, density).len(),
                    "{} at {width}",
                    row.rule
                );
            }
        }
    }

    #[test]
    fn a_fact_is_carried_up_to_the_room_the_row_actually_has() {
        // The boundary, stated rather than implied: a row's fact has the width
        // less what stands to the left of it on the line it can always fall
        // back to. Both readings spend the same marks, so one boundary serves
        // every width.
        for width in [FLOOR_WIDTH, REFERENCE_WIDTH] {
            let room = width as usize - MARKS;
            let fits = "f".repeat(room);
            assert!(
                drawn(&carrying(&fits), width).contains(&fits),
                "a fact of exactly {room} characters is withheld at {width}"
            );
            let over = "f".repeat(room + 1);
            let rendered = drawn(&carrying(&over), width);
            assert!(
                !rendered.contains(&over) && rendered.contains("fact withheld"),
                "a fact of {} characters was not withheld at {width}: {rendered}",
                room + 1
            );
        }
    }

    #[test]
    fn a_fact_that_fits_is_printed_whole_at_both_widths() {
        let queue = queue(vec![finding(
            "REPO-GIT-04",
            Severity::Required,
            Status::AdminOnly,
        )]);
        let whole = queue.rows[0].note.clone().expect("the declaration");
        for width in [120u16, 80] {
            let rendered = rendered(&queue, &State::default(), width, 40);
            assert!(rendered.contains(&whole), "at {width}: {rendered}");
            assert!(!rendered.contains("fact withheld"), "at {width}");
        }
    }

    #[test]
    fn the_status_line_states_the_verdict_completeness_the_count_and_the_gate() {
        let queue = mixed();
        let status = status(&queue);
        assert!(status.contains("complete"), "{status}");
        assert!(status.contains("9 rules"), "{status}");
        assert!(status.contains("registry"), "{status}");
        assert!(status.contains("gate required"), "{status}");
    }
}
