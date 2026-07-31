//! The application state and everything it draws.
//!
//! Nothing here touches a terminal. The state is a plain value, the drawing
//! takes a ratatui frame, and key handling is a pure transition, so the whole
//! interface can be rendered into a buffer and compared.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget as _, Wrap};

/// The column the emptiness values start in.
const FIELD_LABEL_WIDTH: usize = 16;

/// What an unselected installation reaches: nothing, completely.
///
/// Complete rather than truncated: there is no listing here to be a prefix of,
/// and saying "a prefix" would claim airlock fell short of something.
const EMPTY_REACH: catalogue::Reach = catalogue::Reach {
    collected: 0,
    total: 0,
    truncated: false,
};

use airlock_core::findings::Status;
use airlock_core::registry::Severity;

use super::chrome::{self, wrap};
use super::lane::{self, Lane};
use crate::admin::catalogue::{self, Observations, Observe, Row};
use crate::admin::flow::Progress;
use crate::admin::session::Validity;
use crate::admin::sign_in::{Density, Reason, SignIn};

use super::detail;
use super::findings;
use super::organizations;
use super::panel;
use super::policy;
use super::remediation;
use super::repositories::{self, Filter};
use super::screen::{Key, Screen, INPUT_KEYS, REAUTHORIZATION_KEYS};
use super::sign_in;
use super::theme::{ColorMode, Role, Styles, Theme};

/// What the application does after handling an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Keep running.
    Continue,
    /// Restore the terminal and leave.
    Exit,
    /// Abandon the device code on screen and ask for a new one.
    Reissue,
    /// Offer a value to the terminal's clipboard.
    ///
    /// A value rather than an action, because this type does not own the
    /// terminal: it says what it would like held, and the loop that does own
    /// the terminal asks for it. Only two values ever travel here — a rule id
    /// and the registry digest — and no credential is on any screen to be one
    /// of them.
    Copy(String),
}

/// Where the operator was standing when the grant lapsed.
///
/// Addresses and places in lists, and nothing else. Every field here is either
/// a name the operator navigated to or where they stood inside something; none
/// of them is a fact airlock observed about a repository, and none of them can
/// become one, because this type has no field a `Queue`, a `Catalogue`, a
/// `Row`, or a transcript could travel in. That is what makes "position is
/// held, observations are not" a property of the type rather than a promise
/// made by the code that fills it.
///
/// The two names are addresses rather than results: they say where to look
/// again, and everything that was seen there is looked up afresh under the new
/// authorization.
#[derive(Debug, Clone)]
struct Position {
    /// The screen that was open. A remediation in flight holds the queue
    /// behind it instead: a partly applied queue is re-observed, never resumed
    /// from a transcript written under a grant that has lapsed.
    screen: Screen,
    /// The account of the installation that was open.
    installation: Option<String>,
    /// The name of the repository the cursor was on.
    repository: Option<String>,
    /// The repository the queue was observed from, as coordinates.
    target: Option<Observe>,
    /// The incremental filter over the repository name.
    filter: Filter,
    /// Where the operator was in the queue: the row, the named set, the
    /// collapsed groups, and whether the flat lookup was open.
    findings: findings::State,
    /// Where the operator was in a finding's reading.
    detail: panel::Scroll,
    /// Where the operator was in the effective policy.
    inspection: panel::Scroll,
}

impl Position {
    /// Read the position off the interface, and nothing else off it.
    fn of(app: &App) -> Self {
        Self {
            // The transcript is an observation; the queue behind it is where
            // the operator stands once it is gone.
            screen: if app.screen == Screen::Remediation {
                Screen::Findings
            } else {
                app.screen
            },
            installation: app
                .selected_installation()
                .map(|installation| installation.account.clone()),
            repository: app
                .visible_rows()
                .get(app.repository)
                .map(|row| row.repository.name.clone()),
            target: app.requested.clone(),
            filter: app.filter.clone(),
            findings: app.findings.clone(),
            detail: app.detail.clone(),
            inspection: app.inspection.clone(),
        }
    }

    /// What the interface is holding, said rather than left to be trusted.
    ///
    /// Two readings of one fact, as every other screen answers a narrow
    /// terminal: the same things in fewer words rather than some of them and
    /// not the rest. The tight reading drops what the frame is already saying —
    /// the screen label names an open detail by being `finding detail`, and the
    /// breadcrumb carries the trail — and never drops where the operator is.
    fn holding(&self, density: Density) -> String {
        let tight = density == Density::Tight;
        let mut parts = vec![self.screen.label().to_owned()];
        match &self.target {
            Some(target) => parts.push(format!("{}/{}", target.owner, target.name)),
            None => {
                if let Some(installation) = &self.installation {
                    parts.push(installation.clone());
                }
                if let Some(repository) = &self.repository {
                    parts.push(repository.clone());
                }
            }
        }
        if !self.filter.text().is_empty() {
            parts.push(format!("name filter \"{}\"", self.filter.text()));
        }
        if matches!(
            self.screen,
            Screen::Findings | Screen::FindingDetail | Screen::PolicyInspector
        ) {
            parts.push(format!("row {}", self.findings.selected() + 1));
            parts.push(self.findings.filter().label().to_owned());
            if self.findings.flat() {
                parts.push("flat lookup open".to_owned());
            }
            if !tight {
                let collapsed: Vec<String> = findings::Group::ALL
                    .iter()
                    .filter(|group| self.findings.is_collapsed(**group))
                    .map(|group| group.number().to_string())
                    .collect();
                parts.push(if collapsed.is_empty() {
                    "no group collapsed".to_owned()
                } else {
                    format!("groups {} collapsed", collapsed.join(", "))
                });
                parts.push(
                    if self.screen == Screen::FindingDetail {
                        "detail open"
                    } else {
                        "detail closed"
                    }
                    .to_owned(),
                );
            }
        }
        parts.join(" \u{b7} ")
    }
}

/// What the interface holds of a queue's position while it is re-observed.
///
/// Taken by the next observation that arrives rather than applied at once:
/// there is no queue to be positioned in until one has been observed again.
#[derive(Debug, Clone)]
struct HeldQueue {
    findings: findings::State,
    detail: panel::Scroll,
    inspection: panel::Scroll,
}

/// The whole interface state.
#[derive(Debug, Clone)]
pub struct App {
    screen: Screen,
    theme: Theme,
    color: ColorMode,
    version: String,
    sign_in: sign_in::Screen,
    authorized: bool,
    /// The installations this credential reaches, and what is in each.
    catalogue: catalogue::State,
    /// Which installation is selected on the organizations screen.
    installation: usize,
    /// Which repository is selected on the repositories screen.
    repository: usize,
    /// The incremental filter over the repository name.
    filter: Filter,
    /// What this session has observed. Nothing else can populate it: there is
    /// no store behind it and nothing reads one.
    observations: Observations,
    /// The observation the last `↵` on a repository asked for.
    requested: Option<Observe>,
    pending_observation: Option<Observe>,
    /// The run the findings screen draws, once one has been observed.
    ///
    /// A read model rather than the audit document: it is built at one
    /// boundary, which is where every string the run did not write itself is
    /// made safe to draw.
    queue: Option<Box<findings::Queue>>,
    /// Where the operator is in the queue, and what it is showing.
    findings: findings::State,
    /// Where the operator is in a finding's reading.
    detail: panel::Scroll,
    /// The effective policy the run ran under.
    ///
    /// A second read model built from the same run at the same instant, held to
    /// the same rule as the first: the audit document is never retained
    /// anywhere this type draws from, so no server-supplied string has a path
    /// to a cell.
    inspector: Option<Box<policy::Inspector>>,
    /// Where the operator is in the effective policy.
    inspection: panel::Scroll,
    /// The rule `o` last asked to be re-observed.
    ///
    /// The request, not a result. What a re-observation concluded is shown when
    /// the observation returns; recording the asking is all this type may
    /// honestly do with the key.
    reobserve: Option<String>,
    /// What the status line says about the key just pressed, for one frame.
    ///
    /// A key the screen lists and that does nothing on this row says why rather
    /// than silently doing nothing.
    note: Option<String>,
    remediation: remediation::State,
    pending_remediation: Option<remediation::Request>,
    pending_preparation: Option<(Observe, String)>,
    pending_undo: Option<remediation::UndoRequest>,
    /// What is left of the session's grant, where one is held.
    ///
    /// A duration and never a value. It is what the header counts down and
    /// what reaching zero makes the interface re-authorize, so the lapse is
    /// something the operator watched coming rather than something that
    /// happened to them.
    grant: Option<Validity>,
    /// The position being held while the grant is replaced.
    ///
    /// `Some` is the whole of "the re-authorization overlay is up": there is
    /// no separate screen and no second flag that could disagree with it.
    reauthorization: Option<Position>,
    /// Whether the run loop has yet been told to discard the credential and
    /// ask for a new device code.
    reauthorization_requested: bool,
    /// The queue position waiting for the re-observation that will restore it.
    held_queue: Option<HeldQueue>,
    /// The installation and repository to find again once a fresh catalogue
    /// arrives, by name rather than by index: an index into a list that has
    /// been read again is not the row it was.
    held_selection: Option<(Option<String>, Option<String>)>,
}

impl App {
    /// Open the interface at its entry screen.
    #[must_use]
    pub fn new(version: impl Into<String>, color: ColorMode) -> Self {
        Self {
            screen: Screen::ENTRY,
            theme: Theme::Dark,
            color,
            version: version.into(),
            sign_in: sign_in::Screen::default(),
            authorized: false,
            catalogue: catalogue::State::Unauthorized,
            installation: 0,
            repository: 0,
            filter: Filter::default(),
            observations: Observations::default(),
            requested: None,
            pending_observation: None,
            queue: None,
            findings: findings::State::default(),
            detail: panel::Scroll::default(),
            inspector: None,
            inspection: panel::Scroll::default(),
            reobserve: None,
            note: None,
            remediation: remediation::State::default(),
            pending_remediation: None,
            pending_preparation: None,
            pending_undo: None,
            grant: None,
            reauthorization: None,
            reauthorization_requested: false,
            held_queue: None,
            held_selection: None,
        }
    }

    /// Open the interface with a catalogue already read.
    ///
    /// The snapshot suite and the key tests need every state of these two
    /// screens, and the state they need is what GitHub answered — which is
    /// exactly what neither of them has.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn with_catalogue(mut self, catalogue: catalogue::Catalogue) -> Self {
        self.catalogue = catalogue::State::Ready(Box::new(catalogue));
        self
    }

    #[cfg(test)]
    #[cfg_attr(feature = "test-identity", allow(dead_code))]
    #[must_use]
    pub fn with_remediation(mut self, remediation: remediation::State) -> Self {
        self.remediation = remediation;
        self
    }

    /// Record what an observation made in this session reached.
    ///
    /// The one way the journal is populated, and it takes an observation rather
    /// than a repository: a verdict airlock did not produce in this session is
    /// not a verdict it has.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn observed(
        &mut self,
        observe: &Observe,
        at: impl Into<String>,
        verdict: impl Into<String>,
    ) {
        if self.reauthorizing_now() {
            return;
        }
        self.observations.record(observe, at, verdict);
    }

    /// The observation the interface last asked for.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn requested(&self) -> Option<&Observe> {
        self.requested.as_ref()
    }

    /// Take the fresh repository observation request exactly once.
    pub fn take_observation_request(&mut self) -> Option<Observe> {
        self.pending_observation.take()
    }

    /// Take a confirmed remediation exactly once.
    pub fn take_remediation_request(&mut self) -> Option<remediation::Request> {
        self.pending_remediation.take()
    }

    pub fn take_preparation_request(&mut self) -> Option<(Observe, String)> {
        self.pending_preparation.take()
    }

    pub fn take_undo_request(&mut self) -> Option<remediation::UndoRequest> {
        self.pending_undo.take()
    }

    pub fn remediation_prepared(
        &mut self,
        remediation_code: &str,
        input: crate::admin::remediation::PreparedInput,
    ) {
        if self.reauthorizing_now() {
            return;
        }
        let remediation::State::Input { request } = &mut self.remediation else {
            return;
        };
        let Some(item) = request
            .items
            .iter_mut()
            .find(|item| item.remediation == remediation_code)
        else {
            return;
        };
        item.input = match input {
            crate::admin::remediation::PreparedInput::Rulesets(values) => {
                remediation::Input::Choice {
                    values,
                    selected: 0,
                    empty: "no freshly observed organization rulesets are available".to_owned(),
                }
            }
            crate::admin::remediation::PreparedInput::Variables(names) => {
                remediation::Input::VariableRename {
                    names,
                    selected: 0,
                    draft: String::new(),
                    notice: remediation::SECRET_DEFERRAL_NOTICE.to_owned(),
                    error: None,
                }
            }
        };
    }

    /// Close the remediation screen with the post-write observation.
    pub fn remediation_complete(&mut self, transcript: crate::admin::remediation::Transcript) {
        if self.reauthorizing_now() {
            return;
        }
        self.remediation.complete(transcript);
    }

    /// Close a bulk confirmation with one post-write transcript per rule.
    pub fn remediation_group_complete(
        &mut self,
        transcripts: Vec<crate::admin::remediation::Transcript>,
    ) {
        if self.reauthorizing_now() {
            return;
        }
        self.remediation.complete_group(transcripts);
    }

    /// Show a sanitized operational failure in the status line.
    pub fn operation_failed(&mut self, cause: String) {
        if self.reauthorizing_now() {
            return;
        }
        self.note = Some(cause);
    }

    /// Take a run onto the findings screen.
    ///
    /// The one way the queue is populated, and the one boundary at which the
    /// audit document becomes something this type draws: what it keeps is a
    /// read model whose every server-supplied string was sanitized on the way
    /// in. The position is reset, because a position in one repository's queue
    /// is not a position in another's.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn observed_run(
        &mut self,
        report: &airlock_core::findings::Report,
        deliveries: &findings::Deliveries,
    ) {
        // A run that was in flight when the grant lapsed is a reading taken
        // under a credential this session no longer holds. It is refused here
        // as well as dropped with its worker, so the boundary holds whatever
        // order a caller drains its queues in.
        if self.reauthorizing_now() {
            return;
        }
        // A run in which GitHub rejected airlock's own credential is not a
        // reading of the repository. It is the grant having lapsed, observed —
        // and drawing it as a queue would be drawing a repository as failing
        // rules nothing was able to ask about.
        if rejected(report) {
            self.lapse();
            return;
        }
        self.queue = Some(Box::new(findings::Queue::of(report, deliveries)));
        self.inspector = Some(Box::new(policy::Inspector::of(report)));
        match self.held_queue.take() {
            // The position an expiry held, now that there is a queue for it to
            // be a position in. Clamped to the run that has just arrived: the
            // rows are freshly observed and there may be fewer of them.
            Some(held) => {
                self.findings = held.findings;
                self.detail = held.detail;
                self.inspection = held.inspection;
                if let Some(queue) = self.queue.as_deref() {
                    let entries = findings::entries(queue, &self.findings).len();
                    self.findings.clamp(entries);
                }
            }
            None => {
                self.findings = findings::State::default();
                self.detail = panel::Scroll::default();
                self.inspection = panel::Scroll::default();
            }
        }
        self.reobserve = None;
        self.note = None;
    }

    /// The rule the interface last asked to re-observe.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn reobserve_requested(&self) -> Option<&str> {
        self.reobserve.as_deref()
    }

    /// Open the interface with the sign-in flow in a given state.
    ///
    /// The five states are reached by what GitHub answers, and the suite has no
    /// GitHub. This is how each one is rendered and compared.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn signing_in(mut self, state: crate::admin::sign_in::SignIn) -> Self {
        // A re-authorization is this same flow drawn over the screen the grant
        // lapsed on, so giving it a state must not move the operator to
        // sign-in: the held screen is the position being held.
        if self.reauthorization.is_none() {
            self.screen = Screen::SignIn;
        }
        self.sign_in = sign_in::Screen::at(state);
        self
    }

    /// Open the interface on a given screen and palette.
    ///
    /// The snapshot suite must reach every screen without a session, and a
    /// session is exactly what this build does not have.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn at(mut self, screen: Screen, theme: Theme) -> Self {
        self.screen = screen;
        self.theme = theme;
        self
    }

    /// The screen currently open.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn screen(&self) -> Screen {
        self.screen
    }

    /// The palette in force.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn theme(&self) -> Theme {
        self.theme
    }

    fn styles(&self) -> Styles {
        Styles::new(self.theme, self.color)
    }

    /// Apply a key.
    ///
    /// `ctrl-c` exits from every state without exception, and it is taken
    /// first, before anything can capture it. `t` switches theme everywhere
    /// else. Everything after that is the open state's own.
    pub fn handle_key(&mut self, event: KeyEvent) -> Flow {
        // A terminal that reports key releases would otherwise act twice.
        if event.kind == KeyEventKind::Release {
            return Flow::Continue;
        }
        if event.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(event.code, KeyCode::Char('c'))
        {
            return Flow::Exit;
        }
        // The overlay takes every remaining key. Nothing behind it can act:
        // what the held screen's keys acted on was observed under a grant that
        // has lapsed, and none of it is on the screen any more.
        if self.reauthorization.is_some() {
            return self.reauthorizing(event.code);
        }
        if self.screen == Screen::Remediation && self.remediation.is_input() {
            if event.code == KeyCode::Esc {
                self.screen = Screen::Findings;
                return Flow::Continue;
            }
            if self.remediation.input_key(event.code) {
                return Flow::Continue;
            }
        }
        // A focused text input takes printable keys as text, `t` included. The
        // footer stops advertising the theme toggle for exactly as long as
        // this holds, so nothing on screen names a key this state has taken.
        if self.screen == Screen::Repositories && self.filter.is_open() {
            return self.filtering(event.code);
        }
        // A note stands for one frame: it answers the key that was just
        // pressed, and the next key is a different question.
        self.note = None;
        if self.screen == Screen::Findings {
            if let Some(flow) = self.working(event.code) {
                return flow;
            }
        }
        if self.screen == Screen::FindingDetail {
            if let Some(flow) = self.reading(event.code) {
                return flow;
            }
        }
        if self.screen == Screen::PolicyInspector {
            if let Some(flow) = self.inspecting(event.code) {
                return flow;
            }
        }
        if self.screen == Screen::Remediation && matches!(event.code, KeyCode::Enter) {
            self.pending_remediation = self.remediation.take_confirmation();
            return Flow::Continue;
        }
        if self.screen == Screen::Remediation && event.code == KeyCode::Char('u') {
            self.pending_undo = self.remediation.take_undo();
            if self.pending_undo.is_none() {
                self.note = Some("undo is unavailable for this change".to_owned());
            }
            return Flow::Continue;
        }
        match event.code {
            KeyCode::Char('t') => self.theme = self.theme.toggled(),
            KeyCode::Enter => return self.forward(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char('/') if self.screen == Screen::Repositories => self.filter.open(),
            KeyCode::Esc => {
                if let Some(previous) = self.screen.back() {
                    self.screen = previous;
                }
            }
            KeyCode::Char('p') if self.screen == Screen::Findings => {
                self.screen = Screen::PolicyInspector;
                self.inspection.rewind();
            }
            KeyCode::Char('b') if self.screen == Screen::Findings => {
                self.screen = Screen::PublishingBootstrap;
            }
            KeyCode::Char('q') if self.screen == Screen::SignIn => self.sign_in.cycle_scan(),
            // `r` is live only once a device code exists, because until then
            // there is nothing to reissue. Asking for a replacement is a
            // transition of this screen's state and nothing else: the session
            // is not restarted.
            KeyCode::Char('r')
                if self.screen == Screen::SignIn && self.sign_in.state().has_code() =>
            {
                self.sign_in.state_mut().reissue(Reason::Asked);
                return Flow::Reissue;
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Keys the re-authorization overlay takes.
    ///
    /// Sign-in's own, because the overlay is sign-in drawn over the screen the
    /// operator was on. `esc` abandons and leaves rather than walking back a
    /// screen: there is nothing behind this to return to until an
    /// authorization exists again.
    fn reauthorizing(&mut self, code: KeyCode) -> Flow {
        match code {
            KeyCode::Esc => return Flow::Exit,
            KeyCode::Char('t') => self.theme = self.theme.toggled(),
            KeyCode::Char('q') => self.sign_in.cycle_scan(),
            KeyCode::Char('r') if self.sign_in.state().has_code() => {
                self.sign_in.state_mut().reissue(Reason::Asked);
                return Flow::Reissue;
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Keys the work queue takes for itself.
    ///
    /// `None` hands the key back to the screen-independent reading, which is
    /// how `t`, `esc`, `p`, and `b` keep meaning what they mean here. Nothing in
    /// this state captures a printable key as text, so both chrome surfaces go
    /// on offering everything they offer.
    ///
    /// `a` is answered whether or not a run has been observed, because a key
    /// the footer lists and that silently does nothing is a key the operator
    /// presses again.
    fn working(&mut self, code: KeyCode) -> Option<Flow> {
        if matches!(code, KeyCode::Char('a' | 'A')) {
            let row_is_settings = self.focused_row().is_some_and(|row| {
                (row.group == findings::Group::Settings && row.status == Status::Fail)
                    || (row.group == findings::Group::Decision
                        && row.status == Status::Inconclusive)
            });
            if row_is_settings {
                if code == KeyCode::Char('A') {
                    self.open_remediation_group();
                } else {
                    self.open_remediation();
                }
            } else {
                self.note = Some(findings::inert_apply());
            }
            return Some(Flow::Continue);
        }
        let queue = self.queue.as_deref()?;
        let entries = findings::entries(queue, &self.findings);
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.findings.move_selection(-1, entries.len()),
            KeyCode::Down | KeyCode::Char('j') => self.findings.move_selection(1, entries.len()),
            // Collapse is about the focused group, whether the focus is on its
            // heading or on a row inside it. Collapsing puts the focus on the
            // heading, because that is where the group now is.
            KeyCode::Char(' ') if !self.findings.flat() => {
                if let Some(group) =
                    findings::focused_group(queue, &entries, self.findings.selected())
                {
                    self.findings
                        .toggle(group, findings::heading_index(&entries, group));
                }
            }
            KeyCode::Char('f') => self.findings.cycle_filter(),
            KeyCode::Char('l') => self.findings.toggle_flat(),
            // A group heading opens nothing: there is no finding under the
            // focus to show a detail of.
            KeyCode::Enter => {
                if findings::focused_row(queue, &entries, self.findings.selected()).is_some() {
                    self.screen = Screen::FindingDetail;
                    // A position in one finding's reading is not a position in
                    // another's.
                    self.detail.rewind();
                }
            }
            _ => return None,
        }
        let queue = self.queue.as_deref()?;
        self.findings
            .clamp(findings::entries(queue, &self.findings).len());
        Some(Flow::Continue)
    }

    /// Keys the finding detail takes for itself.
    ///
    /// `None` hands the key back, which is how `t` and `esc` keep meaning what
    /// they mean here. Nothing in this state captures a printable key as text,
    /// so both chrome surfaces go on offering everything they offer.
    ///
    /// The three keys that act on the finding are answered whether or not there
    /// is one under the focus, because a key the footer lists and that silently
    /// does nothing is a key the operator presses again.
    fn reading(&mut self, code: KeyCode) -> Option<Flow> {
        let rule = self.focused_row().map(|row| row.rule.clone());
        match code {
            KeyCode::Up => self.detail.by(-1),
            KeyCode::Down => self.detail.by(1),
            // The transcript is reachable only where there is a settings-level
            // change to carry out. Elsewhere the status line says why rather
            // than the key silently doing nothing.
            KeyCode::Char('a') => self.open_remediation(),
            KeyCode::Char('o') => match rule {
                Some(rule) => {
                    self.note = Some(detail::reobserving(&rule));
                    self.reobserve = Some(rule);
                }
                None => self.note = Some(detail::nothing_to_act_on()),
            },
            KeyCode::Char('y') => {
                return Some(match rule {
                    Some(rule) => {
                        self.note = Some(detail::copied(&rule));
                        Flow::Copy(rule)
                    }
                    None => {
                        self.note = Some(detail::nothing_to_act_on());
                        Flow::Continue
                    }
                })
            }
            _ => return None,
        }
        Some(Flow::Continue)
    }

    /// Keys the policy inspector takes for itself.
    ///
    /// The digest, the sources, the provenance, and the table are one reading,
    /// so the arrows move a window over all of it rather than selecting inside
    /// one part of it.
    fn inspecting(&mut self, code: KeyCode) -> Option<Flow> {
        match code {
            KeyCode::Up => self.inspection.by(-1),
            KeyCode::Down => self.inspection.by(1),
            KeyCode::Char('y') => {
                return Some(match self.inspector.as_deref() {
                    Some(inspector) => {
                        self.note = Some(policy::copied());
                        Flow::Copy(inspector.provenance.registry_digest.clone())
                    }
                    None => {
                        self.note = Some(policy::nothing_to_copy());
                        Flow::Continue
                    }
                })
            }
            _ => return None,
        }
        Some(Flow::Continue)
    }

    /// The row the queue's focus is on, when it is on one.
    fn focused_row(&self) -> Option<&findings::Row> {
        let queue = self.queue.as_deref()?;
        let entries = findings::entries(queue, &self.findings);
        findings::focused_row(queue, &entries, self.findings.selected())
    }

    fn open_remediation(&mut self) {
        let Some(row) = self.focused_row().cloned() else {
            self.note = Some(findings::inert_apply());
            return;
        };
        let actionable = (row.group == findings::Group::Settings
            && row.status == Status::Fail
            && row.detail.remediation.code.is_some())
            || (row.group == findings::Group::Decision
                && row.status == Status::Inconclusive
                && row.remediation.as_deref() == Some("declare-capability-property"));
        if !actionable {
            self.note = Some(findings::inert_apply());
            return;
        }
        let target = self.requested.clone().or_else(|| {
            let (owner, name) = self.queue.as_deref()?.repository.split_once('/')?;
            Some(Observe {
                owner: owner.to_owned(),
                name: name.to_owned(),
            })
        });
        let Some(target) = target else {
            self.note = Some("the repository must be re-observed before applying".to_owned());
            return;
        };
        let (Some(code), Some(change), Some(reversible)) =
            (row.remediation, row.change, row.reversible)
        else {
            self.note = Some("this rule declares no settings remediation".to_owned());
            return;
        };
        let input = if code == "declare-capability-property" {
            let Some((property, value)) = row.capability else {
                self.note = Some("the capability declaration was not observed".to_owned());
                return;
            };
            let organization = self.catalogue.installations().iter().any(|installation| {
                installation.account.eq_ignore_ascii_case(&target.owner)
                    && installation.kind == airlock_core::github::AccountKind::Organization
            });
            if !organization {
                self.note = Some(
                    "capability declarations require an organization-owned repository".to_owned(),
                );
                return;
            }
            remediation::Input::Fixed {
                argument: format!("{property}\n{value}"),
                display: format!(
                    "{} = {} · organization {}",
                    crate::admin::text::drawable(&property),
                    crate::admin::text::drawable(&value),
                    target.owner
                ),
            }
        } else {
            self.remediation_input(&code, &target)
        };
        if matches!(
            code.as_str(),
            "attach-org-rulesets"
                | "tighten-org-rulesets"
                | "rename-app-credentials"
                | "rename-task-named-credentials"
        ) {
            self.pending_preparation = Some((target.clone(), code.clone()));
        }
        self.remediation = remediation::State::confirm(
            target.owner,
            target.name,
            vec![remediation::Item {
                rule: row.rule,
                remediation: code,
                change,
                reversible,
                input,
            }],
        );
        self.screen = Screen::Remediation;
    }

    fn remediation_input(&self, code: &str, target: &Observe) -> remediation::Input {
        match code {
            "rename-repository-kebab"
            | "rename-repository-undotted"
            | "rename-repository-family-prefix" => remediation::Input::Text {
                draft: remediation::rename_candidate(code, &target.name, None),
                required_prefix: None,
                error: None,
            },
            "transfer-repository" => remediation::Input::Transfer {
                destinations: self
                    .catalogue
                    .installations()
                    .iter()
                    .map(|installation| installation.account.clone())
                    .filter(|account| account != &target.owner)
                    .collect(),
                selected: 0,
                typed_name: String::new(),
            },
            "attach-org-rulesets" | "tighten-org-rulesets" => remediation::Input::Choice {
                values: Vec::new(),
                selected: 0,
                empty: "no freshly observed organization ruleset choices are available".to_owned(),
            },
            "rename-app-credentials" | "rename-task-named-credentials" => {
                remediation::Input::VariableRename {
                    names: Vec::new(),
                    selected: 0,
                    draft: String::new(),
                    notice: remediation::SECRET_DEFERRAL_NOTICE.to_owned(),
                    error: None,
                }
            }
            _ => remediation::Input::None,
        }
    }

    fn open_remediation_group(&mut self) {
        let Some(focused) = self.focused_row() else {
            return;
        };
        let focused_kind = focused.remediation.as_deref().and_then(bulk_kind);
        if focused_kind.is_none() {
            self.note =
                Some("bulk is unavailable because this remediation takes an input".to_owned());
            return;
        }
        let target = self.requested.clone().or_else(|| {
            let (owner, name) = self.queue.as_deref()?.repository.split_once('/')?;
            Some(Observe {
                owner: owner.to_owned(),
                name: name.to_owned(),
            })
        });
        let Some(target) = target else {
            self.note = Some("the repository must be re-observed before applying".to_owned());
            return;
        };
        let Some(queue) = self.queue.as_deref() else {
            return;
        };
        let items = bulk_items(queue, focused_kind.expect("checked above"));
        if items.len() < 2 {
            self.note = Some("no other open input-free remediation has the same kind".to_owned());
            return;
        }
        self.remediation = remediation::State::confirm(target.owner, target.name, items);
        self.screen = Screen::Remediation;
    }

    /// Keys while the repository filter is open.
    fn filtering(&mut self, code: KeyCode) -> Flow {
        match code {
            KeyCode::Esc => {
                self.filter.close();
                self.repository = 0;
            }
            KeyCode::Backspace => {
                self.filter.backspace();
                self.repository = 0;
            }
            KeyCode::Enter => return self.forward(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char(character) => {
                self.filter.push(character);
                self.repository = 0;
            }
            _ => {}
        }
        Flow::Continue
    }

    /// What `↵` opens from here.
    ///
    /// Sign-in is not on this path: the screen after it is opened by an
    /// authorization arriving, not by a key, because there is nothing to choose
    /// from until one does. The two selection screens open only what they have
    /// selected, so a key press on an empty list opens nothing rather than an
    /// empty screen about nothing.
    fn forward(&mut self) -> Flow {
        match self.screen {
            Screen::SignIn => {}
            Screen::Organizations => {
                if self.selected_installation().is_some() {
                    self.screen = Screen::Repositories;
                    self.repository = 0;
                    self.filter.close();
                }
            }
            Screen::Repositories => return self.observe(),
            other => {
                if let Some(next) = other.forward() {
                    self.screen = next;
                }
            }
        }
        Flow::Continue
    }

    /// Open the selected repository, which is to observe it in full.
    ///
    /// The request is [`Row::observe`], which is built from the row's
    /// coordinates alone. Nothing the screen remembers about the repository
    /// travels with it, so no prior verdict can shorten or steer what follows.
    fn observe(&mut self) -> Flow {
        if let Some(row) = self.visible_rows().get(self.repository) {
            let request = row.observe();
            self.requested = Some(request.clone());
            self.pending_observation = Some(request);
            self.screen = Screen::Findings;
            // A position in one repository's queue is not a position in
            // another's, so opening a different repository lets go of a
            // position an expiry was holding.
            self.held_queue = None;
        }
        Flow::Continue
    }

    fn move_selection(&mut self, delta: isize) {
        let (selected, len) = match self.screen {
            Screen::Organizations => (&mut self.installation, organizations::len(&self.catalogue)),
            Screen::Repositories => {
                let len = self.visible_rows().len();
                (&mut self.repository, len)
            }
            _ => return,
        };
        if len == 0 {
            *selected = 0;
            return;
        }
        let last = len - 1;
        *selected = match delta {
            d if d < 0 => selected.saturating_sub(1),
            _ => (*selected + 1).min(last),
        }
        .min(last);
    }

    fn selected_installation(&self) -> Option<&catalogue::Installation> {
        self.catalogue.installations().get(self.installation)
    }

    /// How far the selected installation's listing got.
    ///
    /// Read from the listing rather than counted off the rows, so a walk that
    /// stopped at the page budget is reported as the prefix it is instead of
    /// as a complete account of a smaller installation.
    fn reach(&self) -> catalogue::Reach {
        self.selected_installation()
            .map_or(EMPTY_REACH, |installation| installation.listing.reach())
    }

    /// The rows of the selected installation, narrowed by the filter.
    fn visible_rows(&self) -> Vec<Row> {
        self.selected_installation()
            .map_or_else(Vec::new, |installation| {
                repositories::visible(&Row::of(installation, &self.observations), &self.filter)
            })
    }

    /// Advance every clock the interface shows.
    ///
    /// A countdown that only moves when a key is pressed is a countdown that
    /// lies, so the loop ticks whether or not anything happened.
    pub fn tick(&mut self, elapsed: std::time::Duration) {
        self.sign_in.state_mut().tick(elapsed);
        if let Some(Validity::Until(remaining)) = &mut self.grant {
            *remaining = remaining.saturating_sub(elapsed);
            if remaining.is_zero() {
                self.lapse();
            }
        }
    }

    /// The grant lapsed. Hold the position; discard what was observed under it.
    ///
    /// The two halves are deliberately asymmetric, and the asymmetry is the
    /// whole point. Everything that says where the operator is survives;
    /// everything that says what airlock saw does not, because an observation
    /// made under a grant that has since lapsed is not evidence of the present
    /// state, and this is exactly the moment that rule would be tempting to
    /// break.
    ///
    /// Nothing is refreshed here. The lapsed credential is discarded by the run
    /// loop when it takes the request below, and what follows is a device
    /// approval — the same and only way a credential ever comes to exist.
    pub fn lapse(&mut self) {
        if self.reauthorization.is_some() {
            return;
        }
        let position = Position::of(self);
        self.authorized = false;
        self.grant = None;
        // Observations, every one of them.
        self.catalogue = catalogue::State::Unauthorized;
        self.observations = Observations::default();
        self.queue = None;
        self.inspector = None;
        self.remediation = remediation::State::Empty;
        self.reobserve = None;
        self.note = None;
        // Requests made under the lapsed grant, which nothing may now carry
        // out: a write authorized by a credential that no longer exists is not
        // a write this session consented to.
        self.pending_observation = None;
        self.pending_remediation = None;
        self.pending_preparation = None;
        self.pending_undo = None;
        self.requested = None;
        self.sign_in = sign_in::Screen::at(SignIn::Requesting {
            reason: Reason::Lapsed,
        });
        self.reauthorization = Some(position);
        self.reauthorization_requested = true;
    }

    /// Take the request to discard the credential and re-authorize, once.
    pub fn take_reauthorization_request(&mut self) -> bool {
        std::mem::take(&mut self.reauthorization_requested)
    }

    /// Whether the re-authorization overlay is up.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn reauthorizing_now(&self) -> bool {
        self.reauthorization.is_some()
    }

    /// What is left of the grant, as the header states it.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn grant(&self) -> Option<Validity> {
        self.grant
    }

    /// Apply what the device flow reported.
    ///
    /// [`Progress`] has no arm that carries a credential, and this signature
    /// names no type that could. The grant travels in the worker's own report,
    /// which the run loop takes apart before anything reaches here — so a
    /// credential is not something this type declines to draw, it is something
    /// it is never given.
    pub fn report(&mut self, progress: Progress) {
        let state = self.sign_in.state_mut();
        match progress {
            Progress::CodeIssued(issued) => state.code_issued(&issued),
            // A poll that got through after a transport failure is what says
            // the interruption is over, so it is the same report that resumes
            // the screen. The code and its remaining validity are the ones it
            // was holding: approval already given is not wasted.
            Progress::Pending(interval) => {
                if matches!(state, crate::admin::sign_in::SignIn::Interrupted { .. }) {
                    state.resumed(interval);
                } else {
                    state.polled();
                }
            }
            Progress::SlowDown(suggested) => state.slow_down(suggested),
            // Expiry and denial are displayed, not skipped past. The worker is
            // already asking for a replacement, and the screen says so; the
            // next report is the replacement arriving, which is what returns
            // the screen to awaiting approval. The session is not restarted and
            // no other screen's position is touched, because none of it lives
            // on this screen.
            Progress::Expired => state.expired(),
            Progress::Denied => state.denied(),
            Progress::Interrupted(cause) => state.interrupted(cause),
        }
    }

    /// The operator approved, and the run loop has taken the credential.
    ///
    /// A notification rather than a value. The interface is told that an
    /// authorization exists; it is never told what it is.
    pub fn authorization_granted(&mut self, grant: Validity) {
        self.authorized = true;
        self.grant = Some(grant);
        // The read is in flight from here. Said as its own state rather than as
        // an empty list, because an answer that has not arrived and an answer of
        // "nothing" are two different things to put on a screen.
        self.catalogue = catalogue::State::Reading;
        match self.reauthorization.take() {
            Some(position) => self.restore(position),
            None => self.screen = Screen::Organizations,
        }
    }

    /// Put the operator back where they were, with nothing they had been shown.
    ///
    /// Every address is restored and every reading is asked for again. The
    /// screens draw their own "nothing observed yet" until the answers arrive,
    /// which is the honest reading of the moment: the position exists, and what
    /// stands at it has not been established under this authorization yet.
    fn restore(&mut self, position: Position) {
        self.screen = position.screen;
        self.filter = position.filter;
        self.held_selection = Some((position.installation, position.repository));
        self.requested = position.target.clone();
        if let Some(target) = position.target {
            self.pending_observation = Some(target);
        }
        self.held_queue = Some(HeldQueue {
            findings: position.findings,
            detail: position.detail,
            inspection: position.inspection,
        });
    }

    /// Apply what the catalogue worker reported.
    ///
    /// Like [`App::report`], this names no type that could carry a credential:
    /// the worker owns the only client, and what crosses the channel is a read
    /// model whose every server-supplied string was sanitized on the way out.
    pub fn catalogue_read(&mut self, read: catalogue::Read) {
        // The credential was rejected rather than the question refused, so
        // this is the grant having lapsed, observed.
        if matches!(read, catalogue::Read::Unauthorized) {
            self.lapse();
            return;
        }
        // A catalogue read that was in flight across the boundary, on the same
        // terms as a run: what it holds was reached with a credential this
        // session no longer has.
        if self.reauthorizing_now() {
            return;
        }
        self.catalogue = match read {
            catalogue::Read::Ready(catalogue) => catalogue::State::Ready(catalogue),
            catalogue::Read::Failed(cause) => catalogue::State::Failed(cause),
            catalogue::Read::Unauthorized => unreachable!("taken above"),
            // A read the session's end abandoned. It is never sent, and if it
            // ever were, the screen it would land on belongs to a session that
            // no longer exists.
            catalogue::Read::Cancelled => return,
        };
        self.installation = 0;
        self.repository = 0;
        match self.held_selection.take() {
            // Found again by name in the list as it now reads. An index kept
            // across a re-read would point at whatever moved into that slot.
            Some((installation, repository)) => {
                if let Some(account) = installation {
                    if let Some(index) = self
                        .catalogue
                        .installations()
                        .iter()
                        .position(|candidate| candidate.account == account)
                    {
                        self.installation = index;
                    }
                }
                if let Some(name) = repository {
                    if let Some(index) = self
                        .visible_rows()
                        .iter()
                        .position(|row| row.repository.name == name)
                    {
                        self.repository = index;
                    }
                }
            }
            None => self.filter.close(),
        }
    }

    /// Whether the session holds an authorization.
    ///
    /// A boolean, deliberately: the interface is told that a credential exists,
    /// never what it is.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn authorized(&self) -> bool {
        self.authorized
    }

    /// Draw the whole interface.
    pub fn render(&self, area: Rect, buffer: &mut ratatui::buffer::Buffer) {
        let styles = self.styles();
        if styles.colored() {
            Paragraph::new("")
                .style(styles.canvas())
                .render(area, buffer);
        }
        if !chrome::fits(area) {
            self.render_undersized(area, buffer);
            return;
        }
        let frame = chrome::layout(area);
        let keys = self.keymap();
        Paragraph::new(chrome::header_line(
            self.screen,
            &self.version,
            styles,
            area.width,
            &keys,
            self.grant,
        ))
        .render(frame.header, buffer);
        for rule in [frame.rule_top, frame.rule_bottom].into_iter().flatten() {
            Paragraph::new(chrome::rule_line(styles, area.width)).render(rule, buffer);
        }
        Paragraph::new(chrome::keymap_line(&keys, styles, area.width)).render(frame.keymap, buffer);
        Paragraph::new(chrome::status_line(&self.status(), styles, area.width))
            .render(frame.status, buffer);
        // The body is wrapped here rather than by the paragraph, so a
        // continuation line lands under the text it continues instead of under
        // the label, and so a column that carries meaning cannot be reflowed
        // out of position.
        let body = self.withhold(
            self.body(frame.body.width, frame.body.height),
            frame.body.height,
        );
        Paragraph::new(body).render(frame.body, buffer);
    }

    /// Cut the body to the rows available, saying so on the last of them.
    ///
    /// Content that runs past the bottom is withheld rather than clipped: a
    /// reader who cannot see that a region continues will read what is on
    /// screen as the whole of it. The note is not a scroll indicator — this
    /// frame does not scroll — it is the statement that something is missing.
    fn withhold(&self, mut lines: Vec<Line<'static>>, height: u16) -> Vec<Line<'static>> {
        let height = height as usize;
        if lines.len() <= height || height == 0 {
            return lines;
        }
        let withheld = lines.len() - (height - 1);
        lines.truncate(height - 1);
        lines.push(Line::from(Span::styled(
            format!(
                "\u{2014} {withheld} more lines withheld: this screen needs {} rows and has {height} \u{2014}",
                withheld + height - 1
            ),
            self.styles().of(Role::Faint).add_modifier(Modifier::ITALIC),
        )));
        lines
    }

    fn render_undersized(&self, area: Rect, buffer: &mut ratatui::buffer::Buffer) {
        let styles = self.styles();
        let lines: Vec<Line<'static>> = chrome::undersized_message(area)
            .into_iter()
            .enumerate()
            .map(|(index, text)| {
                let style = if index == 0 {
                    styles.bold(Role::Accent)
                } else {
                    styles.of(Role::Text)
                };
                Line::from(Span::styled(text, style))
            })
            .collect();
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .render(area, buffer);
    }

    /// The body of the open screen.
    ///
    /// Every screen here is a stub, and each one says so in the terms the
    /// emptiness rule requires: what would have populated the region, why it is
    /// empty, and what can be done next. Only the findings screen draws
    /// anything more, because the status vocabulary is the one thing this task
    /// does own.
    /// The keys live in the state that is open.
    ///
    /// While the filter has focus the footer shows the filter's own keys and
    /// stops advertising `t theme`, because the filter has captured it: every
    /// printable key there is typing. `ctrl-c` is in both readings, because it
    /// is live without exception.
    fn keymap(&self) -> Vec<Key> {
        if self.reauthorization.is_some() {
            return REAUTHORIZATION_KEYS.to_vec();
        }
        if self.screen == Screen::Repositories && self.filter.is_open() {
            return INPUT_KEYS.to_vec();
        }
        if self.screen == Screen::Remediation && self.remediation.captures_text() {
            return INPUT_KEYS.to_vec();
        }
        chrome::keys_of(self.screen)
    }

    /// The status line for the open screen.
    ///
    /// Two screens now know something the shell did not, and they say it. The
    /// rest still state that nothing has been observed, which remains true.
    fn status(&self) -> String {
        if let Some(position) = &self.reauthorization {
            // The facts after the first are what is being held. The body says
            // so in the word; this line has the columns for the position or
            // for the word, and the position is the fact.
            return format!("re-authorizing \u{b7} {}", position.holding(Density::Tight));
        }
        if let Some(note) = &self.note {
            return note.clone();
        }
        match self.screen {
            Screen::Organizations => organizations::status(&self.catalogue),
            Screen::Repositories => repositories::status(self.visible_rows().len(), self.reach()),
            Screen::Findings => self
                .queue
                .as_deref()
                .map_or_else(|| chrome::status_text(Screen::Findings), findings::status),
            Screen::FindingDetail => self.focused_row().map_or_else(
                || chrome::status_text(Screen::FindingDetail),
                detail::status,
            ),
            Screen::PolicyInspector => self.inspector.as_deref().map_or_else(
                || chrome::status_text(Screen::PolicyInspector),
                policy::status,
            ),
            Screen::Remediation => self.remediation.status().to_owned(),
            other => chrome::status_text(other),
        }
    }

    fn body(&self, width: u16, height: u16) -> Vec<Line<'static>> {
        let styles = self.styles();
        if let Some(position) = &self.reauthorization {
            return self.reauthorization_body(styles, width, height, position);
        }
        if self.screen == Screen::SignIn {
            return self.sign_in.body(styles, width, height);
        }
        if self.screen == Screen::Organizations {
            return organizations::body(styles, width, height, &self.catalogue, self.installation);
        }
        if self.screen == Screen::Repositories {
            let installation = self.selected_installation();
            return repositories::body(
                styles,
                width,
                height,
                &repositories::View {
                    installation,
                    catalogue: self.catalogue.catalogue(),
                    rows: &self.visible_rows(),
                    reach: self.reach(),
                    filter: &self.filter,
                    selected: self.repository,
                },
            );
        }
        if self.screen == Screen::Findings {
            if let Some(queue) = self.queue.as_deref() {
                return findings::body(styles, width, height, queue, &self.findings);
            }
        }
        if self.screen == Screen::FindingDetail {
            if let (Some(queue), Some(row)) = (self.queue.as_deref(), self.focused_row()) {
                return detail::body(styles, width, height, row, &queue.provenance, &self.detail);
            }
            return detail::nothing_selected(styles, width as usize);
        }
        if self.screen == Screen::PolicyInspector {
            return self.inspector.as_deref().map_or_else(
                || policy::nothing_observed(styles, width as usize),
                |inspector| policy::body(styles, width, height, inspector, &self.inspection),
            );
        }
        if self.screen == Screen::Remediation {
            return remediation::body(styles, width as usize, &self.remediation);
        }
        let width = width as usize;
        let mut lines = vec![Line::from(Span::styled(
            self.screen.label().to_uppercase(),
            styles.bold(Role::Accent),
        ))];
        for line in wrap(self.screen.purpose(), width) {
            lines.push(Line::from(Span::styled(line, styles.of(Role::Text))));
        }
        lines.push(Line::default());
        // The vocabulary comes first because it is content this build actually
        // has. The emptiness statement describes what is absent, and a reading
        // of what is absent is worth less than a reading of what is present
        // when the two compete for the same rows.
        if self.screen == Screen::Findings {
            lines.extend(self.vocabulary(width));
            lines.push(Line::default());
        }
        lines.extend(self.emptiness(width));
        lines
    }

    /// The device flow, drawn over the screen the operator was on.
    ///
    /// Sign-in's own body: the five states, the code frame, the scan code, and
    /// the standing statement that nothing is stored are one rendering of the
    /// flow, and a second one here would be a second thing to keep true.
    ///
    /// What is being held is added under it where there are rows for all of it.
    /// The status line carries the same reading on every screen and at every
    /// size, so the fact is never the thing that was withheld: what the rows
    /// decide is whether it is said twice.
    fn reauthorization_body(
        &self,
        styles: Styles,
        width: u16,
        height: u16,
        position: &Position,
    ) -> Vec<Line<'static>> {
        let mut lines = self.sign_in.body(styles, width, height);
        let width = width as usize;
        let held = |density| panel::field(styles, "holding", &position.holding(density), width);
        let discarded = panel::field(
            styles,
            "discarded",
            "every observation this session made. Each row is observed again \
             once the authorization returns, because a reading taken under a \
             grant that has lapsed is not evidence of the present state.",
            width,
        );
        // The fullest reading the rows will carry, in order. Each rung says
        // less than the one above it and none of them says something else: the
        // position is stated at every size, and what a short terminal costs is
        // the words around it rather than the fact.
        let mut blank = vec![Line::default()];
        blank.extend(held(Density::Full));
        let mut with_discarded = blank.clone();
        with_discarded.extend(discarded);
        let mut tight = vec![Line::default()];
        tight.extend(held(Density::Tight));
        let ladder = [with_discarded, blank, tight, held(Density::Tight)];
        let room = (height as usize).saturating_sub(lines.len());
        let block = ladder
            .into_iter()
            .find(|candidate| candidate.len() <= room)
            .unwrap_or_default();
        lines.extend(block);
        lines
    }

    fn emptiness(&self, width: usize) -> Vec<Line<'static>> {
        let styles = self.styles();
        let mut lines = vec![Line::from(Span::styled(
            "NOTHING OBSERVED YET",
            styles.bold(Role::Text),
        ))];
        for (label, text) in [
            ("would show", self.screen_content()),
            (
                "empty because",
                "this build is the interface shell. It draws the frame, the \
                 status vocabulary, and the navigation between screens. No \
                 authorization is requested and no repository is observed, so \
                 there is nothing for this region to hold.",
            ),
            (
                "next",
                "navigate with \u{21b5} and esc to read the frame on every \
                 screen, press t to compare the palettes, and ctrl-c to leave.",
            ),
        ] {
            let room = width.saturating_sub(FIELD_LABEL_WIDTH).max(1);
            for (index, part) in wrap(text, room).into_iter().enumerate() {
                let label = if index == 0 { label } else { "" };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{label:<FIELD_LABEL_WIDTH$}"),
                        styles.of(Role::Faint),
                    ),
                    Span::styled(part, styles.of(Role::Dim)),
                ]));
            }
        }
        lines
    }

    fn screen_content(&self) -> &'static str {
        match self.screen {
            Screen::SignIn => {
                "the device code, the address to enter it at, and the scan code \
                 where width allows"
            }
            Screen::Organizations => {
                "the reachable installations, each with its kind and its \
                 repository count"
            }
            Screen::Repositories => {
                "a filter over the repository name, and a table of name, \
                 visibility, last audit, verdict, and default branch"
            }
            Screen::Findings => {
                "the verdict, the status summary, and the eight groups of the \
                 work queue"
            }
            Screen::FindingDetail => {
                "one finding's evidence, error, suppression, remediation, and \
                 effect on the run"
            }
            Screen::Remediation => {
                "the proposed change, the transcript of carrying it out, and \
                 the re-observation that follows it"
            }
            Screen::PolicyInspector => {
                "every rule the run asked about, the registry digest, and where \
                 each rule came from"
            }
            Screen::PublishingBootstrap => {
                "the five steps, the one the observation places you at, and any \
                 outstanding credential"
            }
        }
    }

    /// The status vocabulary, drawn from the one primitive.
    fn vocabulary(&self, width: usize) -> Vec<Line<'static>> {
        let styles = self.styles();
        let mut lines = vec![Line::from(Span::styled(
            "STATUS VOCABULARY",
            styles.bold(Role::Text),
        ))];
        let narrow = width < chrome::REFERENCE_WIDTH as usize;
        for lane in Lane::ALL {
            lines.push(Line::from(vec![
                Span::styled(lane.heading(), styles.bold(Role::Dim)),
                Span::styled(
                    if narrow {
                        String::new()
                    } else {
                        format!("  {}", lane.qualifier())
                    },
                    styles.of(Role::Faint),
                ),
            ]));
            for status in Status::ALL.iter().filter(|s| lane::lane_of(**s) == lane) {
                // A legend that wraps stops being a legend, so the gloss is
                // elided to the room the lanes and the status name leave.
                lines.push(lane::legend_row(*status, styles, width));
            }
        }
        lines.push(Line::default());
        let mut severities = vec![
            Span::styled("SEVERITY", styles.bold(Role::Dim)),
            Span::raw("  "),
        ];
        for (index, severity) in Severity::ALL.iter().enumerate() {
            if index > 0 {
                severities.push(Span::styled("   ", styles.of(Role::Faint)));
            }
            severities.extend(lane::severity_spans(*severity, styles));
        }
        lines.push(Line::from(severities));
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", lane::GATING_RAIL),
                styles.of(Role::Status(Status::Fail)),
            ),
            Span::styled(
                "a solid left rail marks a row that actually gates the run",
                styles.of(Role::Faint).add_modifier(Modifier::ITALIC),
            ),
        ]));
        lines
    }
}

/// Whether a run reports GitHub rejecting the credential it was made with.
///
/// 401 and nothing else: it is the one status that is unambiguously about the
/// credential rather than about the question, which is why the audit's own
/// classification treats it the same way. A 403 is a grant that is too narrow
/// and re-authorizing would not widen it.
fn rejected(report: &airlock_core::findings::Report) -> bool {
    report.findings.iter().any(|finding| {
        finding
            .error
            .as_ref()
            .is_some_and(|error| error.status == Some(401))
    })
}

fn bulk_kind(code: &str) -> Option<crate::admin::remediation::BulkKind> {
    crate::admin::remediation::Action::for_code(code).map(|action| action.bulk_kind())
}

fn bulk_items(
    queue: &findings::Queue,
    kind: crate::admin::remediation::BulkKind,
) -> Vec<remediation::Item> {
    queue
        .rows
        .iter()
        .filter(|row| row.group == findings::Group::Settings && row.status == Status::Fail)
        .filter_map(|row| {
            let code = row.remediation.clone()?;
            if bulk_kind(&code) != Some(kind) {
                return None;
            }
            crate::admin::remediation::Action::for_code(&code)?;
            Some(remediation::Item {
                rule: row.rule.clone(),
                remediation: code,
                change: row.change.clone()?,
                reversible: row.reversible?,
                input: remediation::Input::None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new("0.0.0", ColorMode::Color)
    }

    fn press(app: &mut App, code: KeyCode) -> Flow {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn selected_remediation_rule(app: &App) -> &str {
        let request = match &app.remediation {
            remediation::State::Input { request }
            | remediation::State::Confirm { request }
            | remediation::State::Applying { request }
            | remediation::State::Complete { request, .. } => request,
            remediation::State::Empty => panic!("the remediation was not populated"),
        };
        &request.items[0].rule
    }

    /// The grant a test session is authorized with.
    ///
    /// Eight hours, which is what GitHub states for a user access token with
    /// expiry enabled. A shape, not a fixture: what is asserted is that the
    /// interface counts down what it was given.
    fn granted() -> Validity {
        Validity::Until(std::time::Duration::from_secs(28_800))
    }

    fn issued() -> crate::admin::flow::Issued {
        crate::admin::flow::Issued {
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://github.com/login/device".to_owned(),
            expires_in: std::time::Duration::from_secs(900),
            interval: std::time::Duration::from_secs(5),
        }
    }

    #[test]
    fn the_interface_opens_on_sign_in_in_the_dark_palette() {
        let app = app();
        assert_eq!(app.screen(), Screen::SignIn);
        assert_eq!(app.theme(), Theme::Dark);
    }

    #[test]
    fn ctrl_c_exits_from_every_screen() {
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            let flow = app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert_eq!(flow, Flow::Exit, "{screen:?}");
        }
    }

    #[test]
    fn t_switches_theme_on_every_screen_and_never_exits() {
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            assert_eq!(press(&mut app, KeyCode::Char('t')), Flow::Continue);
            assert_eq!(app.theme(), Theme::Light, "{screen:?}");
            press(&mut app, KeyCode::Char('t'));
            assert_eq!(app.theme(), Theme::Dark, "{screen:?}");
            assert_eq!(app.screen(), screen, "theme is not navigation");
        }
    }

    #[test]
    fn enter_and_esc_walk_the_chain_and_stop_at_its_ends() {
        // The walk starts from an authorization and a catalogue, because that
        // is what the chain is made of now: the screen after sign-in is opened
        // by a grant arriving, and the two selection screens open what they
        // have selected rather than an empty screen about nothing.
        let mut app = app().with_catalogue(catalogue());
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        assert_eq!(app.screen(), Screen::Organizations);
        for expected in [
            Screen::Repositories,
            Screen::Findings,
            Screen::FindingDetail,
        ] {
            press(&mut app, KeyCode::Enter);
            assert_eq!(app.screen(), expected);
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail, "the chain ends here");
        for expected in [
            Screen::Findings,
            Screen::Repositories,
            Screen::Organizations,
            Screen::SignIn,
        ] {
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), expected);
        }
        press(&mut app, KeyCode::Esc);
        assert_eq!(
            app.screen(),
            Screen::SignIn,
            "sign-in has nothing behind it"
        );
    }

    #[test]
    fn the_screens_hung_off_findings_are_reachable_and_return_to_it() {
        for (code, expected) in [
            (KeyCode::Char('p'), Screen::PolicyInspector),
            (KeyCode::Char('b'), Screen::PublishingBootstrap),
        ] {
            let mut app = app().at(Screen::Findings, Theme::Dark);
            press(&mut app, code);
            assert_eq!(app.screen(), expected);
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), Screen::Findings);
        }
    }

    #[test]
    fn apply_is_inert_where_the_specification_says_it_is() {
        // `a` is a property of the focused finding rather than of the screen,
        // on both screens that offer it: the transcript exists to carry out a
        // settings-level change, and without one there is nothing to open.
        for screen in Screen::ALL {
            let mut app = app().at(screen, Theme::Dark);
            press(&mut app, KeyCode::Char('a'));
            assert_eq!(app.screen(), screen, "{screen:?}");
        }
    }

    #[test]
    fn apply_opens_the_transcript_only_for_a_settings_level_change() {
        // The queue's first row is the settings failure, and the group it
        // stands in is the one the interface may act in.
        let mut app = app();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::Remediation);
        assert_eq!(selected_remediation_rule(&app), "REPO-GIT-01");
    }

    #[test]
    fn a_capability_decision_is_not_offered_for_a_user_account() {
        use airlock_core::github::{AccountKind, RepositorySelection};
        let mut app = observed().with_catalogue(catalogue::Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::UserAccount,
            RepositorySelection::All,
            &["widget"],
        )]));
        focus(&mut app, findings::Group::Decision);
        press(&mut app, KeyCode::Char('a'));

        assert_eq!(app.screen(), Screen::Findings);
        assert!(
            app.status()
                .contains("require an organization-owned repository"),
            "{}",
            app.status()
        );
    }

    #[test]
    fn a_capability_write_uses_raw_policy_data_not_its_drawable_copy() {
        let mut finding = findings::fixture::capability_undeclared();
        let capability = finding
            .evidence
            .as_mut()
            .and_then(|evidence| evidence.capability.as_mut())
            .expect("the fixture carries a declaration");
        capability.value = "tr\u{1b}ue".to_owned();
        let report =
            findings::fixture::report(airlock_core::findings::Gate::Required, vec![finding]);
        let mut app = app().with_catalogue(catalogue());
        app.observed_run(&report, &findings::Deliveries::default());
        app.screen = Screen::Findings;
        focus(&mut app, findings::Group::Decision);
        press(&mut app, KeyCode::Char('a'));

        let request = match &app.remediation {
            remediation::State::Confirm { request } => request,
            state => panic!("expected confirmation, got {state:?}"),
        };
        let remediation::Input::Fixed { argument, display } = &request.items[0].input else {
            panic!("capability decisions carry fixed input")
        };
        assert_eq!(argument, "release\ntr\u{1b}ue");
        assert!(!display.contains('\u{1b}'));
    }

    #[test]
    fn a_long_input_remediation_code_opens_its_text_input() {
        let mut finding =
            findings::fixture::finding("REPO-NAME-02", Severity::Blocking, Status::Fail);
        finding.remediation = Some(airlock_core::findings::Remediation::new(
            airlock_core::remediation::ActionGroup::RENAME_REPOSITORY,
            "Rename the repository.",
        ));
        let report =
            findings::fixture::report(airlock_core::findings::Gate::Required, vec![finding]);
        let mut app = app();
        app.observed_run(&report, &findings::Deliveries::default());
        app.screen = Screen::Findings;

        focus(&mut app, findings::Group::Settings);
        press(&mut app, KeyCode::Char('a'));

        let remediation::State::Input { request } = &app.remediation else {
            panic!("the long remediation code must demand input");
        };
        assert_eq!(request.items[0].remediation, "rename-repository-undotted");
        assert!(matches!(
            request.items[0].input,
            remediation::Input::Text { .. }
        ));
    }

    #[test]
    fn detail_apply_replaces_a_stale_confirmation_with_the_focused_rule() {
        use airlock_core::findings::Remediation;
        use airlock_core::remediation::ActionGroup;

        let mut second =
            findings::fixture::finding("REPO-GIT-04", Severity::Blocking, Status::Fail);
        second.remediation = Some(Remediation::new(
            ActionGroup::CORRECT_MERGE_SETTINGS,
            "Disable merge commits.",
        ));
        let mut app = app();
        app.observed_run(
            &findings::fixture::report(
                airlock_core::findings::Gate::Required,
                vec![findings::fixture::settings_failure(), second],
            ),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;

        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(selected_remediation_rule(&app), "REPO-GIT-01");
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
        press(&mut app, KeyCode::Char('a'));

        assert_eq!(app.screen(), Screen::Remediation);
        assert_eq!(selected_remediation_rule(&app), "REPO-GIT-04");
    }

    #[test]
    fn apply_declines_a_settings_rule_this_run_offered_no_remedy_for() {
        // The rule's declared lane is the one this interface may act in, and
        // the run produced nothing to carry out. A transcript opened here would
        // offer to apply a change nothing described.
        let mut app = app();
        app.observed_run(
            &findings::fixture::report(
                airlock_core::findings::Gate::Required,
                vec![findings::fixture::settings_failure_without_a_remedy()],
            ),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::FindingDetail, "nothing was opened");
        assert!(app.status().contains("airlock closes"), "{}", app.status());
    }

    #[test]
    fn apply_says_why_it_did_nothing_on_a_file_level_gap() {
        let mut app = app();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        // Past group one's heading and row, onto group two's row: a file-level
        // gap, which leaves as a pull request and is never applied from here.
        for _ in 0..3 {
            press(&mut app, KeyCode::Down);
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::FindingDetail, "nothing was opened");
        assert!(app.status().contains("airlock closes"), "{}", app.status());
    }

    #[test]
    fn re_observing_records_the_request_and_claims_no_result() {
        let mut app = app();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.reobserve_requested(), Some("REPO-GIT-01"));
        assert!(app.status().contains("requested"), "{}", app.status());
        assert_eq!(
            app.screen(),
            Screen::FindingDetail,
            "that is not navigation"
        );
    }

    #[test]
    fn copying_a_rule_id_asks_the_terminal_and_says_only_that() {
        let mut app = app();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            press(&mut app, KeyCode::Char('y')),
            Flow::Copy("REPO-GIT-01".to_owned())
        );
        assert!(app.status().contains("clipboard"), "{}", app.status());
    }

    #[test]
    fn a_key_that_acts_on_a_finding_says_so_when_there_is_none() {
        for code in [KeyCode::Char('o'), KeyCode::Char('y')] {
            let mut app = app().at(Screen::FindingDetail, Theme::Dark);
            press(&mut app, code);
            assert!(
                app.status().contains("no finding is open"),
                "{:?}: {}",
                code,
                app.status()
            );
        }
    }

    #[test]
    fn a_finding_is_always_read_from_the_top() {
        let mut app = app();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::Deliveries::default(),
        );
        app.screen = Screen::Findings;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        // Draw once so the state knows how long the reading is, then move.
        let _ = app.body(chrome::FLOOR_WIDTH, chrome::FLOOR_HEIGHT - 3);
        for _ in 0..5 {
            press(&mut app, KeyCode::Down);
        }
        assert!(app.detail.offset() > 0);
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.detail.offset(),
            0,
            "a different finding starts at its top"
        );
    }

    #[test]
    fn an_authorization_is_a_notification_rather_than_a_value() {
        // There is no call to write here that hands this type a grant, because
        // neither `report` nor `authorization_granted` names a type that could
        // carry one. That absence is the assertion; what follows is only that
        // the notification does what it says.
        let mut app = app();
        assert!(!app.authorized());
        app.authorization_granted(granted());
        assert!(app.authorized(), "the session holds an authorization");
        assert_eq!(app.screen(), Screen::Organizations);
    }

    #[test]
    fn the_five_states_are_reached_by_what_github_answers() {
        use crate::admin::sign_in::SignIn;
        let mut app = app();
        assert!(matches!(app.sign_in.state(), SignIn::Requesting { .. }));
        app.report(Progress::CodeIssued(Box::new(issued())));
        assert!(matches!(app.sign_in.state(), SignIn::Awaiting { .. }));
        app.report(Progress::Interrupted("connection reset".to_owned()));
        assert!(matches!(app.sign_in.state(), SignIn::Interrupted { .. }));
        // The next poll that gets through is what says the interruption is
        // over, and it keeps the code that was already on screen.
        app.report(Progress::Pending(std::time::Duration::from_secs(5)));
        assert!(matches!(app.sign_in.state(), SignIn::Awaiting { .. }));
        app.report(Progress::Expired);
        assert_eq!(app.sign_in.state(), &SignIn::Expired);
        app.report(Progress::Denied);
        assert_eq!(app.sign_in.state(), &SignIn::Denied);
        assert_eq!(app.screen(), Screen::SignIn, "none of that is navigation");
    }

    #[test]
    fn r_asks_for_a_new_code_only_once_there_is_one_to_replace() {
        let mut app = app();
        assert_eq!(press(&mut app, KeyCode::Char('r')), Flow::Continue);
        app.report(Progress::CodeIssued(Box::new(issued())));
        assert_eq!(press(&mut app, KeyCode::Char('r')), Flow::Reissue);
    }

    #[test]
    fn ticking_runs_the_code_validity_down() {
        use crate::admin::sign_in::SignIn;
        let mut app = app();
        app.report(Progress::CodeIssued(Box::new(issued())));
        app.tick(std::time::Duration::from_secs(60));
        let SignIn::Awaiting { remaining, .. } = app.sign_in.state() else {
            panic!("expected the awaiting state");
        };
        assert_eq!(*remaining, std::time::Duration::from_secs(840));
    }

    #[test]
    fn a_key_release_does_nothing() {
        let mut app = app();
        let mut event = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        event.kind = KeyEventKind::Release;
        assert_eq!(app.handle_key(event), Flow::Continue);
        assert_eq!(app.theme(), Theme::Dark);
    }

    #[test]
    fn every_screen_states_what_would_have_populated_it() {
        // Three screens are excluded because they are no longer empty: sign-in
        // draws the device flow, and the two selection screens draw what the
        // catalogue holds. A region that has content states its content, and
        // each of the three states its own emptiness in its own terms.
        let drawn = [Screen::SignIn, Screen::Organizations, Screen::Repositories];
        for screen in Screen::ALL.into_iter().filter(|s| !drawn.contains(s)) {
            let app = app().at(screen, Theme::Dark);
            let text: String = app
                .body(chrome::REFERENCE_WIDTH, chrome::REFERENCE_HEIGHT)
                .iter()
                .flat_map(|line| line.spans.iter())
                .map(|span| span.content.as_ref())
                .collect();
            assert!(text.contains("would show"), "{screen:?}");
            assert!(text.contains("empty because"), "{screen:?}");
            assert!(text.contains("next"), "{screen:?}");
        }
    }

    #[test]
    fn content_that_runs_past_the_bottom_is_withheld_and_says_so() {
        let app = app();
        let lines: Vec<Line<'static>> = (0..30).map(|_| Line::raw("x")).collect();
        let kept = app.withhold(lines.clone(), 10);
        assert_eq!(kept.len(), 10);
        let note: String = kept[9].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(note.contains("21 more lines withheld"), "{note}");
        assert!(note.contains("30 rows"), "{note}");
        assert_eq!(
            app.withhold(lines.clone(), 30).len(),
            30,
            "an exact fit is untouched"
        );
        assert_eq!(
            app.withhold(lines, 40).len(),
            30,
            "room to spare is untouched"
        );
    }

    // ---------------------------------------------------------------------
    // Choosing an organization, and then a repository
    // ---------------------------------------------------------------------

    fn installation(
        account: &str,
        kind: airlock_core::github::AccountKind,
        selection: airlock_core::github::RepositorySelection,
        names: &[&str],
    ) -> catalogue::Installation {
        catalogue::Installation {
            id: 7,
            account: account.to_owned(),
            kind,
            selection,
            listing: catalogue::Listing::Read {
                repositories: names
                    .iter()
                    .map(|name| catalogue::Repository {
                        owner: account.to_owned(),
                        name: (*name).to_owned(),
                        visibility: "private".to_owned(),
                        default_branch: Some("main".to_owned()),
                    })
                    .collect(),
                total: names.len() as u64,
                truncated: false,
            },
        }
    }

    /// An organization and a user account, the second scoped.
    fn catalogue() -> catalogue::Catalogue {
        use airlock_core::github::{AccountKind, RepositorySelection};
        catalogue::Catalogue::of(vec![
            installation(
                "acme-industries",
                AccountKind::Organization,
                RepositorySelection::All,
                &["widget", "sprocket"],
            ),
            installation(
                "sample-operator",
                AccountKind::UserAccount,
                RepositorySelection::Selected,
                &["notes"],
            ),
        ])
    }

    fn selected(app: &App) -> catalogue::Catalogue {
        catalogue::Catalogue::of(vec![app
            .selected_installation()
            .expect("an installation is selected")
            .clone()])
    }

    #[test]
    fn an_authorization_puts_the_catalogue_read_in_flight_rather_than_showing_an_empty_list() {
        let mut app = app();
        app.authorization_granted(granted());
        assert_eq!(app.catalogue, catalogue::State::Reading);
        assert!(
            organizations::status(&app.catalogue).contains("reading"),
            "an answer that has not arrived is not an answer of none"
        );
        app.catalogue_read(catalogue::Read::Failed("rate_limit".to_owned()));
        assert!(matches!(app.catalogue, catalogue::State::Failed(_)));
    }

    #[test]
    fn the_arrows_move_the_selection_and_stop_at_both_ends() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Organizations, Theme::Dark);
        assert_eq!(app.installation, 0);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.installation, 0, "the top of the list is the top");
        press(&mut app, KeyCode::Down);
        assert_eq!(app.installation, 1);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.installation, 1, "the end of the list is the end");
    }

    #[test]
    fn enter_opens_nothing_when_there_is_nothing_selected() {
        let mut app = app()
            .with_catalogue(catalogue::Catalogue::of(Vec::new()))
            .at(Screen::Organizations, Theme::Dark);
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.screen(),
            Screen::Organizations,
            "an empty list opens nothing rather than an empty screen about nothing"
        );
    }

    #[test]
    fn opening_an_installation_shows_the_repositories_it_reaches() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Organizations, Theme::Dark);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::Repositories);
        let rows = app.visible_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].repository.name, "notes");
    }

    #[test]
    fn the_filter_narrows_the_rows_as_it_is_typed() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        assert_eq!(app.visible_rows().len(), 2);
        press(&mut app, KeyCode::Char('/'));
        assert!(app.filter.is_open());
        for character in "spro".chars() {
            press(&mut app, KeyCode::Char(character));
        }
        assert_eq!(app.visible_rows().len(), 1);
        assert_eq!(app.visible_rows()[0].repository.name, "sprocket");
        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.filter.text(), "spr");
    }

    #[test]
    fn an_open_filter_types_the_theme_key_and_esc_closes_it_rather_than_navigating() {
        // A focused text input takes printable keys as text, `t` included, and
        // the footer stops advertising the toggle for as long as it does.
        // `ctrl-c` is untouched: it is live without exception.
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.theme(), Theme::Dark, "the key was typed, not acted on");
        assert_eq!(app.filter.text(), "t");
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Flow::Exit,
            "ctrl-c leaves from every state, including this one"
        );

        press(&mut app, KeyCode::Esc);
        assert!(!app.filter.is_open());
        assert_eq!(app.filter.text(), "", "closing the filter clears it");
        assert_eq!(app.screen(), Screen::Repositories, "esc closed the filter");
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), Screen::Organizations, "and then it goes back");
    }

    fn footer(app: &App) -> String {
        chrome::keymap_line(&app.keymap(), app.styles(), chrome::REFERENCE_WIDTH)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn the_footer_never_advertises_a_key_the_open_state_has_captured() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);

        let unfocused = footer(&app);
        assert!(unfocused.contains("t theme"), "{unfocused}");
        assert!(unfocused.contains("/ filter"), "{unfocused}");
        assert!(unfocused.contains("esc back"), "{unfocused}");
        assert!(unfocused.contains("ctrl-c exit"), "{unfocused}");

        press(&mut app, KeyCode::Char('/'));
        let focused = footer(&app);
        assert!(
            !focused.contains("t theme"),
            "the filter has taken `t`, and a footer that still offered it \
             would describe a different program: {focused}"
        );
        assert!(
            !focused.contains("esc back"),
            "esc closes the filter here rather than leaving the screen: {focused}"
        );
        assert!(focused.contains("esc close the filter"), "{focused}");
        assert!(focused.contains("backspace delete"), "{focused}");
        assert!(
            focused.contains("ctrl-c exit"),
            "ctrl-c is live without exception: {focused}"
        );

        // The toggle comes back the moment focus leaves the input.
        press(&mut app, KeyCode::Esc);
        assert_eq!(footer(&app), unfocused);

        app.screen = Screen::Remediation;
        app.remediation = remediation::State::confirm(
            "generic-owner".to_owned(),
            "sample-repository".to_owned(),
            vec![remediation::Item {
                rule: "REPO-NAME-01".to_owned(),
                remediation: "rename-repository-kebab".to_owned(),
                change: "rename".to_owned(),
                reversible: true,
                input: remediation::Input::Text {
                    draft: "sample-repository".to_owned(),
                    required_prefix: None,
                    error: None,
                },
            }],
        );
        let remediation_focused = footer(&app);
        assert!(
            !remediation_focused.contains("t theme"),
            "{remediation_focused}"
        );
        assert!(
            remediation_focused.contains("backspace delete"),
            "{remediation_focused}"
        );
    }

    fn header(app: &App) -> String {
        chrome::header_line(
            app.screen(),
            "0.0.0",
            app.styles(),
            chrome::REFERENCE_WIDTH,
            &app.keymap(),
            app.grant(),
        )
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
    }

    #[test]
    fn the_header_withdraws_the_theme_key_with_the_footer_and_holds_its_geometry() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);

        let unfocused = header(&app);
        assert!(unfocused.contains("theme t"), "{unfocused}");

        press(&mut app, KeyCode::Char('/'));
        let focused = header(&app);
        assert!(
            !focused.contains("theme t"),
            "the header advertised a key the filter had captured: {focused}"
        );
        assert!(focused.contains("theme \u{2014}"), "{focused}");
        assert!(
            !footer(&app).contains("t theme"),
            "the two surfaces disagreed about the same key"
        );

        // Nothing moved: a filter opening must repaint the header, never
        // reflow it.
        assert_eq!(unfocused.chars().count(), focused.chars().count());
        assert_eq!(unfocused.find("theme"), focused.find("theme"));

        // And the key comes back with focus leaving, on both surfaces at once.
        press(&mut app, KeyCode::Esc);
        assert_eq!(header(&app), unfocused);
        assert!(footer(&app).contains("t theme"));
    }

    #[test]
    fn esc_closes_a_focused_filter_and_only_then_leaves_the_screen() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Char('w'));
        press(&mut app, KeyCode::Esc);
        assert!(!app.filter.is_open());
        assert_eq!(app.screen(), Screen::Repositories);
        assert_eq!(
            press(&mut app, KeyCode::Char('t')),
            Flow::Continue,
            "the toggle is live again"
        );
        assert_eq!(app.theme(), Theme::Light);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), Screen::Organizations);
    }

    #[test]
    fn ctrl_c_leaves_from_a_focused_filter_too() {
        let mut app = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        press(&mut app, KeyCode::Char('/'));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Flow::Exit
        );
    }

    #[test]
    fn a_truncated_listing_reaches_the_screen_as_the_prefix_it_is() {
        use airlock_core::github::{AccountKind, RepositorySelection};
        let mut installation = installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget", "sprocket"],
        );
        installation.listing = catalogue::Listing::Read {
            repositories: installation.listing.repositories().to_vec(),
            total: 400,
            truncated: true,
        };
        let app = app()
            .with_catalogue(catalogue::Catalogue::of(vec![installation]))
            .at(Screen::Repositories, Theme::Dark);

        assert_eq!(app.reach().total, 400);
        assert!(app.reach().truncated);
        let status = app.status();
        assert!(status.contains("2 of 400 shown"), "{status}");
        assert!(status.contains("a prefix"), "{status}");
        let text = body_text(&app);
        assert!(text.contains("2 of 400 read"), "{text}");

        // And the organizations row, which is where the operator decides
        // whether the screen behind it is the whole installation.
        let organizations = app.at(Screen::Organizations, Theme::Dark);
        let text = body_text(&organizations);
        assert!(text.contains("400 repositories, 2 read"), "{text}");
    }

    #[test]
    fn opening_a_repository_asks_for_a_full_observation_whatever_is_remembered() {
        // The contract in the interface's own terms: a repository this session
        // observed and found conformant produces exactly the request an
        // unobserved one does. Nothing is acted upon from memory.
        let coordinates = Observe {
            owner: "acme-industries".to_owned(),
            name: "widget".to_owned(),
        };

        let mut fresh = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        press(&mut fresh, KeyCode::Enter);
        assert_eq!(fresh.requested(), Some(&coordinates));
        assert_eq!(fresh.screen(), Screen::Findings);

        let mut remembered = app()
            .with_catalogue(catalogue())
            .at(Screen::Repositories, Theme::Dark);
        remembered.observed(&coordinates, "2026-01-02", "conformant");
        assert_eq!(
            remembered.visible_rows()[0].prior.verdict(),
            "conformant",
            "the row does display what the session remembers"
        );
        press(&mut remembered, KeyCode::Enter);
        assert_eq!(
            remembered.requested(),
            fresh.requested(),
            "a remembered verdict changed what airlock asked for"
        );
    }

    #[test]
    fn a_repository_scoped_out_of_an_installation_is_told_apart_from_an_absent_one() {
        use airlock_core::github::{AccountKind, RepositorySelection};
        let scoped = catalogue::Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::Selected,
            &["widget"],
        )]);
        let mut scoped = app()
            .with_catalogue(scoped)
            .at(Screen::Repositories, Theme::Dark);
        press(&mut scoped, KeyCode::Char('/'));
        for character in "sprocket".chars() {
            press(&mut scoped, KeyCode::Char(character));
        }
        let text = body_text(&scoped);
        assert!(
            text.contains("installation scope rather than absence"),
            "{text}"
        );
        assert!(text.contains("repository selection"), "{text}");

        let everything = catalogue::Catalogue::of(vec![installation(
            "acme-industries",
            AccountKind::Organization,
            RepositorySelection::All,
            &["widget"],
        )]);
        let mut everything = app()
            .with_catalogue(everything)
            .at(Screen::Repositories, Theme::Dark);
        press(&mut everything, KeyCode::Char('/'));
        for character in "sprocket".chars() {
            press(&mut everything, KeyCode::Char(character));
        }
        let text = body_text(&everything);
        assert!(text.contains("absent rather than out of scope"), "{text}");
    }

    #[test]
    fn the_status_line_says_what_each_selection_screen_knows() {
        let app = app()
            .with_catalogue(catalogue())
            .at(Screen::Organizations, Theme::Dark);
        assert!(app.status().contains("2 installations"), "{}", app.status());
        assert!(app.status().contains("intersection"), "{}", app.status());
        let app = app.at(Screen::Repositories, Theme::Dark);
        assert!(app.status().contains("2 of 2 shown"), "{}", app.status());
        assert!(
            app.status().contains("orientation only"),
            "{}",
            app.status()
        );
    }

    #[test]
    fn the_catalogue_is_what_the_organizations_screen_draws() {
        let app = app()
            .with_catalogue(catalogue())
            .at(Screen::Organizations, Theme::Dark);
        let text = body_text(&app);
        assert!(text.contains("acme-industries"), "{text}");
        assert!(text.contains("organization"), "{text}");
        assert!(text.contains("user account"), "{text}");
        assert!(text.contains("2 repositories"), "{text}");
        assert!(text.contains("THREE CAUSES"), "{text}");
        // The selected installation is the one the repositories screen is
        // about, and the catalogue it draws from is the same one.
        assert_eq!(selected(&app).installations().len(), 1);
    }

    // ---------------------------------------------------------------------
    // The work queue
    // ---------------------------------------------------------------------

    fn observed() -> App {
        let mut app = app().at(Screen::Findings, Theme::Dark);
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::fixture::deliveries(),
        );
        app
    }

    /// Move the focus onto the first row of a group.
    fn focus(app: &mut App, group: findings::Group) {
        let queue = app.queue.as_deref().expect("a run is on screen");
        let entries = findings::entries(queue, &app.findings);
        let index = entries
            .iter()
            .position(|entry| match entry {
                findings::Entry::Row(index) => queue.rows[*index].group == group,
                findings::Entry::Heading(_) => false,
            })
            .expect("the group holds a row");
        for _ in 0..index {
            press(app, KeyCode::Down);
        }
    }

    #[test]
    fn a_run_reaches_the_screen_as_the_queue_and_replaces_the_emptiness() {
        let app = observed();
        let text = body_text(&app);
        assert!(text.contains("VERDICT"), "{text}");
        assert!(!text.contains("NOTHING OBSERVED YET"), "{text}");
        for group in findings::Group::ALL.iter().take(2) {
            assert!(text.contains(group.heading()), "{group:?}");
        }
    }

    #[test]
    fn the_queue_moves_on_the_arrows_and_on_j_and_k() {
        let mut app = observed();
        assert_eq!(app.findings.selected(), 0);
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.findings.selected(), 1);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.findings.selected(), 2);
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.findings.selected(), 1);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.findings.selected(),
            0,
            "the top of the queue is the top"
        );
    }

    #[test]
    fn space_collapses_the_focused_group_and_no_count_moves() {
        let mut app = observed();
        let before = app
            .queue
            .as_deref()
            .expect("a run")
            .count(findings::Group::Settings);
        press(&mut app, KeyCode::Char(' '));
        assert!(app.findings.is_collapsed(findings::Group::Settings));
        assert_eq!(
            app.queue
                .as_deref()
                .expect("a run")
                .count(findings::Group::Settings),
            before,
            "collapsing is screen space, never a count"
        );
        press(&mut app, KeyCode::Char(' '));
        assert!(!app.findings.is_collapsed(findings::Group::Settings));
    }

    #[test]
    fn collapsing_from_inside_a_group_leaves_the_focus_on_its_heading() {
        let mut app = observed();
        focus(&mut app, findings::Group::AgentWork);
        press(&mut app, KeyCode::Char(' '));
        assert!(app.findings.is_collapsed(findings::Group::AgentWork));
        let queue = app.queue.as_deref().expect("a run");
        let entries = findings::entries(queue, &app.findings);
        assert_eq!(
            entries[app.findings.selected()],
            findings::Entry::Heading(findings::Group::AgentWork)
        );
    }

    #[test]
    fn apply_acts_only_on_a_settings_row_and_says_why_everywhere_else() {
        let mut app = observed();
        // The focus opens on the first group's heading, which is not a row.
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::Findings);
        assert!(
            app.status().contains("only on a row in group 1"),
            "{}",
            app.status()
        );

        let mut app = observed();
        focus(&mut app, findings::Group::AgentWork);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(
            app.screen(),
            Screen::Findings,
            "a file-level gap is shown here and acted on nowhere"
        );
        assert!(app.status().contains("writes a file"), "{}", app.status());
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::FindingDetail);
        assert!(app.status().contains("writes a file"), "{}", app.status());

        let mut app = observed();
        focus(&mut app, findings::Group::Settings);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::Remediation);
    }

    #[test]
    fn merge_settings_bulk_never_contains_the_default_branch_ref() {
        let mut app = observed();
        let queue = app.queue.as_deref_mut().expect("an observed queue");
        let template = queue
            .rows
            .iter()
            .find(|row| row.group == findings::Group::Settings)
            .expect("a settings row")
            .clone();
        queue.rows = [
            "set-default-branch-main",
            "disable-merge-commits",
            "enable-squash-merge",
            "enable-head-branch-auto-delete",
        ]
        .into_iter()
        .map(|code| {
            let mut row = template.clone();
            row.rule = format!("REPO-SAMPLE-{code}");
            row.status = Status::Fail;
            row.remediation = Some(code.to_owned());
            row.change = Some(code.to_owned());
            row.reversible = Some(true);
            row
        })
        .collect();
        let items = bulk_items(
            queue,
            crate::admin::remediation::BulkKind::RepositorySettings,
        );
        assert!(
            items.len() >= 2,
            "the fixture must exercise a bulk settings confirmation"
        );
        assert!(items
            .iter()
            .all(|item| item.remediation != "set-default-branch-main"));
        assert!(items.iter().all(|item| {
            crate::admin::remediation::Action::for_code(&item.remediation).is_some_and(|action| {
                action.bulk_kind() == crate::admin::remediation::BulkKind::RepositorySettings
            })
        }));
    }

    #[test]
    fn merge_settings_bulk_groups_git_04_with_git_06_from_queue_rows() {
        let report = findings::fixture::report(
            airlock_core::findings::Gate::Required,
            vec![
                findings::fixture::finding("REPO-GIT-04", Severity::Blocking, Status::Fail),
                findings::fixture::finding("REPO-GIT-06", Severity::Blocking, Status::Fail),
            ],
        );
        let queue = findings::Queue::of(&report, &findings::Deliveries::default());
        let items = bulk_items(
            &queue,
            crate::admin::remediation::BulkKind::RepositorySettings,
        );
        assert_eq!(items.len(), 2);
        assert!(items
            .iter()
            .any(|item| item.remediation == "disable-merge-commits"));
        assert!(items
            .iter()
            .any(|item| item.remediation == "enable-head-branch-auto-delete"));
        assert!(items.iter().all(|item| {
            crate::admin::remediation::Action::for_code(&item.remediation).is_some_and(|action| {
                action.bulk_kind() == crate::admin::remediation::BulkKind::RepositorySettings
            })
        }));
    }

    #[test]
    fn enter_opens_a_finding_from_a_row_and_nothing_from_a_heading() {
        let mut app = observed();
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.screen(),
            Screen::Findings,
            "a heading has no finding under it"
        );
        focus(&mut app, findings::Group::Settings);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);
    }

    #[test]
    fn f_selects_one_of_five_sets_and_l_reaches_the_lookup_view() {
        let mut app = observed();
        assert_eq!(app.findings.filter(), findings::FilterSet::Everything);
        for expected in findings::FilterSet::ALL.iter().skip(1) {
            press(&mut app, KeyCode::Char('f'));
            assert_eq!(app.findings.filter(), *expected);
        }
        press(&mut app, KeyCode::Char('f'));
        assert_eq!(
            app.findings.filter(),
            findings::FilterSet::Everything,
            "the five cycle"
        );

        assert!(!app.findings.flat());
        press(&mut app, KeyCode::Char('l'));
        assert!(app.findings.flat());
        assert!(body_text(&app).contains("ordered by rule id"));
        press(&mut app, KeyCode::Char('l'));
        assert!(!app.findings.flat());
    }

    #[test]
    fn the_queue_captures_no_key_so_both_chrome_surfaces_keep_offering_the_theme() {
        // Nothing on this screen types: the filter selects between named sets,
        // so no printable key is text and neither surface has to withdraw one.
        // The footer here is longer than the row it has and drops entries from
        // the end with a count, which is the overflow rule; what it never does
        // is withdraw a key, and the header's slot is what shows the difference.
        let mut app = observed();
        for code in [
            KeyCode::Char('f'),
            KeyCode::Char('l'),
            KeyCode::Char(' '),
            KeyCode::Char('j'),
        ] {
            press(&mut app, code);
            assert!(header(&app).contains("theme t"), "{}", header(&app));
            let footer = footer(&app);
            assert!(footer.contains("f filter"), "{footer}");
            assert!(
                footer.contains("t theme") || footer.contains("more\u{2026}"),
                "a key left the footer without the footer admitting it: {footer}"
            );
        }
        let before = app.theme();
        press(&mut app, KeyCode::Char('t'));
        assert_ne!(app.theme(), before, "the toggle is live throughout");
    }

    #[test]
    fn the_status_line_carries_the_verdict_completeness_and_the_gate() {
        let app = observed();
        let status = app.status();
        assert!(status.contains("complete"), "{status}");
        assert!(status.contains("9 rules"), "{status}");
        assert!(status.contains("gate required"), "{status}");
    }

    #[test]
    fn a_note_answers_one_key_and_then_the_status_line_returns() {
        let mut app = observed();
        press(&mut app, KeyCode::Char('a'));
        assert!(app.status().contains("group 1"));
        press(&mut app, KeyCode::Down);
        assert!(!app.status().contains("group 1"), "{}", app.status());
    }

    fn body_text(app: &App) -> String {
        app.body(chrome::REFERENCE_WIDTH, chrome::REFERENCE_HEIGHT)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_findings_screen_prints_all_nine_statuses_with_their_glosses() {
        let app = app().at(Screen::Findings, Theme::Dark);
        let text: String = app
            .body(chrome::REFERENCE_WIDTH, chrome::REFERENCE_HEIGHT)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        for status in Status::ALL {
            assert!(text.contains(status.code()), "{status:?} is missing");
            assert!(text.contains(lane::glyph_of(*status)), "{status:?} glyph");
            // The gloss is elided to the room the row leaves, so its opening is
            // what the row is asserted to carry.
            let opening: String = lane::gloss_of(*status).chars().take(24).collect();
            assert!(text.contains(&opening), "{status:?} gloss");
        }
        for lane in Lane::ALL {
            assert!(text.contains(lane.heading()), "{lane:?}");
        }
    }

    // ---------------------------------------------------------------------
    // Mid-session expiry, and re-authorizing in place
    // ---------------------------------------------------------------------

    /// A session standing on the findings queue of an observed repository.
    ///
    /// Driven to where it stands rather than assembled there: an authorization,
    /// a catalogue, a repository opened, and a run observed, which is the whole
    /// of what an expiry has to survive.
    fn working_session() -> App {
        let mut app = app();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Enter);
        app.take_observation_request();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::fixture::deliveries(),
        );
        app
    }

    /// Everything the interface would draw, frame and all.
    fn frame_text(app: &App) -> String {
        let mut buffer = ratatui::buffer::Buffer::empty(Rect {
            x: 0,
            y: 0,
            width: chrome::REFERENCE_WIDTH,
            height: chrome::REFERENCE_HEIGHT,
        });
        app.render(buffer.area, &mut buffer);
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| {
                        buffer
                            .cell((x, y))
                            .map_or(" ", ratatui::buffer::Cell::symbol)
                            .to_owned()
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A run in which GitHub rejected the credential it was made with.
    fn rejected_run() -> airlock_core::findings::Report {
        let mut finding =
            findings::fixture::finding("REPO-GIT-01", Severity::Blocking, Status::Error);
        finding.error = Some(airlock_core::findings::FindingError {
            cause: "unauthenticated".to_owned(),
            endpoint: "GET /repos/{owner}/{repo}".to_owned(),
            status: Some(401),
            message: Some("Bad credentials".to_owned()),
            request_id: None,
            accepted_permissions: None,
            documentation_url: None,
            message_hints_version: airlock_core::github::MESSAGE_HINTS_VERSION,
        });
        findings::fixture::report(airlock_core::findings::Gate::Required, vec![finding])
    }

    #[test]
    fn the_grant_is_counted_down_and_the_countdown_is_what_lapses_it() {
        let mut app = working_session();
        assert_eq!(
            app.grant(),
            Some(Validity::Until(std::time::Duration::from_secs(28_800)))
        );
        assert!(header(&app).contains("grant ends in"), "{}", header(&app));

        app.tick(std::time::Duration::from_secs(28_799));
        assert!(!app.reauthorizing_now(), "a second is a second");
        assert!(app.queue.is_some(), "nothing is discarded before the lapse");

        app.tick(std::time::Duration::from_secs(1));
        assert!(app.reauthorizing_now(), "the grant ran out");
        assert_eq!(app.grant(), None, "there is no grant to count down");
        assert!(
            !header(&app).contains("grant"),
            "a lapsed grant is not a countdown of zero"
        );
    }

    #[test]
    fn a_grant_that_states_no_expiry_is_never_lapsed_by_a_clock() {
        // GitHub states no expiry when token expiry is disabled for the app.
        // Inventing one would be demanding a re-authorization for no observed
        // reason.
        let mut app = working_session();
        app.grant = Some(Validity::Unstated);
        app.tick(std::time::Duration::from_secs(60 * 60 * 24));
        assert!(!app.reauthorizing_now());
        assert!(header(&app).contains("expiry"), "{}", header(&app));
    }

    #[test]
    fn expiry_raises_the_overlay_on_every_screen_and_holds_the_screen_it_was_on() {
        // Every screen an authorized session can stand on. Sign-in is not one:
        // there is no grant there to lapse.
        for screen in [
            Screen::Organizations,
            Screen::Repositories,
            Screen::Findings,
            Screen::FindingDetail,
            Screen::PolicyInspector,
            Screen::PublishingBootstrap,
            Screen::Remediation,
        ] {
            let mut app = working_session();
            app.screen = screen;

            app.lapse();

            assert!(app.reauthorizing_now(), "{screen:?}");
            assert!(app.take_reauthorization_request(), "{screen:?}");
            // The transcript is an observation; the queue behind it is where
            // the operator stands once it is gone.
            let expected = if screen == Screen::Remediation {
                Screen::Findings
            } else {
                screen
            };
            // Abandon-and-exit is offered at every width. The footer drops
            // entries from the end, so the key that leaves leads it.
            for width in [chrome::REFERENCE_WIDTH, chrome::FLOOR_WIDTH] {
                let footer: String = chrome::keymap_line(&app.keymap(), app.styles(), width)
                    .spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect();
                assert!(
                    footer.contains("esc abandon and exit"),
                    "{screen:?} at {width}: {footer}"
                );
                assert!(
                    footer.contains("r issue a new code"),
                    "{screen:?} at {width}: {footer}"
                );
                assert!(footer.contains("ctrl-c") || footer.contains("more\u{2026}"));
            }

            app.authorization_granted(granted());
            assert_eq!(app.screen(), expected, "{screen:?}");
        }
    }

    #[test]
    fn no_observation_survives_the_boundary_on_any_screen() {
        // Read off the enum rather than listed here, so a screen added later
        // is covered by this proof on the day it is added rather than on the
        // day somebody remembers to add it to a list. Sign-in is included: a
        // session standing there has nothing to lose, and a proof that it
        // loses nothing costs one iteration.
        for screen in Screen::ALL {
            let mut app = working_session();
            app.screen = screen;
            // The remediation screen is only itself with something on it.
            if screen == Screen::Remediation {
                app.remediation = remediation::State::confirm(
                    "acme-industries".to_owned(),
                    "widget".to_owned(),
                    vec![remediation::Item {
                        rule: "REPO-GIT-01".to_owned(),
                        remediation: "correct-merge-settings".to_owned(),
                        change: "disable merge commits".to_owned(),
                        reversible: true,
                        input: remediation::Input::None,
                    }],
                );
            }
            app.observed(
                &Observe {
                    owner: "acme-industries".to_owned(),
                    name: "widget".to_owned(),
                },
                "this session",
                "nonconformant",
            );
            assert!(app.queue.is_some(), "{screen:?}: there is a run to lose");

            app.lapse();

            // The state that carried what was seen.
            assert!(app.queue.is_none(), "{screen:?}");
            assert!(app.inspector.is_none(), "{screen:?}");
            assert_eq!(app.catalogue, catalogue::State::Unauthorized, "{screen:?}");
            assert_eq!(app.observations, Observations::default(), "{screen:?}");
            assert!(
                matches!(app.remediation, remediation::State::Empty),
                "{screen:?}"
            );
            assert!(!app.authorized(), "{screen:?}");

            // And the screen, which is where it would have been read. Every
            // one of these is something airlock saw: a rule it evaluated, the
            // verdict it reached, what it counted in an installation, and what
            // kind of account GitHub said that installation was.
            let after = frame_text(&app);
            for observed in [
                "REPO-GIT-01",
                "REPO-GIT-04",
                "nonconformant",
                "2 repositories",
                "user account",
            ] {
                assert!(
                    !after.contains(observed),
                    "{screen:?}: {observed} survived the boundary\n{after}"
                );
            }
            // The address did survive, and says so: it is where to look again,
            // not something that was seen there.
            assert!(
                after.contains("acme-industries/widget"),
                "{screen:?}: the position was not held\n{after}"
            );
        }
    }

    #[test]
    fn nothing_the_lapsed_grant_authorized_is_still_waiting_to_be_carried_out() {
        // A write authorized by a credential that no longer exists is not a
        // write this session consented to.
        let mut app = working_session();
        focus(&mut app, findings::Group::Settings);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.screen(), Screen::Remediation);
        press(&mut app, KeyCode::Enter);
        assert!(app.pending_remediation.is_some(), "the confirmation stands");

        app.lapse();

        assert!(app.take_remediation_request().is_none());
        assert!(app.take_undo_request().is_none());
        assert!(app.take_preparation_request().is_none());
        assert!(app.take_observation_request().is_none());
        assert!(matches!(app.remediation, remediation::State::Empty));
    }

    #[test]
    fn a_remediation_in_flight_is_re_observed_rather_than_resumed_from_memory() {
        let mut app = working_session();
        focus(&mut app, findings::Group::Settings);
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Enter);
        app.take_remediation_request();
        app.remediation_complete(crate::admin::remediation::Transcript {
            rule: "REPO-GIT-01".to_owned(),
            remediation: "correct-merge-settings".to_owned(),
            proposed_change: "disable merge commits".to_owned(),
            steps: Vec::new(),
            observed: crate::admin::remediation::ObservedStatus::Pass,
            undo: None,
        });
        assert!(matches!(
            app.remediation,
            remediation::State::Complete { .. }
        ));

        app.lapse();
        app.authorization_granted(granted());

        assert_eq!(app.screen(), Screen::Findings, "the queue behind it");
        assert!(matches!(app.remediation, remediation::State::Empty));
        assert_eq!(
            app.take_observation_request(),
            Some(Observe {
                owner: "acme-industries".to_owned(),
                name: "widget".to_owned()
            }),
            "the queue is asked for again rather than resumed"
        );
    }

    #[test]
    fn the_position_is_held_across_the_boundary_and_restored_with_a_fresh_run() {
        let mut app = working_session();
        // A place in the queue that is nobody's default: a filter, a collapsed
        // group, a moved row, and an open detail.
        press(&mut app, KeyCode::Char('f'));
        press(&mut app, KeyCode::Char(' '));
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        let held = app.findings.clone();
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::FindingDetail);

        app.lapse();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        let requested = app
            .take_observation_request()
            .expect("the repository is observed again");
        assert_eq!(requested.name, "widget");
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::fixture::deliveries(),
        );

        assert_eq!(app.screen(), Screen::FindingDetail, "the detail was open");
        assert_eq!(app.findings.selected(), held.selected());
        assert_eq!(app.findings.filter(), held.filter());
        for group in findings::Group::ALL {
            assert_eq!(
                app.findings.is_collapsed(group),
                held.is_collapsed(group),
                "{group:?}"
            );
        }
        assert_eq!(app.installation, 0);
        assert_eq!(app.repository, 0);
    }

    #[test]
    fn a_held_queue_position_is_let_go_of_when_another_repository_is_opened() {
        // A position in one repository's queue is not a position in another's.
        let mut app = working_session();
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        app.lapse();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        app.take_observation_request();
        // The operator opens the other repository instead of waiting.
        app.screen = Screen::Repositories;
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        app.take_observation_request();
        app.observed_run(
            &findings::fixture::mixed(),
            &findings::fixture::deliveries(),
        );
        assert_eq!(
            app.findings.selected(),
            0,
            "a fresh queue is read from the top"
        );
    }

    #[test]
    fn the_held_position_is_found_again_by_name_rather_than_by_index() {
        // A list read again is not the list that was read: an index kept across
        // the boundary would point at whatever moved into that slot.
        use airlock_core::github::{AccountKind, RepositorySelection};
        let mut app = app();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), Screen::Repositories);
        assert_eq!(
            app.selected_installation().map(|i| i.account.as_str()),
            Some("sample-operator")
        );

        app.lapse();
        app.authorization_granted(granted());
        // The same installations, in the other order.
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue::Catalogue::of(
            vec![
                installation(
                    "sample-operator",
                    AccountKind::UserAccount,
                    RepositorySelection::Selected,
                    &["notes"],
                ),
                installation(
                    "acme-industries",
                    AccountKind::Organization,
                    RepositorySelection::All,
                    &["widget", "sprocket"],
                ),
            ],
        ))));

        assert_eq!(
            app.selected_installation().map(|i| i.account.as_str()),
            Some("sample-operator"),
            "the position is an address, and the address was found again"
        );
    }

    #[test]
    fn an_installation_that_is_gone_leaves_the_selection_at_the_top() {
        let mut app = app();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        press(&mut app, KeyCode::Down);
        app.lapse();
        app.authorization_granted(granted());
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue::Catalogue::of(
            Vec::new(),
        ))));
        assert_eq!(app.installation, 0);
        assert!(app.selected_installation().is_none());
    }

    #[test]
    fn a_rejected_observation_lapses_the_session_rather_than_drawing_a_queue() {
        // 401 is the credential being rejected, not the repository failing a
        // rule. Drawing it as a queue would report a repository as failing
        // rules nothing was able to ask about.
        let mut app = working_session();
        app.observed_run(&rejected_run(), &findings::Deliveries::default());
        assert!(app.reauthorizing_now());
        assert!(app.queue.is_none(), "nothing of it was drawn");
    }

    #[test]
    fn a_catalogue_read_that_was_rejected_lapses_the_session() {
        let mut app = working_session();
        app.catalogue_read(catalogue::Read::Unauthorized);
        assert!(app.reauthorizing_now());
        assert!(app.take_reauthorization_request());
    }

    #[test]
    fn the_overlay_says_what_it_is_holding_at_every_size() {
        let mut app = working_session();
        press(&mut app, KeyCode::Char('f'));
        press(&mut app, KeyCode::Down);
        app.lapse();

        // The status line carries the reading at both sizes, so the fact is
        // never what a short terminal withheld.
        // The status line summarises it, and fits the floor without eliding.
        let status = app.status();
        assert!(status.contains("re-authorizing"), "{status}");
        assert!(status.contains("findings"), "{status}");
        assert!(status.contains("acme-industries/widget"), "{status}");
        assert!(status.contains("row 2"), "{status}");
        assert!(status.contains("gating failures"), "{status}");
        assert!(
            status.chars().count() <= chrome::FLOOR_WIDTH as usize,
            "{} columns: {status}",
            status.chars().count()
        );

        // The body carries it at both sizes: the reading is where the fact
        // lives, and a short terminal costs the words around it rather than
        // the fact itself.
        for width in [chrome::REFERENCE_WIDTH, chrome::FLOOR_WIDTH] {
            let height = if width == chrome::FLOOR_WIDTH { 21 } else { 35 };
            let text = app
                .body(width, height)
                .iter()
                .flat_map(|line| line.spans.iter())
                .map(|span| span.content.as_ref())
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("holding"), "at {width}: {text}");
            assert!(
                text.contains("acme-industries/widget"),
                "at {width}: {text}"
            );
            assert!(text.contains("row 2"), "at {width}: {text}");
        }

        // At the reference there are rows for the whole of it.
        let body = body_text(&app);
        assert!(body.contains("discarded"), "{body}");
        assert!(body.contains("observed again"), "{body}");
        assert!(body.contains("detail closed"), "{body}");
        // And the flow itself is sign-in's, not a second rendering of it.
        assert!(
            body.contains("No credential of any kind is stored"),
            "{body}"
        );
        assert!(body.contains("lapsed"), "{body}");
    }

    #[test]
    fn the_overlay_fits_the_floor_whole() {
        let mut app = working_session();
        app.lapse();
        for state in [
            SignIn::Requesting {
                reason: Reason::Lapsed,
            },
            {
                let mut awaiting = SignIn::opening();
                awaiting.code_issued(&issued());
                awaiting
            },
            SignIn::Expired,
            SignIn::Denied,
        ] {
            app.sign_in = sign_in::Screen::at(state);
            let lines = app.body(chrome::FLOOR_WIDTH, 21);
            assert!(lines.len() <= 21, "{} rows", lines.len());
            for line in lines {
                let printed: usize = line
                    .spans
                    .iter()
                    .map(|span| span.content.chars().count())
                    .sum();
                assert!(printed <= chrome::FLOOR_WIDTH as usize, "{printed} columns");
            }
        }
    }

    #[test]
    fn the_overlay_takes_the_keys_and_esc_abandons_the_session() {
        let mut app = working_session();
        app.lapse();

        // Nothing behind the overlay may act: what those keys acted on was
        // observed under a grant that has lapsed.
        for code in [
            KeyCode::Enter,
            KeyCode::Down,
            KeyCode::Char('a'),
            KeyCode::Char('f'),
            KeyCode::Char('p'),
            KeyCode::Char('o'),
        ] {
            assert_eq!(press(&mut app, code), Flow::Continue, "{code:?}");
            assert!(app.reauthorizing_now(), "{code:?}");
            assert!(app.queue.is_none(), "{code:?}");
        }

        // Sign-in's own two are live, on sign-in's own terms.
        assert_eq!(press(&mut app, KeyCode::Char('r')), Flow::Continue);
        app.report(Progress::CodeIssued(Box::new(issued())));
        assert_eq!(press(&mut app, KeyCode::Char('r')), Flow::Reissue);
        let before = app.theme();
        press(&mut app, KeyCode::Char('t'));
        assert_ne!(app.theme(), before);

        assert_eq!(
            press(&mut app, KeyCode::Esc),
            Flow::Exit,
            "esc abandons the re-authorization and exits"
        );
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Flow::Exit
        );
    }

    #[test]
    fn nothing_produced_under_the_lapsed_grant_can_be_applied_after_the_boundary() {
        // The workers are dropped at the boundary, so their queues go with
        // them. This is the other half of that: whatever order a caller drains
        // its queues in, an answer reached with a credential this session no
        // longer holds is refused rather than drawn.
        let mut app = working_session();
        app.lapse();
        let holding = app.status();

        app.observed_run(
            &findings::fixture::aligned(),
            &findings::fixture::deliveries(),
        );
        app.catalogue_read(catalogue::Read::Ready(Box::new(catalogue())));
        app.observed(
            &Observe {
                owner: "acme-industries".to_owned(),
                name: "widget".to_owned(),
            },
            "this session",
            "conformant",
        );
        app.remediation_complete(crate::admin::remediation::Transcript {
            rule: "REPO-GIT-01".to_owned(),
            remediation: "correct-merge-settings".to_owned(),
            proposed_change: "disable merge commits".to_owned(),
            steps: Vec::new(),
            observed: crate::admin::remediation::ObservedStatus::Pass,
            undo: None,
        });
        app.operation_failed("a failure from the session that ended".to_owned());

        assert!(app.reauthorizing_now(), "the overlay is still up");
        assert!(app.queue.is_none(), "a stale run was drawn");
        assert!(app.inspector.is_none(), "a stale policy was drawn");
        assert_eq!(app.catalogue, catalogue::State::Unauthorized);
        assert_eq!(app.observations, Observations::default());
        assert!(matches!(app.remediation, remediation::State::Empty));
        assert_eq!(
            app.status(),
            holding,
            "the overlay still says what it holds"
        );
    }

    #[test]
    fn a_lapse_is_asked_for_once_however_many_ways_it_is_noticed() {
        let mut app = working_session();
        app.lapse();
        let held = app.status();
        // A second notice while the overlay is up must not replace the
        // position it is holding with the position of the overlay itself.
        app.lapse();
        app.catalogue_read(catalogue::Read::Unauthorized);
        assert_eq!(app.status(), held);
        assert!(app.take_reauthorization_request());
        assert!(!app.take_reauthorization_request(), "asked for once");
    }
}
