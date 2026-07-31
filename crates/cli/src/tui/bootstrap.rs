//! The publishing bootstrap screen.
//!
//! Five steps that take a package from never-published to publishing without a
//! stored credential, and no memory of where the operator was in them. On entry
//! the interface re-observes the repository secret, the package, and any public
//! publisher signal, and the steps' states are read off those observations.
//! Closing the terminal loses nothing, because nothing here is a saved wizard
//! position.

use std::time::Duration;

use ratatui::text::{Line, Span};

use crate::admin::bootstrap::{
    place, Ceremony, Credential, Observation, Placement, Publication, StepState,
};
use crate::admin::catalogue::Observe;
use crate::admin::remediation::{ObservedStatus, Transcript};

use super::chrome::wrap;
use super::panel::{self, LABEL_WIDTH};
use super::remediation::SecretInputState;
use super::theme::{Role, Styles};

/// The confirmed write the screen asks the loop to make.
///
/// A name and coordinates. The value travels beside the credential, in the
/// terminal driver, and this type has no field it could sit in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub owner: String,
    pub repo: String,
    pub secret: String,
}

/// What step 2 is doing, where it is doing anything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Entry {
    /// The steps are being read rather than acted on.
    #[default]
    Idle,
    /// The shared secret-entry surface holds focus. The value is the terminal
    /// driver's; this state is the fixed, value-independent indicator.
    Secret {
        secret: String,
        replacing: bool,
        input: SecretInputState,
    },
    /// The value is supplied and the named write awaits confirmation.
    Confirm { secret: String, replacing: bool },
    /// The confirmed write is in flight.
    Applying { secret: String },
    /// The write returned, with what was then observed.
    Complete { transcript: Box<Transcript> },
}

/// Everything the screen holds. None of it survives a lapse, and none of it is
/// a position.
#[derive(Debug, Clone, Default)]
pub struct State {
    /// The repository the observation is of.
    target: Option<Observe>,
    /// What was observed, one entry per declared publication target.
    observations: Vec<Observation>,
    /// Which target is being read, where the repository publishes more than
    /// one.
    selected: usize,
    /// How long ago the last observation arrived.
    ///
    /// A duration counted by the loop's own tick rather than a wall clock: the
    /// screen states how stale its reading is, and a reading's age is what the
    /// operator needs while step 3 waits on an external event.
    since: Option<Duration>,
    /// Whether an observation has been asked for and not yet answered.
    observing: bool,
    entry: Entry,
    /// Where the operator is in a reading longer than the terminal is tall.
    ///
    /// Height is answered by scrolling here as everywhere else: five steps with
    /// their notes and an outstanding credential is more than twenty-four rows
    /// hold, and a step dropped to make the rest fit would be a step the
    /// operator never learns is blocked.
    scroll: panel::Scroll,
}

impl State {
    /// Ask for the observation the screen is placed by.
    ///
    /// Every entry to the screen asks, and `o` asks again. There is no cached
    /// answer to prefer: an observation is what places the operator, and one
    /// taken a while ago places them where they were.
    pub fn observe(&mut self, target: Observe) {
        self.target = Some(target);
        self.observing = true;
    }

    /// Take the freshly observed facts.
    pub fn observed(&mut self, target: Observe, observations: Vec<Observation>) {
        self.target = Some(target);
        self.observations = observations;
        self.selected = self.selected.min(self.observations.len().saturating_sub(1));
        self.since = Some(Duration::ZERO);
        self.observing = false;
        self.scroll.rewind();
    }

    /// Age the reading, so the screen says how stale it is rather than implying
    /// it is current.
    pub fn tick(&mut self, elapsed: Duration) {
        if let Some(since) = &mut self.since {
            *since = since.saturating_add(elapsed);
        }
    }

    /// Move the window over a reading longer than the terminal is tall.
    pub fn scroll(&mut self, delta: isize) {
        self.scroll.by(delta);
    }

    /// Move to the next publication target, where the repository declares more
    /// than one. A position in one target's reading is not a position in
    /// another's, so the window returns to the top.
    pub fn next_target(&mut self) -> bool {
        if self.observations.len() < 2 {
            return false;
        }
        self.selected = (self.selected + 1) % self.observations.len();
        self.scroll.rewind();
        true
    }

    #[must_use]
    pub fn focused(&self) -> Option<&Observation> {
        self.observations.get(self.selected)
    }

    /// Where the observation places the operator on the focused target.
    #[must_use]
    pub fn placement(&self) -> Option<Placement> {
        self.focused().map(place)
    }

    /// Whether the shared secret surface holds focus.
    #[must_use]
    pub const fn accepts_secret(&self) -> bool {
        matches!(self.entry, Entry::Secret { .. })
    }

    /// Whether a printable key is text rather than a screen key.
    #[must_use]
    pub const fn captures_text(&self) -> bool {
        self.accepts_secret()
    }

    pub fn secret_input_changed(&mut self, holding_input: bool) {
        if let Entry::Secret { input, .. } = &mut self.entry {
            *input = if holding_input {
                SecretInputState::Holding
            } else {
                SecretInputState::Empty
            };
        }
    }

    pub fn secret_empty_refused(&mut self) {
        if let Entry::Secret { input, .. } = &mut self.entry {
            *input = SecretInputState::EmptyRefused;
        }
    }

    /// The operator supplied a value. The write is not made until the named
    /// write itself is confirmed.
    pub fn secret_supplied(&mut self) {
        if let Entry::Secret {
            secret, replacing, ..
        } = &self.entry
        {
            self.entry = Entry::Confirm {
                secret: secret.clone(),
                replacing: *replacing,
            };
        }
    }

    /// Leave whatever step 2 was doing, without making a request.
    pub fn cancel(&mut self) -> bool {
        if matches!(self.entry, Entry::Idle) {
            return false;
        }
        self.entry = Entry::Idle;
        true
    }

    /// Open the shared secret surface for the focused target.
    ///
    /// Live while the ceremony's credential step is the live one, and also
    /// while the repository already holds the secret — a token that died before
    /// the first publish is re-minted by setting the same name again.
    pub fn supply_secret(&mut self) -> Result<(), &'static str> {
        let Some(observation) = self.focused() else {
            return Err("nothing has been observed yet, so there is no secret to set");
        };
        let Some(secret) = observation.unit.registry.bootstrap_secret() else {
            return Err(match observation.unit.registry.ceremony() {
                Ceremony::PendingPublisher => {
                    "this registry configures a publisher before publication, so it \
                     has no bootstrap credential to set"
                }
                _ => {
                    "the container path has no bootstrap credential; its first step \
                     is a push, not a token"
                }
            });
        };
        let placement = place(observation);
        let live = placement.live_step();
        if !matches!(live, Some(1..=3)) {
            return Err(
                "the token step is not the live one; re-observe if you believe that is stale",
            );
        }
        self.entry = Entry::Secret {
            secret: secret.to_owned(),
            replacing: observation.credential.is_some(),
            input: SecretInputState::Empty,
        };
        Ok(())
    }

    /// Confirm the named write once. A second `↵` cannot queue a second write.
    pub fn take_confirmation(&mut self) -> Option<Request> {
        let Entry::Confirm { secret, .. } = &self.entry else {
            return None;
        };
        let target = self.target.clone()?;
        let request = Request {
            owner: target.owner,
            repo: target.name,
            secret: secret.clone(),
        };
        self.entry = Entry::Applying {
            secret: request.secret.clone(),
        };
        Some(request)
    }

    /// Whether a confirmed write is in flight, which is what makes the returning
    /// transcript this screen's rather than the remediation screen's.
    #[must_use]
    pub const fn applying(&self) -> bool {
        matches!(self.entry, Entry::Applying { .. })
    }

    /// Close the write with what was observed after it.
    pub fn complete(&mut self, transcript: Transcript) {
        self.entry = Entry::Complete {
            transcript: Box::new(transcript),
        };
    }

    /// The status line: the step, what it waits on, and how the position was
    /// reached.
    #[must_use]
    pub fn status(&self) -> String {
        if let Entry::Secret { input, .. } = &self.entry {
            return match input {
                SecretInputState::Empty => {
                    "token value required \u{b7} no value entered \u{b7} the value is never displayed"
                }
                SecretInputState::EmptyRefused => "empty value refused \u{b7} no request made",
                SecretInputState::Holding => {
                    "token input held \u{b7} value and length hidden"
                }
            }
            .to_owned();
        }
        if matches!(self.entry, Entry::Confirm { .. }) {
            return "confirmation required \u{b7} the value is consumed only by the named write"
                .to_owned();
        }
        if matches!(self.entry, Entry::Applying { .. }) {
            return "setting the secret \u{b7} completion is the re-observed presence of the name"
                .to_owned();
        }
        if let Entry::Complete { transcript } = &self.entry {
            return match transcript.observed {
                ObservedStatus::Pass => {
                    "secret observed present \u{b7} its value is not readable back, so nothing here claims it works"
                }
                ObservedStatus::Fail => "the secret was not observed after the write",
                ObservedStatus::Inconclusive => "the write could not be established",
            }
            .to_owned();
        }
        let Some(placement) = self.placement() else {
            return if self.observing {
                "observing \u{b7} position is derived from observation, never remembered".to_owned()
            } else {
                "nothing observed yet \u{b7} position is derived from observation, never remembered"
                    .to_owned()
            };
        };
        let extent = placement.extent();
        match (placement.live_step(), placement.waiting_on()) {
            (Some(step), Some(waiting)) => format!(
                "step {step} of {extent} \u{b7} {} \u{b7} re-observed on entry",
                first_sentence(waiting)
            ),
            _ => match placement {
                Placement::Unnecessary { .. } => {
                    "no ceremony on this registry \u{b7} re-observed on entry".to_owned()
                }
                _ => format!(
                    "no step is live \u{b7} {extent} of {extent} observed done \u{b7} re-observed on entry"
                ),
            },
        }
    }
}

fn first_sentence(text: &str) -> String {
    text.split_once(". ")
        .map_or_else(|| text.to_owned(), |(first, _)| first.to_owned())
}

/// Why the sequence exists, stated before any of it is acted on.
const WHY: &str = "Most registries will not accept a trusted publisher for a package that has \
     never been published. A token exists only to produce that first release, \
     and that token is the thing the policy is trying to eliminate. First \
     publication is a distinct, human-supervised, credentialed event; steady \
     state is credential-free.";

/// The statement that nothing here is remembered.
const RESUME: &str = "Position in the sequence is never remembered. On entry airlock re-observes \
     the repository secret, the package, and any public publisher signal, and \
     places you at the step those observations imply. Closing the terminal loses \
     nothing.";

/// Draw the screen.
#[must_use]
pub fn body(styles: Styles, width: u16, height: u16, state: &State) -> Vec<Line<'static>> {
    state
        .scroll
        .window(reading(styles, width, state), height as usize, styles)
}

fn reading(styles: Styles, width: u16, state: &State) -> Vec<Line<'static>> {
    let width = width as usize;
    let mut lines = vec![Line::from(Span::styled(
        "PUBLISHING BOOTSTRAP",
        styles.bold(Role::Accent),
    ))];
    for line in wrap(WHY, width) {
        lines.push(Line::from(Span::styled(line, styles.of(Role::Text))));
    }
    lines.push(Line::default());

    let Some(observation) = state.focused() else {
        lines.extend(nothing_observed(styles, width, state));
        return lines;
    };

    lines.extend(panel::field(
        styles,
        "package",
        &format!(
            "{} \u{b7} {}",
            observation.unit.package,
            observation.unit.registry.label()
        ),
        width,
    ));
    if state.observations.len() > 1 {
        lines.extend(panel::field(
            styles,
            "target",
            &format!(
                "{} of {} declared publication targets \u{b7} tab selects the next",
                state.selected + 1,
                state.observations.len()
            ),
            width,
        ));
    }
    lines.extend(panel::field(
        styles,
        "observed",
        &match state.since {
            Some(since) if state.observing => format!(
                "{} ago \u{b7} a fresh observation is in flight",
                elapsed(since)
            ),
            Some(since) => format!("{} ago \u{b7} press o to re-observe now", elapsed(since)),
            None => "not yet \u{b7} press o to observe".to_owned(),
        },
        width,
    ));
    lines.extend(panel::field(
        styles,
        "publication",
        &match &observation.publication {
            Publication::Published { latest } => format!(
                "`{}` is on {} at {latest}",
                observation.unit.package,
                observation.unit.registry.label()
            ),
            Publication::Absent => format!(
                "`{}` is not on {}",
                observation.unit.package,
                observation.unit.registry.label()
            ),
            Publication::Undecided { reason } => {
                format!("not established: {reason}. This is not the same as absent.")
            }
        },
        width,
    ));
    lines.push(Line::default());
    // What is being acted on leads. While step 2 holds the operator's input,
    // the surface they are typing into is the first thing on the screen rather
    // than something a short terminal makes them scroll to find.
    lines.extend(entry_block(styles, width, state));
    lines.extend(steps(styles, width, observation));
    lines.push(Line::default());
    lines.extend(credential_block(styles, width, observation));
    for line in wrap(RESUME, width) {
        lines.push(Line::from(Span::styled(line, styles.of(Role::Faint))));
    }
    lines
}

fn steps(styles: Styles, width: usize, observation: &Observation) -> Vec<Line<'static>> {
    let placement = place(observation);
    let mut lines = Vec::new();
    match &placement {
        Placement::Unnecessary { reason } => {
            lines.push(panel::heading(styles, "NO CEREMONY ON THIS REGISTRY"));
            for line in wrap(reason, width) {
                lines.push(Line::from(Span::styled(line, styles.of(Role::Text))));
            }
        }
        Placement::Ceremony(steps) => {
            lines.push(panel::heading(styles, "THE FIVE STEPS"));
            for (step, state) in steps {
                lines.extend(step_lines(
                    styles,
                    width,
                    step.number(),
                    step.title(),
                    state,
                ));
            }
        }
        Placement::Container(steps) => {
            lines.push(panel::heading(styles, "THE CONTAINER PATH"));
            for (step, state) in steps {
                lines.extend(step_lines(
                    styles,
                    width,
                    step.number(),
                    step.title(),
                    state,
                ));
            }
        }
    }
    lines
}

fn step_lines(
    styles: Styles,
    width: usize,
    number: usize,
    title: &str,
    state: &StepState,
) -> Vec<Line<'static>> {
    let role = match state {
        StepState::Done { .. } => Role::Dim,
        StepState::Live { .. } => Role::Accent,
        StepState::Blocked { .. } | StepState::Unobservable { .. } => Role::Faint,
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{} {number}. ", state.glyph()), styles.bold(role)),
        Span::styled(title.to_owned(), styles.bold(role)),
        Span::styled(
            format!(" \u{2014} {}", state.name()),
            styles.of(Role::Faint),
        ),
    ])];
    let room = width.saturating_sub(6).max(1);
    for line in wrap(state.note(), room) {
        lines.push(Line::from(Span::styled(
            format!("     {line}"),
            styles.of(Role::Dim),
        )));
    }
    lines
}

/// The outstanding credential, shown for as long as one exists.
fn credential_block(styles: Styles, width: usize, observation: &Observation) -> Vec<Line<'static>> {
    let Some(Credential {
        name,
        scope,
        created,
    }) = &observation.credential
    else {
        if observation.unit.registry.ceremony() == Ceremony::Token {
            return vec![
                panel::heading(styles, "OUTSTANDING CREDENTIAL"),
                Line::from(Span::styled(
                    format!(
                        "{:<LABEL_WIDTH$}none. No bootstrap secret was observed on this repository.",
                        "credential"
                    ),
                    styles.of(Role::Dim),
                )),
                Line::default(),
            ];
        }
        return Vec::new();
    };
    let mut lines = vec![panel::heading(styles, "OUTSTANDING CREDENTIAL")];
    for (label, value) in [
        ("secret", name.clone()),
        ("scope", scope.clone()),
        ("created", created.clone()),
        (
            "expiry",
            "not observable. GitHub does not hold the registry token's lifetime and \
             airlock does not guess one; if it dies before the first publish, set \
             the same secret again with a freshly minted token."
                .to_owned(),
        ),
        (
            "value",
            "never displayed, never logged, never written anywhere by airlock.".to_owned(),
        ),
        (
            "why it exists",
            format!(
                "solely to complete this bootstrap. The flow is not conformant until \
                 `{name}` no longer exists and the token behind it is revoked."
            ),
        ),
    ] {
        lines.extend(panel::field(styles, label, &value, width));
    }
    lines.push(Line::default());
    lines
}

fn entry_block(styles: Styles, width: usize, state: &State) -> Vec<Line<'static>> {
    match &state.entry {
        Entry::Idle => Vec::new(),
        Entry::Secret {
            secret,
            replacing,
            input,
        } => {
            let mut lines = vec![panel::heading(styles, "TOKEN VALUE")];
            lines.extend(panel::field(
                styles,
                "target secret",
                &format!(
                    "{secret} \u{b7} {}",
                    if *replacing {
                        "the repository already holds this name; the value will be replaced"
                    } else {
                        "the repository does not hold this name yet"
                    }
                ),
                width,
            ));
            lines.extend(panel::field(
                styles,
                "value",
                "input is accepted here. The value and its length are never displayed.",
                width,
            ));
            lines.extend(panel::field(
                styles,
                "input status",
                match input {
                    SecretInputState::Empty => "empty \u{b7} enter refuses",
                    SecretInputState::Holding => "holding input \u{b7} value and length hidden",
                    SecretInputState::EmptyRefused => {
                        "empty value refused \u{b7} no request was made"
                    }
                },
                width,
            ));
            lines.extend(panel::field(
                styles,
                "next",
                "enter continues to the named confirmation \u{b7} esc cancels",
                width,
            ));
            lines.push(Line::default());
            lines
        }
        Entry::Confirm { secret, replacing } => {
            let mut lines = vec![panel::heading(styles, "CONFIRM THE NAMED WRITE")];
            lines.extend(panel::field(
                styles,
                "write",
                &format!(
                    "set the repository secret `{secret}`{}",
                    if *replacing {
                        ", replacing the value it currently holds"
                    } else {
                        ""
                    }
                ),
                width,
            ));
            lines.extend(panel::field(
                styles,
                "value",
                "supplied by you just now. It is neither shown here nor verified: \
                 GitHub does not read a secret's value back, so airlock cannot say \
                 whether the token works.",
                width,
            ));
            lines.push(Line::from(Span::styled(
                "Press enter to confirm. No request has been made.",
                styles.bold(Role::Text),
            )));
            lines.push(Line::default());
            lines
        }
        Entry::Applying { secret } => vec![
            panel::heading(styles, "CONFIRM THE NAMED WRITE"),
            Line::from(Span::styled(
                format!("Confirmed `{secret}`. Waiting for re-observation."),
                styles.of(Role::Text),
            )),
            Line::default(),
        ],
        Entry::Complete { transcript } => {
            let mut lines = vec![panel::heading(styles, "TRANSCRIPT")];
            lines.push(Line::from(Span::styled(
                transcript.proposed_change.clone(),
                styles.of(Role::Dim),
            )));
            for step in &transcript.steps {
                let glyph = if step.succeeded { "\u{2713}" } else { "!" };
                for (index, line) in wrap(
                    &format!(
                        "{glyph} +{:>6.2}s  {}",
                        step.elapsed.as_secs_f64(),
                        step.detail
                    ),
                    width,
                )
                .into_iter()
                .enumerate()
                {
                    lines.push(Line::from(Span::styled(
                        if index == 0 {
                            line
                        } else {
                            format!("    {line}")
                        },
                        styles.of(Role::Text),
                    )));
                }
            }
            lines.push(Line::default());
            lines
        }
    }
}

fn nothing_observed(styles: Styles, width: usize, state: &State) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "NOTHING OBSERVED YET",
        styles.bold(Role::Text),
    ))];
    for (label, text) in [
        (
            "would show",
            "the five steps, the one the observation places you at, and any \
             outstanding credential"
                .to_owned(),
        ),
        (
            "empty because",
            if state.observing {
                "the observation this screen is placed by is in flight. Nothing is \
                 drawn from a previous one, because a position is never remembered."
                    .to_owned()
            } else if state.target.is_none() {
                "no repository has been observed in this session, so there is \
                 nothing to bootstrap. Open a repository from the repositories \
                 screen first."
                    .to_owned()
            } else {
                "the observation established no declared publication target: \
                 `.intentional/config.yml` declares no release units, or no unit's \
                 path carries a manifest airlock recognises. Either is possible and \
                 an empty result cannot tell them apart."
                    .to_owned()
            },
        ),
        (
            "next",
            "press o to observe now, or esc to return to the findings queue.".to_owned(),
        ),
    ] {
        lines.extend(panel::field(styles, label, &text, width));
    }
    lines
}

/// How long ago, in the units the reader thinks in.
fn elapsed(since: Duration) -> String {
    let seconds = since.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    if seconds < 3600 {
        return format!("{}m {}s", seconds / 60, seconds % 60);
    }
    format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::bootstrap::{Container, Publisher, Registry, Unit};

    fn observe() -> Observe {
        Observe {
            owner: "generic-owner".to_owned(),
            name: "sample-repository".to_owned(),
        }
    }

    fn observation(credential: Option<Credential>, publication: Publication) -> Observation {
        Observation {
            unit: Unit {
                package: "sample-package".to_owned(),
                registry: Registry::CratesIo,
            },
            credential,
            publication,
            publisher: Publisher::Unobservable {
                reason: "gated on crate ownership".to_owned(),
            },
            container: None,
        }
    }

    fn credential() -> Credential {
        Credential {
            name: "CARGO_REGISTRY_TOKEN".to_owned(),
            scope: "generic-owner/sample-repository \u{b7} Actions repository secret".to_owned(),
            created: "2026-01-02T03:04:05Z".to_owned(),
        }
    }

    fn state(observation: Observation) -> State {
        let mut state = State::default();
        state.observe(observe());
        state.observed(observe(), vec![observation]);
        state
    }

    /// The frame as one line, so an assertion is about what the screen says
    /// rather than about where the width happened to wrap it.
    fn rendered(state: &State) -> String {
        let text = drawn(state);
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn drawn(state: &State) -> String {
        reading(
            Styles::new(
                super::super::theme::Theme::Dark,
                super::super::theme::ColorMode::NoColor,
            ),
            80,
            state,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
    }

    #[test]
    fn the_screen_says_why_the_ceremony_exists() {
        let text = rendered(&state(observation(None, Publication::Absent)));
        assert!(text.contains("never been published"), "{text}");
        assert!(text.contains("steady state is credential-free"), "{text}");
    }

    #[test]
    fn an_outstanding_credential_is_named_scoped_dated_and_never_valued() {
        let state = state(observation(Some(credential()), Publication::Absent));
        let text = rendered(&state);
        assert!(text.contains("CARGO_REGISTRY_TOKEN"), "{text}");
        assert!(text.contains("Actions repository secret"), "{text}");
        assert!(text.contains("2026-01-02T03:04:05Z"), "{text}");
        assert!(text.contains("never displayed"), "{text}");
        assert!(text.contains("not conformant until"), "{text}");
        assert!(text.contains("not observable"), "{text}");
    }

    #[test]
    fn the_external_step_says_leaving_is_expected_and_how_stale_the_reading_is() {
        let mut state = state(observation(Some(credential()), Publication::Absent));
        state.tick(Duration::from_secs(125));
        let text = rendered(&state);
        assert!(text.contains("external event"), "{text}");
        assert!(text.contains("leaving is expected"), "{text}");
        assert!(text.contains("2m 5s ago"), "{text}");
        assert!(
            state.status().starts_with("step 3 of 5"),
            "{}",
            state.status()
        );
    }

    #[test]
    fn the_position_is_stated_as_re_observed_rather_than_remembered() {
        let state = state(observation(None, Publication::Absent));
        assert!(
            state.status().contains("re-observed on entry"),
            "{}",
            state.status()
        );
        assert!(rendered(&state).contains("never remembered"));
    }

    #[test]
    fn supplying_a_value_reaches_confirmation_and_never_the_write_directly() {
        let mut state = state(observation(None, Publication::Absent));
        state.supply_secret().expect("the token step is live");
        assert!(state.accepts_secret());
        assert!(state.take_confirmation().is_none(), "entry is not consent");
        state.secret_input_changed(true);
        state.secret_supplied();
        assert!(!state.accepts_secret());
        let request = state.take_confirmation().expect("the named write");
        assert_eq!(request.secret, "CARGO_REGISTRY_TOKEN");
        assert_eq!(request.repo, "sample-repository");
        // One consent, one write.
        assert!(state.take_confirmation().is_none());
        assert!(state.applying());
    }

    #[test]
    fn a_dead_token_is_re_minted_by_setting_the_same_name_again() {
        let mut state = state(observation(Some(credential()), Publication::Absent));
        state.supply_secret().expect("re-minting is supported");
        let Entry::Secret { replacing, .. } = &state.entry else {
            panic!("the shared secret surface was expected");
        };
        assert!(*replacing);
        assert!(rendered(&state).contains("value will be replaced"));
    }

    #[test]
    fn the_secret_surface_renders_identically_whatever_was_typed() {
        let mut state = state(observation(None, Publication::Absent));
        state.supply_secret().expect("the token step is live");
        state.secret_input_changed(true);
        let held = drawn(&state);
        state.secret_input_changed(true);
        assert_eq!(held, drawn(&state));
        assert!(rendered(&state).contains("never displayed"));
    }

    #[test]
    fn a_registry_that_needs_no_ceremony_offers_no_secret_step() {
        let mut observed = observation(None, Publication::Absent);
        observed.unit.registry = Registry::PyPi;
        let mut state = state(observed);
        assert!(state.supply_secret().is_err());
        let text = rendered(&state);
        assert!(text.contains("NO CEREMONY ON THIS REGISTRY"), "{text}");
        assert!(text.contains("pending publisher"), "{text}");
    }

    #[test]
    fn the_container_path_draws_its_own_three_steps() {
        let mut observed = observation(None, Publication::Absent);
        observed.unit.registry = Registry::Ghcr;
        observed.container = Some(Container::Present {
            visibility: "private".to_owned(),
            repository: None,
        });
        let state = state(observed);
        let text = rendered(&state);
        assert!(text.contains("THE CONTAINER PATH"), "{text}");
        assert!(text.contains("Link it to this repository"), "{text}");
        assert!(!text.contains("OUTSTANDING CREDENTIAL"), "{text}");
        assert!(state
            .focused()
            .expect("a target")
            .container
            .as_ref()
            .is_some());
    }

    #[test]
    fn an_unread_registry_is_never_drawn_as_an_absent_package() {
        let state = state(observation(
            None,
            Publication::Undecided {
                reason: "the registry answered 503".to_owned(),
            },
        ));
        let text = rendered(&state);
        assert!(text.contains("not established"), "{text}");
        assert!(text.contains("not the same as absent"), "{text}");
    }

    #[test]
    fn emptiness_states_every_cause_it_cannot_distinguish() {
        let mut state = State::default();
        state.observe(observe());
        let text = rendered(&state);
        assert!(text.contains("in flight"), "{text}");
        state.observed(observe(), Vec::new());
        let text = rendered(&state);
        assert!(text.contains("declares no release units"), "{text}");
        assert!(text.contains("cannot tell them apart"), "{text}");
    }
}
