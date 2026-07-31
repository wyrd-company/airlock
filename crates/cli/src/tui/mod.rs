//! The interactive terminal interface.
//!
//! The interface has no subcommand and no flag. Bare `airlock` on an
//! interactive terminal is the only thing that starts it, and nothing starts it
//! headlessly, because the code path to do so does not exist. That is the
//! structural form of the boundary: an agent has nothing to invoke, and the
//! guarantee holds without a check declining to take the path.

mod app;
mod bootstrap;
mod chrome;
mod detail;
mod findings;
mod lane;
mod organizations;
mod panel;
mod policy;
mod remediation;
mod repositories;
mod screen;
mod sign_in;
mod terminal;
mod theme;

#[cfg(test)]
mod snapshots;

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use crossterm::event::{self, Event};

use self::app::{App, Flow};
use self::theme::ColorMode;
use crate::admin::catalogue::{self, Reading};
use crate::admin::flow::{Authorizing, Report};
use crate::admin::remediation::{
    Request as WorkerRequest, Response as WorkerResponse, SecretEntry, SecretInputAction,
    SecretOperation, SecretValue, Target, Working,
};
use crate::admin::session::SessionCredential;
use crate::admin::text::{self, CAUSE_LIMIT};

/// How long the loop waits for a key before it looks at the clock again.
///
/// The sign-in screen counts a code's validity down and a backoff down, and a
/// countdown that only moves when a key is pressed is a countdown that lies.
const TICK: Duration = Duration::from_millis(250);

/// Drawable consumers implement only these value-free state notifications.
/// The shared controller below owns every key and paste decision, so another
/// secret-bearing screen does not add a second routing path.
trait SecretInputHost {
    fn secret_input_active(&self) -> bool;
    fn secret_input_changed(&mut self, holding_input: bool);
    fn secret_empty_refused(&mut self);
    fn secret_supplied(&mut self);
}

impl SecretInputHost for App {
    fn secret_input_active(&self) -> bool {
        self.accepts_secret()
    }

    fn secret_input_changed(&mut self, holding_input: bool) {
        Self::secret_input_changed(self, holding_input);
    }

    fn secret_empty_refused(&mut self) {
        Self::secret_empty_refused(self);
    }

    fn secret_supplied(&mut self) {
        Self::secret_supplied(self);
    }
}

fn route_secret_input(
    host: &mut impl SecretInputHost,
    entry: &mut SecretEntry,
    event: Event,
) -> SecretInputAction {
    let action = entry.handle_terminal_event(event);
    match &action {
        SecretInputAction::Changed { holding_input } => {
            host.secret_input_changed(*holding_input);
        }
        SecretInputAction::RefusedEmpty => host.secret_empty_refused(),
        SecretInputAction::Submit(_) => host.secret_supplied(),
        SecretInputAction::Cancel | SecretInputAction::Exit | SecretInputAction::Ignored => {}
    }
    action
}

/// Whether both halves of the terminal are interactive.
///
/// Both are required, and for different reasons: the interface reads keys from
/// stdin and paints the alternate screen on stdout. A pipe on either one means
/// the invocation cannot work, so it is refused rather than half-attempted.
#[must_use]
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// What is printed, and exited with, when the interface is asked for without a
/// terminal.
///
/// It names the requirement and the surfaces that do work unattended, so a
/// workflow that invoked it wrongly is told what to invoke instead. Nothing is
/// rendered first: a scheduler capturing a half-drawn alternate screen is worse
/// than a scheduler capturing an error.
#[must_use]
pub const fn non_interactive_message() -> &'static str {
    "airlock requires an interactive terminal. Bare `airlock` opens the \
     release-readiness console and will not run under a pipe, a redirect, or a \
     scheduler. For unattended use run `airlock audit <owner/repo>` for the \
     complete findings surface, or `airlock agent-work <owner/repo>` for the \
     agent lane, and `airlock --help` for the rest."
}

/// Run the interface until the operator leaves it.
///
/// The caller has already established that the terminal is interactive.
pub fn run(version: &str) -> Result<u8> {
    let mut app = App::new(version, ColorMode::from_env());
    // The device flow starts before the terminal is taken, so a failure to
    // start it is an ordinary error on an ordinary terminal rather than one
    // printed into an alternate screen that is about to be torn down.
    let authorizing = Authorizing::start(&crate::admin::flow::login_base())?;
    let mut session = terminal::Session::take()?;
    let outcome = drive(&mut app, &mut session, authorizing);
    drop(session);
    outcome
}

/// The loop.
///
/// The credential lives here and nowhere else. It is never handed to [`App`],
/// which is what draws: a value the renderer cannot reach cannot be rendered,
/// and that is a stronger guarantee than a renderer that remembers not to.
///
/// It is dropped, and zeroized, when this function returns — on the clean path,
/// on the error path, and on the panic that unwinds through it.
fn drive(app: &mut App, session: &mut terminal::Session, authorizing: Authorizing) -> Result<u8> {
    // Held in an `Option` because a lapse ends one device flow and starts
    // another: the worker returns once it has sent a grant, so re-authorizing
    // is a new flow rather than a request made to a thread that has finished.
    let mut authorizing = Some(authorizing);
    let mut credential: Option<SessionCredential> = None;
    // The one reader of the credential. It is started from the grant and owns
    // the only client built from it, so the token is spent at the boundary
    // rather than carried around by anything that draws.
    let mut reading: Option<Reading> = None;
    let mut working: Option<Working> = None;
    // Secret bytes live here, beside the credential and outside `App`, which
    // is the complete drawable/snapshot model.
    let mut secret_entry = SecretEntry::default();
    let mut supplied_secret: Option<SecretValue> = None;
    let mut last = Instant::now();
    loop {
        session
            .terminal()
            .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
            .context("cannot draw the interface")?;

        if event::poll(TICK).context("cannot wait on the terminal")? {
            let event = event::read().context("cannot read from the terminal")?;
            if app.secret_input_active() {
                match route_secret_input(app, &mut secret_entry, event) {
                    SecretInputAction::Changed { .. } | SecretInputAction::RefusedEmpty => {}
                    SecretInputAction::Submit(value) => {
                        supplied_secret = Some(value);
                    }
                    SecretInputAction::Cancel => {
                        supplied_secret = None;
                        let _ = app.handle_key(crossterm::event::KeyEvent::new(
                            crossterm::event::KeyCode::Esc,
                            crossterm::event::KeyModifiers::NONE,
                        ));
                    }
                    SecretInputAction::Exit => return Ok(0),
                    SecretInputAction::Ignored => {}
                }
                continue;
            }
            match event {
                Event::Paste(value) => {
                    app.handle_paste(&value);
                    continue;
                }
                Event::Key(key) => {
                    if key.code == crossterm::event::KeyCode::Esc {
                        supplied_secret = None;
                    }
                    match app.handle_key(key) {
                        Flow::Exit => return Ok(0),
                        Flow::Reissue => reissue(app, &mut authorizing),
                        // The interface says what it would like the terminal to
                        // hold; the terminal is owned here, so the asking happens
                        // here. A terminal that ignores it says nothing back, and
                        // nothing here claims it complied.
                        Flow::Copy(value) => offer_to_clipboard(&value),
                        Flow::Continue => {}
                    }
                }
                // A resize redraws on the next pass; everything else is not
                // bound.
                _ => continue,
            }
        }

        let now = Instant::now();
        app.tick(now.saturating_duration_since(last));
        last = now;

        // Taken before anything the workers have to say is applied: a report
        // that arrives from the flow that authorized the session it is ending
        // is dropped with it rather than adopted.
        if discard_session(
            app,
            &mut authorizing,
            &mut credential,
            &mut reading,
            &mut working,
            &mut secret_entry,
            &mut supplied_secret,
        ) {
            reissue(app, &mut authorizing);
        }

        // Everything the worker has to say, without waiting: the wait above is
        // the loop's only one.
        while let Some(report) = authorizing
            .as_ref()
            .and_then(|worker| worker.next_report(Duration::ZERO))
        {
            match report {
                // The grant is taken here and the interface is only told that
                // one exists. `App::report` names no type that could carry it.
                Report::Granted(grant) => {
                    let session = SessionCredential::from_device_grant(*grant);
                    // The validity, and nothing else: what the interface is
                    // told is how long GitHub said this grant is good for.
                    app.authorization_granted(session.validity());
                    // Started from the credential rather than given it: what
                    // the worker keeps is a client, and the interface is told
                    // only that a read is in flight.
                    match Reading::start(&session) {
                        Ok(started) => reading = Some(started),
                        Err(error) => app.catalogue_read(catalogue::Read::Failed(text::sanitize(
                            &format!("{error:#}"),
                            CAUSE_LIMIT,
                        ))),
                    }
                    match Working::start(&session, env!("CARGO_PKG_VERSION")) {
                        Ok(started) => working = Some(started),
                        Err(error) => app.operation_failed(text::sanitize(
                            &format!("cannot start the remediation worker: {error:#}"),
                            CAUSE_LIMIT,
                        )),
                    }
                    credential = Some(session);
                }
                Report::Progress(progress) => app.report(progress),
            }
        }

        // The catalogue read, on the same terms: everything it has, without
        // waiting, because the wait above is the loop's only one.
        //
        // A read can be the thing that discovers the lapse, and the reports
        // queued behind it were produced under the same lapsed grant. The drain
        // stops at the boundary rather than emptying the queue past it: the
        // worker is dropped below, and nothing it had in hand is applied.
        if let Some(worker) = reading.as_ref() {
            while let Some(read) = worker.next_report(Duration::ZERO) {
                app.catalogue_read(read);
                if app.reauthorizing_now() {
                    break;
                }
            }
        }
        if discard_session(
            app,
            &mut authorizing,
            &mut credential,
            &mut reading,
            &mut working,
            &mut secret_entry,
            &mut supplied_secret,
        ) {
            reissue(app, &mut authorizing);
            continue;
        }

        if let (Some(worker), Some(observe)) = (working.as_ref(), app.take_observation_request()) {
            if let Err(error) = worker.request(WorkerRequest::Observe(Target {
                owner: observe.owner,
                repo: observe.name,
            })) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        if let (Some(worker), Some((observe, remediation))) =
            (working.as_ref(), app.take_preparation_request())
        {
            if let Err(error) = worker.request(WorkerRequest::Prepare {
                target: Target {
                    owner: observe.owner,
                    repo: observe.name,
                },
                remediation,
            }) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        if let (Some(worker), Some(request)) = (working.as_ref(), app.take_remediation_request()) {
            let target = Target {
                owner: request.owner,
                repo: request.repo,
            };
            let work = if request.items.len() == 1 {
                let item = request.items.into_iter().next().expect("one item");
                let argument = item.argument();
                let variable = item.variable_rename();
                let secret = item.secret_rename();
                if let Some(secret) = secret.filter(|_| {
                    matches!(
                        item.remediation.as_str(),
                        "rename-app-credentials" | "rename-task-named-credentials"
                    )
                }) {
                    let Some(value) = supplied_secret.take() else {
                        app.operation_failed(
                            "no request was made because the supplied secret value is no longer available"
                                .to_owned(),
                        );
                        continue;
                    };
                    WorkerRequest::ApplyWithSecret {
                        target,
                        rule: item.rule,
                        remediation: item.remediation,
                        operation: SecretOperation::RenameCredentials { variable, secret },
                        value,
                    }
                } else {
                    WorkerRequest::Apply {
                        target,
                        rule: item.rule,
                        remediation: item.remediation,
                        argument,
                    }
                }
            } else {
                WorkerRequest::ApplyGroup {
                    target,
                    requests: request
                        .items
                        .into_iter()
                        .map(|item| {
                            let action =
                                crate::admin::remediation::Action::for_code(&item.remediation)
                                    .expect("bulk items are structurally input-free actions");
                            (item.rule, action)
                        })
                        .collect(),
                }
            };
            if let Err(error) = worker.request(work) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        if let (Some(worker), Some(observe)) =
            (working.as_ref(), app.take_bootstrap_observation_request())
        {
            if let Err(error) = worker.request(WorkerRequest::ObserveBootstrap(Target {
                owner: observe.owner,
                repo: observe.name,
            })) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        // The bootstrap's step 2, on the same terms as every other secret-bearing
        // write: the value is taken here, beside the credential, and is consumed
        // only by the write the operator has just confirmed by name.
        if let (Some(worker), Some(request)) = (working.as_ref(), app.take_bootstrap_request()) {
            let Some(value) = supplied_secret.take() else {
                app.operation_failed(
                    "no request was made because the supplied secret value is no longer available"
                        .to_owned(),
                );
                continue;
            };
            if let Err(error) = worker.request(WorkerRequest::ApplyWithSecret {
                target: Target {
                    owner: request.owner,
                    repo: request.repo,
                },
                rule: "publishing-bootstrap".to_owned(),
                remediation: "set-publishing-bootstrap-secret".to_owned(),
                operation: SecretOperation::SetRepositorySecret {
                    name: request.secret,
                },
                value,
            }) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        if let (Some(worker), Some(request)) = (working.as_ref(), app.take_undo_request()) {
            if let Err(error) = worker.request(WorkerRequest::Undo {
                target: Target {
                    owner: request.owner,
                    repo: request.repo,
                },
                rule: request.rule,
                remediation: request.remediation,
                undo: request.undo,
                expected: request.expected,
            }) {
                app.operation_failed(text::sanitize(&format!("{error:#}"), CAUSE_LIMIT));
            }
        }
        if let Some(worker) = working.as_ref() {
            while let Some(response) = worker.next_response() {
                match response {
                    WorkerResponse::Observed { target, report } => {
                        let observe = catalogue::Observe {
                            owner: target.owner,
                            name: target.repo,
                        };
                        app.observed(&observe, "this session", report.outcome.code());
                        app.observed_run(&report, &Default::default());
                    }
                    WorkerResponse::BootstrapObserved {
                        target,
                        observations,
                    } => app.bootstrap_observed(
                        catalogue::Observe {
                            owner: target.owner,
                            name: target.repo,
                        },
                        observations,
                    ),
                    WorkerResponse::Prepared { remediation, input } => {
                        app.remediation_prepared(&remediation, input)
                    }
                    WorkerResponse::Applied { target, transcript } => {
                        app.remediation_complete(transcript);
                        if let Err(error) = worker.request(WorkerRequest::Observe(target)) {
                            app.operation_failed(text::sanitize(
                                &format!("{error:#}"),
                                CAUSE_LIMIT,
                            ));
                        }
                    }
                    WorkerResponse::GroupApplied {
                        target,
                        transcripts,
                    } => {
                        app.remediation_group_complete(transcripts);
                        if let Err(error) = worker.request(WorkerRequest::Observe(target)) {
                            app.operation_failed(text::sanitize(
                                &format!("{error:#}"),
                                CAUSE_LIMIT,
                            ));
                        }
                    }
                    WorkerResponse::Failed(cause) => app.operation_failed(cause),
                }
                // The same boundary, for the same reason: an observation, a
                // transcript, or a set of choices produced under a grant that
                // has since lapsed is not evidence of anything, and the queue
                // behind this response is full of exactly that.
                if app.reauthorizing_now() {
                    break;
                }
            }
        }
        if discard_session(
            app,
            &mut authorizing,
            &mut credential,
            &mut reading,
            &mut working,
            &mut secret_entry,
            &mut supplied_secret,
        ) {
            reissue(app, &mut authorizing);
            continue;
        }

        // Held so the credential's lifetime is this loop's, and so it is
        // dropped — and zeroized — however this function returns.
        let _ = &credential;
    }
}

/// End the session a lapse ended, if one has been asked for.
///
/// The credential and everything built from it are dropped here — and a
/// `SessionCredential` zeroizes when it drops — so the boundary is a credential
/// ceasing to exist rather than one being renewed. Nothing is refreshed and
/// nothing was stored; what follows is another device approval.
///
/// Dropping the two workers is also what makes the boundary absolute in the
/// other direction. Each owns a queue of answers produced under the lapsed
/// grant, and dropping the receiver is what stops those answers reaching a
/// screen: there is no path by which a stale observation can be applied,
/// because there is nothing left to read one from.
///
/// `true` when a session was ended, which is the caller's cue to start the loop
/// again rather than go on servicing workers that no longer exist.
fn discard_session(
    app: &mut App,
    authorizing: &mut Option<Authorizing>,
    credential: &mut Option<SessionCredential>,
    reading: &mut Option<Reading>,
    working: &mut Option<Working>,
    secret_entry: &mut SecretEntry,
    supplied_secret: &mut Option<SecretValue>,
) -> bool {
    if !app.take_reauthorization_request() {
        return false;
    }
    *reading = None;
    *working = None;
    *credential = None;
    *authorizing = None;
    // Secret input is session state even though it is deliberately not
    // drawable state. Erase both forms at the same boundary as the grant so a
    // fresh authorization cannot inherit bytes entered under the lapsed one.
    secret_entry.clear();
    drop(supplied_secret.take());
    true
}

/// Ask for a device code, starting a flow where the last one has finished.
///
/// A worker returns once it has sent a grant, so the flow that authorized the
/// session cannot be asked for a replacement: a lapse needs a new one. A
/// failure to start it is reported on the overlay as an interruption rather
/// than ending the session, and `r` asks again.
fn reissue(app: &mut App, authorizing: &mut Option<Authorizing>) {
    if let Some(worker) = authorizing.as_ref() {
        worker.reissue();
        return;
    }
    match Authorizing::start(&crate::admin::flow::login_base()) {
        Ok(started) => *authorizing = Some(started),
        Err(error) => app.report(crate::admin::flow::Progress::Interrupted(text::sanitize(
            &format!("the device flow could not be started again: {error:#}"),
            CAUSE_LIMIT,
        ))),
    }
}

/// Offer a value to the terminal's clipboard.
///
/// The terminal's own facility, because the binary shells out to nothing: no
/// `xclip`, no `pbcopy`, no child process of any kind. The request is written
/// to the terminal and there is no reply to read, so this reports nothing and
/// swallows nothing that matters — a terminal that does not implement the
/// sequence ignores it, and the value is on the screen in full regardless.
///
/// Only a rule id and the registry digest ever reach here. No credential is on
/// any screen, so none can be copied off one.
fn offer_to_clipboard(value: &str) {
    use base64::Engine as _;
    use std::io::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    let mut out = std::io::stdout();
    // A failure to write is not reported: the interface never claimed the
    // terminal took it, and a torn-down clipboard request is not a reason to
    // interrupt a session.
    let _ = write!(out, "\u{1b}]52;c;{encoded}\u{7}");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Host {
        active: bool,
        holding: bool,
        refused: bool,
        supplied: bool,
    }

    impl SecretInputHost for Host {
        fn secret_input_active(&self) -> bool {
            self.active
        }

        fn secret_input_changed(&mut self, holding_input: bool) {
            self.holding = holding_input;
        }

        fn secret_empty_refused(&mut self) {
            self.refused = true;
        }

        fn secret_supplied(&mut self) {
            self.supplied = true;
        }
    }

    #[test]
    fn the_refusal_names_the_requirement_and_what_to_run_instead() {
        let message = non_interactive_message();
        assert!(message.contains("interactive terminal"));
        assert!(message.contains("airlock audit"));
        assert!(message.contains("airlock agent-work"));
        assert!(message.contains("--help"));
    }

    #[test]
    fn shared_secret_routing_needs_only_a_value_free_host() {
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
        let mut host = Host {
            active: true,
            ..Host::default()
        };
        let mut entry = SecretEntry::default();
        assert!(matches!(
            route_secret_input(
                &mut host,
                &mut entry,
                Event::Paste("opaque-input".to_owned())
            ),
            SecretInputAction::Changed {
                holding_input: true
            }
        ));
        assert!(host.holding);
        assert!(matches!(
            route_secret_input(
                &mut host,
                &mut entry,
                Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            ),
            SecretInputAction::Submit(_)
        ));
        assert!(host.supplied);
    }

    /// The bootstrap's own state composes with the same boundary.
    ///
    /// Its placement is a reading of a repository and its step-2 input is a
    /// value the operator supplied, so a lapse must leave neither behind: the
    /// screen comes back saying it has observed nothing, and the entry buffer
    /// the driver owns is erased with the grant.
    #[test]
    fn lapse_discards_the_bootstrap_placement_and_its_supplied_value() {
        use crate::admin::bootstrap::{Observation, Publication, Publisher, Registry, Unit};
        use crate::admin::catalogue::Observe;

        let mut app = App::new("0.0.0", ColorMode::NoColor);
        app.authorization_granted(crate::admin::session::Validity::Unstated);
        let target = Observe {
            owner: "generic-owner".to_owned(),
            name: "sample-repository".to_owned(),
        };
        app.bootstrap_observed(
            target,
            vec![Observation {
                unit: Unit {
                    package: "sample-package".to_owned(),
                    registry: Registry::CratesIo,
                },
                credential: None,
                publication: Publication::Absent,
                publisher: Publisher::Unobservable {
                    reason: "gated on crate ownership".to_owned(),
                },
                container: None,
            }],
        );
        assert!(app.bootstrap_placement().is_some());

        let mut secret_entry = SecretEntry::default();
        for character in "bootstrap-token".chars() {
            secret_entry.push(character);
        }
        let mut supplied_secret = secret_entry.take();
        let mut authorizing = None;
        let mut credential = None;
        let mut reading = None;
        let mut working = None;

        app.lapse();
        assert!(discard_session(
            &mut app,
            &mut authorizing,
            &mut credential,
            &mut reading,
            &mut working,
            &mut secret_entry,
            &mut supplied_secret,
        ));
        assert!(
            app.bootstrap_placement().is_none(),
            "a placement observed under a lapsed grant survived"
        );
        assert!(supplied_secret.is_none(), "the supplied value survived");
        assert!(secret_entry.take().is_none(), "partial input survived");
    }

    #[test]
    fn lapse_discards_secret_input_before_a_fresh_authorization() {
        let mut app = App::new("0.0.0", ColorMode::NoColor);
        app.authorization_granted(crate::admin::session::Validity::Unstated);

        let mut secret_entry = SecretEntry::default();
        for character in "prior-prefix".chars() {
            secret_entry.push(character);
        }
        let mut pending = SecretEntry::default();
        for character in "prior-submission".chars() {
            pending.push(character);
        }
        let mut supplied_secret = pending.take();
        let mut authorizing = None;
        let mut credential = None;
        let mut reading = None;
        let mut working = None;

        app.lapse();
        assert!(discard_session(
            &mut app,
            &mut authorizing,
            &mut credential,
            &mut reading,
            &mut working,
            &mut secret_entry,
            &mut supplied_secret,
        ));
        assert!(secret_entry.take().is_none(), "partial input survived");
        assert!(supplied_secret.is_none(), "submitted input survived");

        app.authorization_granted(crate::admin::session::Validity::Unstated);
        for character in "fresh-value".chars() {
            secret_entry.push(character);
        }
        let submitted = secret_entry.take().expect("fresh input submits");
        assert_eq!(submitted.test_bytes(), b"fresh-value");
    }
}
