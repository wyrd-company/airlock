//! The interactive terminal interface.
//!
//! The interface has no subcommand and no flag. Bare `airlock` on an
//! interactive terminal is the only thing that starts it, and nothing starts it
//! headlessly, because the code path to do so does not exist. That is the
//! structural form of the boundary: an agent has nothing to invoke, and the
//! guarantee holds without a check declining to take the path.

mod app;
mod chrome;
mod lane;
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
use crate::admin::flow::{Authorizing, Report};
use crate::admin::session::SessionCredential;

/// How long the loop waits for a key before it looks at the clock again.
///
/// The sign-in screen counts a code's validity down and a backoff down, and a
/// countdown that only moves when a key is pressed is a countdown that lies.
const TICK: Duration = Duration::from_millis(250);

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
    let outcome = drive(&mut app, &mut session, &authorizing);
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
fn drive(app: &mut App, session: &mut terminal::Session, authorizing: &Authorizing) -> Result<u8> {
    let mut credential: Option<SessionCredential> = None;
    let mut last = Instant::now();
    loop {
        session
            .terminal()
            .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
            .context("cannot draw the interface")?;

        if event::poll(TICK).context("cannot wait on the terminal")? {
            match event::read().context("cannot read from the terminal")? {
                Event::Key(key) => match app.handle_key(key) {
                    Flow::Exit => return Ok(0),
                    Flow::Reissue => authorizing.reissue(),
                    Flow::Continue => {}
                },
                // A resize redraws on the next pass; everything else is not
                // bound.
                _ => continue,
            }
        }

        let now = Instant::now();
        app.tick(now.saturating_duration_since(last));
        last = now;

        // Everything the worker has to say, without waiting: the wait above is
        // the loop's only one.
        while let Some(report) = authorizing.next_report(Duration::ZERO) {
            match report {
                // The grant is taken here and the interface is only told that
                // one exists. `App::report` names no type that could carry it.
                Report::Granted(grant) => {
                    credential = Some(SessionCredential::from_device_grant(*grant));
                    app.authorization_granted();
                }
                Report::Progress(progress) => app.report(progress),
            }
        }
        // Held only so the credential's lifetime is this loop's. Nothing reads
        // it yet: the screens that would are the tasks after this one.
        let _ = &credential;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_names_the_requirement_and_what_to_run_instead() {
        let message = non_interactive_message();
        assert!(message.contains("interactive terminal"));
        assert!(message.contains("airlock audit"));
        assert!(message.contains("airlock agent-work"));
        assert!(message.contains("--help"));
    }
}
