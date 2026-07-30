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
mod terminal;
mod theme;

#[cfg(test)]
mod snapshots;

use std::io::IsTerminal;

use anyhow::{Context as _, Result};
use crossterm::event::{self, Event};

use self::app::{App, Flow};
use self::theme::ColorMode;

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
    let mut session = terminal::Session::take()?;
    let outcome = drive(&mut app, &mut session);
    drop(session);
    outcome
}

fn drive(app: &mut App, session: &mut terminal::Session) -> Result<u8> {
    loop {
        session
            .terminal()
            .draw(|frame| app.render(frame.area(), frame.buffer_mut()))
            .context("cannot draw the interface")?;
        match event::read().context("cannot read from the terminal")? {
            Event::Key(key) => {
                if app.handle_key(key) == Flow::Exit {
                    return Ok(0);
                }
            }
            // A resize redraws on the next pass; everything else is not bound.
            _ => continue,
        }
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
