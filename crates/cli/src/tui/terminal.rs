//! Terminal lifecycle: taking the terminal, and giving it back on every exit
//! path.
//!
//! There are four ways out of the interface — a clean exit, an error, a panic,
//! and a signal — and a terminal left in raw mode on the alternate screen is a
//! shell the operator has to repair by hand. Each path is covered separately,
//! because none of them subsumes the others:
//!
//! * the clean and error paths by [`Session`]'s `Drop`;
//! * a panic by a hook installed ahead of the one already there, so the
//!   backtrace still prints, and on the normal terminal where it can be read;
//! * a signal by a handler that restores with async-signal-safe calls only and
//!   then re-raises with the default disposition, so the process still dies of
//!   what killed it and the exit status still says so.
//!
//! `ctrl-c` never reaches the signal path in practice: raw mode delivers it as
//! a key event, which the application treats as a clean exit. The handler is
//! there for the signal arriving from anywhere else.

use std::io::{self, Stdout, Write as _};

use anyhow::{Context as _, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand as _;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

/// The terminal, taken for the duration of the interface.
pub struct Session {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Session {
    /// Take the terminal: raw mode, the alternate screen, and no cursor.
    ///
    /// Installs the panic and signal restorers first, so there is no window in
    /// which the terminal is taken and nothing would give it back.
    pub fn take() -> Result<Self> {
        install_panic_hook();
        install_signal_handlers();
        enable_raw_mode().context("cannot put the terminal into raw mode")?;
        let mut out = io::stdout();
        out.execute(EnterAlternateScreen)
            .context("cannot enter the alternate screen")?;
        out.execute(Hide).context("cannot hide the cursor")?;
        let terminal =
            Terminal::new(CrosstermBackend::new(out)).context("cannot drive the terminal")?;
        Ok(Self { terminal })
    }

    /// The terminal to draw on.
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        restore();
    }
}

/// Give the terminal back. Safe to call more than once, and on a terminal that
/// was never taken.
pub fn restore() {
    let mut out = io::stdout();
    let _ = out.execute(LeaveAlternateScreen);
    let _ = out.execute(Show);
    let _ = disable_raw_mode();
    let _ = out.flush();
}

fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
    });
}

/// The escape sequences that undo the alternate screen and the hidden cursor.
///
/// Written as bytes because a signal handler may only call async-signal-safe
/// functions, and `write` is one while `println!` is not.
#[cfg(unix)]
const RESTORE_SEQUENCE: &[u8] = b"\x1b[?1049l\x1b[?25h\x1b[0m";

#[cfg(unix)]
mod signals {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The terminal settings as they were before raw mode.
    ///
    /// Written once, before any handler can run, and read only from a handler.
    /// A mutex here would risk deadlocking the handler against the thread it
    /// interrupted, so the value is a plain static guarded by a flag.
    static mut ORIGINAL: libc::termios = unsafe { std::mem::zeroed() };
    static SAVED: AtomicBool = AtomicBool::new(false);

    /// Record the current terminal settings so a handler can put them back.
    pub(super) fn save_terminal_settings() {
        // SAFETY: `tcgetattr` writes a `termios` through the pointer. This runs
        // once, on the main thread, before any handler is installed.
        unsafe {
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut ORIGINAL) == 0 {
                SAVED.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Undo the alternate screen, the hidden cursor, and raw mode, using only
    /// calls that are safe to make from a signal handler, then die of the
    /// signal that arrived.
    ///
    /// # Safety
    ///
    /// Called only as a signal handler.
    pub(super) extern "C" fn handle(signal: libc::c_int) {
        // SAFETY: every call below is async-signal-safe: `write`, `tcsetattr`,
        // `signal`, and `raise` are all on the POSIX list.
        unsafe {
            let sequence = super::RESTORE_SEQUENCE;
            libc::write(
                libc::STDOUT_FILENO,
                sequence.as_ptr().cast(),
                sequence.len(),
            );
            if SAVED.load(Ordering::SeqCst) {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const ORIGINAL);
            }
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }
}

#[cfg(unix)]
fn install_signal_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        signals::save_terminal_settings();
        // SAFETY: installs a handler that only calls async-signal-safe
        // functions and then re-raises with the default disposition.
        let handler: extern "C" fn(libc::c_int) = signals::handle;
        unsafe {
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(signal, handler as usize as libc::sighandler_t);
            }
        }
    });
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_a_terminal_that_was_never_taken_is_harmless() {
        restore();
        restore();
    }

    #[test]
    fn the_panic_hook_is_installed_once_however_often_it_is_asked_for() {
        install_panic_hook();
        install_panic_hook();
        install_signal_handlers();
        install_signal_handlers();
    }

    #[cfg(unix)]
    #[test]
    fn the_restore_sequence_undoes_what_taking_the_terminal_did() {
        let sequence = std::str::from_utf8(RESTORE_SEQUENCE).expect("the sequence is text");
        assert!(sequence.contains("[?1049l"), "leaves the alternate screen");
        assert!(sequence.contains("[?25h"), "shows the cursor");
    }
}
