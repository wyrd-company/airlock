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

/// Restores the terminal when dropped, whether or not acquisition ever
/// finished.
///
/// Acquisition is several fallible calls, and the first of them already
/// mutates the terminal. Arming this before that first call is what closes the
/// window in which a later failure would return an error over a terminal left
/// half-taken: every path out after the guard exists — `?`, panic, or a clean
/// return — unwinds through it.
struct Restorer;

impl Drop for Restorer {
    fn drop(&mut self) {
        restore();
    }
}

/// The terminal, taken for the duration of the interface.
pub struct Session {
    // Declared before the restorer, and therefore dropped before it: the
    // backend flushes what it holds onto the alternate screen before the
    // alternate screen is left.
    terminal: Terminal<CrosstermBackend<Stdout>>,
    // Held for its `Drop` and nothing else.
    _restorer: Restorer,
}

impl Session {
    /// Take the terminal: raw mode, the alternate screen, and no cursor.
    ///
    /// The panic and signal restorers are installed first, and the drop
    /// restorer is armed before the first call that changes anything, so there
    /// is no instant at which the terminal is altered and nothing would give it
    /// back.
    pub fn take() -> Result<Self> {
        Self::take_with(acquire)
    }

    /// The ordering under test: whatever `acquire` does, and however it fails,
    /// it runs inside the guard.
    fn take_with(
        acquire: impl FnOnce() -> Result<Terminal<CrosstermBackend<Stdout>>>,
    ) -> Result<Self> {
        install_panic_hook();
        install_signal_handlers();
        let restorer = Restorer;
        let terminal = acquire()?;
        Ok(Self {
            terminal,
            _restorer: restorer,
        })
    }

    /// The terminal to draw on.
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }
}

/// Every call that changes the terminal, in order.
fn acquire() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("cannot put the terminal into raw mode")?;
    let mut out = io::stdout();
    out.execute(EnterAlternateScreen)
        .context("cannot enter the alternate screen")?;
    out.execute(Hide).context("cannot hide the cursor")?;
    Terminal::new(CrosstermBackend::new(out)).context("cannot drive the terminal")
}

/// Give the terminal back. Safe to call more than once, and on a terminal that
/// was never taken, which is what lets the guard be armed before the first
/// change rather than after it.
pub fn restore() {
    let mut out = io::stdout();
    let _ = out.execute(LeaveAlternateScreen);
    let _ = out.execute(Show);
    let _ = disable_raw_mode();
    let _ = out.flush();
    #[cfg(test)]
    RESTORES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// How many times the terminal has been given back.
///
/// Recorded only under test, where it is the one observable that distinguishes
/// "the failure path restored" from "the failure path returned an error".
#[cfg(test)]
static RESTORES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
        // functions and then re-raises with the default disposition. SIGPIPE
        // is deliberately absent: the terminal entry path keeps it ignored so
        // socket EPIPE is reported as a transport error, while non-interactive
        // invocations restore SIGPIPE before they can enter this module.
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
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    /// Restorations are counted process-wide, so the tests that read the count
    /// take turns.
    static COUNTING: Mutex<()> = Mutex::new(());

    fn restorations() -> usize {
        RESTORES.load(Ordering::SeqCst)
    }

    #[test]
    fn restoring_a_terminal_that_was_never_taken_is_harmless() {
        let _turn = COUNTING.lock().expect("the counting lock");
        restore();
        restore();
    }

    #[test]
    fn a_failure_part_way_through_taking_the_terminal_still_gives_it_back() {
        let _turn = COUNTING.lock().expect("the counting lock");
        let before = restorations();
        let outcome = Session::take_with(|| {
            // Stands for any of the calls after raw mode is enabled: the
            // alternate screen, the cursor, or constructing the terminal.
            anyhow::bail!("the alternate screen refused")
        });
        assert!(outcome.is_err(), "the failure is reported");
        assert_eq!(
            restorations(),
            before + 1,
            "the guard was armed before the first change, so the failure restored"
        );
    }

    #[test]
    fn a_panic_gives_the_terminal_back_before_the_backtrace_prints() {
        let _turn = COUNTING.lock().expect("the counting lock");
        install_panic_hook();
        let before = restorations();
        let outcome = std::panic::catch_unwind(|| panic!("the interface came apart"));
        assert!(outcome.is_err(), "the panic is a panic");
        assert!(
            restorations() > before,
            "the hook restored on the way out; the previous hook then printed"
        );
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
