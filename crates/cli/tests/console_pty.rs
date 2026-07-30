//! The console driven through a real pseudo-terminal, in a real child process.
//!
//! Everything else about the interface is provable in-process: the frame
//! renders into a buffer, key handling is a pure transition, and the failure and
//! panic restoration paths are observable where they are written. Two things are
//! not, and they are the two that leave an operator with a broken shell when
//! they are wrong:
//!
//! * a clean exit, where the binary must actually put the terminal back;
//! * a delivered signal, where the handler must put the terminal back using
//!   only async-signal-safe calls and then still die of the signal.
//!
//! Both are asserted here against the terminal itself — the line discipline read
//! back off the pty after the child is gone — rather than against the escape
//! bytes alone, because a program can emit the right sequence and still leave
//! the terminal in raw mode.
//!
//! Not automated, and why: the panic path cannot be reached from outside the
//! binary without a production-only failure injection hook, which would be a
//! test seam in a shipped surface. It is asserted in
//! `crates/cli/src/tui/terminal.rs` instead, where the panic can be raised
//! directly and the restoration observed. The panic, clean, and error paths all
//! run the same `restore`, and the signal path — the only one that does not — is
//! covered below.

#![cfg(unix)]

use std::ffi::CStr;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// The reference size, so the console draws its full frame.
const ROWS: u16 = 40;
const COLUMNS: u16 = 120;

/// Long enough for the child to draw, short enough to keep the suite quick.
const SETTLE: Duration = Duration::from_millis(600);

/// How long to wait for the child to leave before giving up on it.
const EXIT_BUDGET: Duration = Duration::from_secs(10);

/// Enters the alternate screen.
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h";
/// Leaves it again.
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[?1049l";
/// Shows the cursor.
const SHOW_CURSOR: &str = "\x1b[?25h";

/// A pseudo-terminal, held open from this side for as long as the test needs to
/// read the line discipline back.
struct Pty {
    controller: OwnedFd,
    device: OwnedFd,
}

impl Pty {
    fn open() -> Self {
        // SAFETY: the POSIX pty dance. Every returned descriptor is checked and
        // then owned by the returned value.
        unsafe {
            let controller = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(controller >= 0, "cannot open a pseudo-terminal");
            assert_eq!(libc::grantpt(controller), 0, "cannot grant the pty");
            assert_eq!(libc::unlockpt(controller), 0, "cannot unlock the pty");
            let name = libc::ptsname(controller);
            assert!(!name.is_null(), "the pty has no name");
            let name = CStr::from_ptr(name).to_owned();
            let device = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(device >= 0, "cannot open the pty device");

            let size = libc::winsize {
                ws_row: ROWS,
                ws_col: COLUMNS,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            assert_eq!(
                libc::ioctl(controller, libc::TIOCSWINSZ, &size),
                0,
                "cannot size the pty"
            );

            Self {
                controller: OwnedFd::from_raw_fd(controller),
                device: OwnedFd::from_raw_fd(device),
            }
        }
    }

    /// Start `airlock` with this pty as its controlling terminal, on all three
    /// standard descriptors, exactly as a shell would.
    fn spawn_console(&self) -> Child {
        self.spawn_console_in(&[])
    }

    /// Start the console with extra environment, as above.
    fn spawn_console_in(&self, environment: &[(&str, &std::path::Path)]) -> Child {
        let device = self.device.as_raw_fd();
        let mut command = Command::new(assert_cmd::cargo::cargo_bin("airlock"));
        command.env_remove("NO_COLOR");
        // Nowhere for the flow to reach: the loopback port the override names
        // refuses at once, so the console shows a polling interruption rather
        // than the suite talking to github.com.
        command.env("AIRLOCK_GITHUB_LOGIN_URL", "http://127.0.0.1:1");
        for (name, value) in environment {
            command.env(name, value);
        }
        // SAFETY: `pre_exec` runs between fork and exec. Every call here —
        // `setsid`, `ioctl`, `dup2`, `close` — is async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(device, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for target in 0..3 {
                    if libc::dup2(device, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if device > 2 {
                    libc::close(device);
                }
                Ok(())
            });
        }
        command.spawn().expect("the console starts")
    }

    fn write(&self, bytes: &[u8]) {
        // SAFETY: writing owned bytes to an owned descriptor.
        let written = unsafe {
            libc::write(
                self.controller.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        };
        assert_eq!(written, bytes.len() as isize, "cannot write to the pty");
    }

    /// Everything the child has written so far.
    ///
    /// The device stays open on this side, so reads never see end-of-file; the
    /// descriptor is set non-blocking and drained instead.
    fn drain(&self) -> String {
        // SAFETY: setting O_NONBLOCK on an owned descriptor.
        unsafe {
            let raw = self.controller.as_raw_fd();
            let flags = libc::fcntl(raw, libc::F_GETFL);
            libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut file = std::mem::ManuallyDrop::new(
            // SAFETY: wrapped only to reuse `Read`; the fd stays owned by self.
            unsafe { std::fs::File::from_raw_fd(self.controller.as_raw_fd()) },
        );
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(read) = file.read(&mut chunk) {
            if read == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Whether the terminal is in the cooked state a shell hands over.
    ///
    /// This is the assertion that matters: raw mode clears `ICANON` and `ECHO`,
    /// so seeing them set again means the line discipline was actually put back,
    /// not merely that the right bytes were printed.
    fn is_cooked(&self) -> bool {
        // SAFETY: `tcgetattr` writes a `termios` through the pointer.
        unsafe {
            let mut settings: libc::termios = std::mem::zeroed();
            assert_eq!(
                libc::tcgetattr(self.device.as_raw_fd(), &mut settings),
                0,
                "cannot read the terminal settings"
            );
            settings.c_lflag & libc::ICANON != 0 && settings.c_lflag & libc::ECHO != 0
        }
    }
}

fn wait_for(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + EXIT_BUDGET;
    loop {
        match child.try_wait().expect("the child can be waited on") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                panic!("the console did not leave within {EXIT_BUDGET:?}");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Start the console and wait until it has drawn its first frame.
fn started(pty: &Pty) -> (Child, String) {
    assert!(
        pty.is_cooked(),
        "the terminal starts cooked, so the assertions below mean something"
    );
    let child = pty.spawn_console();
    std::thread::sleep(SETTLE);
    let drawn = pty.drain();
    assert!(
        drawn.contains(ENTER_ALTERNATE_SCREEN),
        "the console did not take the terminal: {drawn:?}"
    );
    assert!(
        drawn.contains("AIRLOCK"),
        "the console drew no frame: {drawn:?}"
    );
    assert!(
        !pty.is_cooked(),
        "the console did not put the terminal into raw mode"
    );
    (child, drawn)
}

fn assert_restored(pty: &Pty, transcript: &str) {
    assert!(
        transcript.contains(LEAVE_ALTERNATE_SCREEN),
        "the alternate screen was not left: {transcript:?}"
    );
    assert!(
        transcript.contains(SHOW_CURSOR),
        "the cursor was not shown again: {transcript:?}"
    );
    assert!(
        pty.is_cooked(),
        "the terminal was left in raw mode, whatever was printed"
    );
}

#[test]
fn a_clean_exit_gives_the_terminal_back() {
    let pty = Pty::open();
    let (mut child, opening) = started(&pty);

    // `t` switches palette and `ctrl-c` leaves: in raw mode ctrl-c arrives as a
    // key, so this is the clean path rather than the signal path.
    pty.write(b"t");
    std::thread::sleep(SETTLE);
    let after_theme = pty.drain();
    assert!(
        after_theme.contains("theme t"),
        "the console redrew after the palette changed: {after_theme:?}"
    );

    pty.write(b"\x03");
    let status = wait_for(&mut child);
    let closing = pty.drain();

    assert_eq!(status.code(), Some(0), "a clean exit reports success");
    assert_eq!(status.signal(), None, "ctrl-c was a key, not a signal");
    assert_restored(&pty, &format!("{opening}{after_theme}{closing}"));
}

#[test]
fn a_delivered_signal_gives_the_terminal_back_and_still_kills_the_process() {
    let pty = Pty::open();
    let (mut child, opening) = started(&pty);

    // Not ctrl-c: a signal arriving from anywhere else, which raw mode does not
    // intercept. This is the handler's path.
    let pid = i32::try_from(child.id()).expect("a plausible pid");
    // SAFETY: signalling a child this process started and has not reaped.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0, "cannot signal");

    let status = wait_for(&mut child);
    let closing = pty.drain();

    assert_eq!(
        status.signal(),
        Some(libc::SIGINT),
        "the process still dies of what killed it, so the exit status says so"
    );
    assert_eq!(status.code(), None, "a signalled process has no exit code");
    assert_restored(&pty, &format!("{opening}{closing}"));
}

/// Every file under a directory, recursively.
fn contents(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut frontier = vec![root.to_path_buf()];
    while let Some(directory) = frontier.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                frontier.push(path.clone());
            }
            found.push(path);
        }
    }
    found
}

#[test]
fn a_whole_session_writes_no_file_anywhere() {
    // The write path's guarantee is that no credential is stored, under any
    // circumstance, in any location. The strongest available reading of that is
    // that a session creates no file at all: every place airlock could write to
    // is redirected into one empty directory, and it is still empty afterwards.
    let home = tempfile::tempdir().expect("a home to watch");
    let watched: &[(&str, &std::path::Path)] = &[
        ("HOME", home.path()),
        ("XDG_CONFIG_HOME", home.path()),
        ("XDG_DATA_HOME", home.path()),
        ("XDG_CACHE_HOME", home.path()),
        ("XDG_STATE_HOME", home.path()),
        ("TMPDIR", home.path()),
    ];
    assert!(
        contents(home.path()).is_empty(),
        "the directory starts empty"
    );

    let pty = Pty::open();
    let mut child = pty.spawn_console_in(watched);
    std::thread::sleep(SETTLE);
    let drawn = pty.drain();
    assert!(
        drawn.contains("AIRLOCK"),
        "the console drew no frame: {drawn:?}"
    );
    assert!(
        drawn.contains("POLLING INTERRUPTED") || drawn.contains("REQUESTING A DEVICE CODE"),
        "the device flow did not run: {drawn:?}"
    );

    pty.write(b"r");
    std::thread::sleep(SETTLE);
    let after = pty.drain();
    pty.write(b"\x03");
    let status = wait_for(&mut child);

    assert_eq!(status.code(), Some(0), "a clean exit reports success");
    assert_restored(&pty, &format!("{drawn}{after}{}", pty.drain()));
    assert_eq!(
        contents(home.path()),
        Vec::<std::path::PathBuf>::new(),
        "the session wrote something, and it may write nothing"
    );
}

#[test]
fn a_terminal_that_is_not_a_terminal_is_refused_without_taking_anything() {
    // The counterpart to the two above: the same binary, the same pty for
    // stdin, but stdout redirected away. The console must not take the terminal
    // at all.
    let pty = Pty::open();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("airlock"))
        .stdin(std::process::Stdio::from(
            pty.device.try_clone().expect("the device clones"),
        ))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the console starts");
    let status = wait_for(&mut child);
    assert_eq!(status.code(), Some(2), "the invocation is refused");
    assert!(
        pty.is_cooked(),
        "a refusal must not have touched the terminal"
    );
    assert!(
        !pty.drain().contains(ENTER_ALTERNATE_SCREEN),
        "a refusal must not have drawn anything"
    );
}
