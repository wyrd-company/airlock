//! The write path's prohibitions, asserted against the artifact and the source.
//!
//! Everything here is a negative: what the binary does not contain, and what the
//! write path's source does not call. A negative is exactly what the credential
//! posture is — no store, no environment, no flag, no child process, no second
//! identity — and a passing behavioural test is not sufficient evidence for one,
//! because it only shows that the path nobody took today was not taken.
//!
//! # What these assertions are worth
//!
//! Two of them are proofs and the rest are tripwires, and the difference is
//! worth stating plainly rather than leaving a reader to assume the stronger
//! reading.
//!
//! **Proofs.** The identity binding is read out of the built binary: the bytes
//! that would be needed to accept the other app are not in the file, so no code
//! in it can. The credential type's shape is read out of its own declaration:
//! there is one constructor and it takes a device grant.
//!
//! **Tripwires.** The source scans below look for the calls that would store,
//! export, or resolve a credential, *by the names those calls have today*. They
//! catch a reintroduction, which is what they are for. They do not catch an
//! alias, a macro, a re-export under another name, or a helper in another
//! module that the write path calls into — and nothing that reads source text
//! could. Read them as "no one has put it back", not as "it cannot be put
//! back". The behavioural complement, and its own stated limits, is
//! `tests/console_pty.rs`.

use std::path::{Path, PathBuf};

/// Airlock Admin, the shipped write identity. Read only by the profile that
/// ships it; the other profile is asserted not to contain it.
#[cfg(not(feature = "test-identity"))]
const ADMIN_SLUG: &str = "airlock-admin";
const ADMIN_CLIENT_ID: &str = "Iv23li6LeVszqbchI9Ah";

/// Airlock Test, the development identity, installed on one account only.
const TEST_SLUG: &str = "airlock-test";
const TEST_CLIENT_ID: &str = "Iv23liTl9KRNwxjFhrfA";

fn binary() -> Vec<u8> {
    let path = assert_cmd::cargo::cargo_bin("airlock");
    std::fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn admin_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/admin")
}

/// Every Rust source file of the write path, as text.
fn write_path_sources() -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut frontier = vec![admin_source()];
    while let Some(directory) = frontier.pop() {
        for entry in std::fs::read_dir(&directory)
            .expect("the write path has a source directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                frontier.push(path);
            } else if path.extension().is_some_and(|kind| kind == "rs") {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_owned();
                found.push((name, std::fs::read_to_string(&path).expect("readable")));
            }
        }
    }
    assert!(!found.is_empty(), "the write path has sources to read");
    found
}

/// The write path's source, with its test modules and its prose removed.
///
/// A test may legitimately name a token or build a fixture path, and a comment
/// says what the code deliberately does not do — both would read as the thing
/// being forbidden. It is the shipped statements these assertions are about.
fn shipped_only(source: &str) -> String {
    let code = match source.find("#[cfg(test)]\nmod tests {") {
        Some(index) => &source[..index],
        None => source,
    };
    code.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[cfg(not(feature = "test-identity"))]
fn the_shipped_binary_cannot_accept_the_test_identity() {
    // The assertion is about the artifact, not about a configuration value: the
    // strings that would be needed to accept Airlock Test are not in the file at
    // all, so there is no code in it that could.
    let binary = binary();
    assert!(
        contains(&binary, ADMIN_SLUG),
        "the shipped binary is bound to Airlock Admin"
    );
    assert!(contains(&binary, ADMIN_CLIENT_ID));
    assert!(
        !contains(&binary, TEST_SLUG),
        "the shipped binary carries the test identity's slug"
    );
    assert!(
        !contains(&binary, TEST_CLIENT_ID),
        "the shipped binary carries the test identity's client id"
    );
}

#[test]
#[cfg(feature = "test-identity")]
fn a_test_build_is_bound_to_the_test_identity_and_not_to_the_shipped_one() {
    let binary = binary();
    assert!(contains(&binary, TEST_SLUG));
    assert!(contains(&binary, TEST_CLIENT_ID));
    assert!(
        !contains(&binary, ADMIN_CLIENT_ID),
        "a test build must not be able to reach the production identity"
    );
}

/// Tripwire: the write path names no credential-bearing environment variable.
#[test]
fn the_write_path_names_no_credential_environment_variable() {
    // The one exception is the OAuth host override, which is read here and is
    // honoured only for a loopback address — asserted where it is written.
    for (name, source) in write_path_sources() {
        let shipped = shipped_only(&source);
        for forbidden in [
            "AIRLOCK_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "std::env::var_os",
        ] {
            assert!(
                !shipped.contains(forbidden),
                "{name} names {forbidden}, and the write credential has one source"
            );
        }
        if name != "flow.rs" {
            assert!(
                !shipped.contains("std::env::var"),
                "{name} reads the environment"
            );
        }
    }
}

/// Tripwire: the write path calls nothing that writes a file.
#[test]
fn the_write_path_calls_nothing_that_writes_a_file() {
    for (name, source) in write_path_sources() {
        let shipped = shipped_only(&source);
        for forbidden in [
            "fs::write",
            "File::create",
            "OpenOptions",
            "create_dir",
            "BufWriter",
            "tempfile",
        ] {
            assert!(
                !shipped.contains(forbidden),
                "{name} writes to the filesystem, and this path stores nothing"
            );
        }
    }
}

/// Tripwire: the write path calls nothing that starts a process.
#[test]
fn the_write_path_calls_nothing_that_starts_a_child_process() {
    // A credential is never exported to a child process, and the reason it
    // cannot be is that the write path starts none. Opening the browser for the
    // operator would be the tempting exception, and it is deliberately absent.
    for (name, source) in write_path_sources() {
        let shipped = shipped_only(&source);
        for forbidden in ["process::Command", "Command::new", "exec("] {
            assert!(
                !shipped.contains(forbidden),
                "{name} starts a child process"
            );
        }
    }
}

/// Tripwire: the write path names nothing from the read path's resolver.
#[test]
fn the_write_path_names_nothing_from_the_read_paths_credential_resolver() {
    // `crate::credential` resolves a token from a flag, the environment, or the
    // stored profile. If any of it could be reached from here, "never stored"
    // would be a convention rather than a property.
    for (name, source) in write_path_sources() {
        let shipped = shipped_only(&source);
        for forbidden in [
            "crate::credential",
            "use crate::config",
            "credential::resolve",
            "CredentialInputs",
        ] {
            assert!(
                !shipped.contains(forbidden),
                "{name} can reach the read path's credential resolution"
            );
        }
    }
}

/// Tripwire: every server-supplied string leaves the worker sanitized.
///
/// A terminal is an interpreter, so a string GitHub chose is a program for it
/// unless something examines it first. The examination lives in `text.rs`, and
/// this asserts that the two places server data leaves the worker call it.
#[test]
fn every_server_supplied_string_leaves_the_worker_sanitized() {
    let flow = std::fs::read_to_string(admin_source().join("flow.rs"))
        .expect("the worker has a source file");
    let shipped = shipped_only(&flow);
    for constructed in [
        "user_code: text::sanitize(",
        "verification_uri: text::sanitize(",
    ] {
        assert!(
            shipped.contains(constructed),
            "{constructed} is missing: a code or an address reaches the interface raw"
        );
    }
    assert!(
        shipped.contains("fn cause(error: &anyhow::Error) -> String {")
            && shipped.contains("text::sanitize(&format!(\"{error:#}\"), CAUSE_LIMIT)"),
        "a reported cause reaches the interface raw"
    );
    assert!(
        shipped.contains("Progress::Interrupted(text::sanitize(&message, CAUSE_LIMIT))"),
        "a message GitHub chose reaches the interface raw"
    );

    // The second gate, in the state the screen renders: the state machine's
    // guarantee must not depend on which caller it has.
    let state = std::fs::read_to_string(admin_source().join("sign_in.rs"))
        .expect("the state machine has a source file");
    let state = shipped_only(&state);
    assert!(
        state.contains("text::sanitize(&issued.user_code, CODE_LIMIT)")
            && state.contains("text::sanitize(&issued.verification_uri, ADDRESS_LIMIT)")
            && state.contains("cause: text::sanitize(cause.as_ref(), CAUSE_LIMIT)"),
        "the state the screen renders trusts its caller"
    );
}

/// Proof: read out of the type's own declaration.
#[test]
fn the_session_credential_cannot_be_printed_or_copied() {
    let source = std::fs::read_to_string(admin_source().join("session.rs"))
        .expect("the credential has a source file");
    let declaration = source
        .find("pub struct SessionCredential")
        .expect("the credential is declared");
    let preceding = &source[..declaration];
    let derive = preceding
        .rfind("#[derive")
        .map(|index| preceding[index..].to_owned());
    assert_eq!(
        derive, None,
        "SessionCredential derives something; a value that can be formatted can be logged, \
         and one that can be cloned has more than one owner to reason about"
    );
    for forbidden in [
        "impl std::fmt::Debug for SessionCredential",
        "impl std::fmt::Display for SessionCredential",
        "impl Serialize for SessionCredential",
    ] {
        assert!(!source.contains(forbidden), "{forbidden} exists");
    }
    assert!(
        source.contains("impl Drop for SessionCredential"),
        "the credential must be cleared when it goes"
    );
}

/// Proof: read out of the type's own declaration.
#[test]
fn the_only_way_to_a_session_credential_is_a_device_grant() {
    let source = std::fs::read_to_string(admin_source().join("session.rs"))
        .expect("the credential has a source file");
    let shipped = shipped_only(&source);
    let constructors: Vec<&str> = shipped
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub fn") || line.starts_with("pub const fn"))
        .filter(|line| line.contains("-> Self") || line.contains("-> SessionCredential"))
        .collect();
    assert_eq!(
        constructors.len(),
        1,
        "there must be exactly one way in: {constructors:?}"
    );
    assert!(
        constructors[0].contains("from_device_grant(mut grant: TokenGrant)"),
        "the one way in is a device grant, by value: {}",
        constructors[0]
    );
    for forbidden in [
        "impl From<String> for SessionCredential",
        "impl FromStr for SessionCredential",
    ] {
        assert!(!source.contains(forbidden), "{forbidden} exists");
    }
}

#[test]
fn no_subcommand_or_flag_reaches_the_write_path() {
    // The console has no invocation of its own, so an agent holding this binary
    // has nothing to run that could acquire a write credential. Asserted against
    // the command surface the binary actually prints.
    let help = std::process::Command::new(assert_cmd::cargo::cargo_bin("airlock"))
        .arg("--help")
        .output()
        .expect("airlock prints its help");
    let help = String::from_utf8_lossy(&help.stdout).to_lowercase();
    // `align-files` and `agent-work` are the headless file lanes; neither holds
    // a write credential. What must not exist is anything naming the console or
    // the write path itself.
    for forbidden in ["airlock admin", "console", "tui", "sign-in", "signin"] {
        assert!(
            !help.contains(forbidden),
            "`{forbidden}` appears on the command surface"
        );
    }
}
