//! Integration tests for the `airlock` binary.
//!
//! `assert_cmd` runs the binary as a subprocess, so stdout is a pipe rather
//! than a terminal — these exercise the non-interactive path.

use assert_cmd::Command;
use predicates::str::contains;

fn airlock() -> Command {
    Command::cargo_bin("airlock").expect("the airlock binary builds")
}

#[test]
fn bare_invocation_exits_two_and_says_why() {
    airlock()
        .assert()
        .code(2)
        .stderr(contains("TUI not yet available; use a subcommand."));
}

#[test]
fn help_lists_the_command_surface() {
    airlock()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("audit"))
        .stdout(contains("auth"));
}

#[test]
fn auth_help_lists_login_and_status() {
    airlock()
        .args(["auth", "--help"])
        .assert()
        .success()
        .stdout(contains("login"))
        .stdout(contains("status"));
}

#[test]
fn unimplemented_subcommands_exit_two() {
    for args in [
        vec!["audit", "wyrd-company/airlock"],
        vec!["auth", "status"],
        vec!["auth", "login"],
    ] {
        airlock()
            .args(&args)
            .assert()
            .code(2)
            .stderr(contains("not yet implemented"));
    }
}
