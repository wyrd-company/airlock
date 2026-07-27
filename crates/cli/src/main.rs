//! The `airlock` binary.
//!
//! The command line surface is defined here in full; the audit itself is not
//! yet wired up. Subcommands that are declared but not implemented exit 2 with
//! a message naming what is missing, so the surface is honest about its own
//! state rather than silently succeeding.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit code for an operational failure: authentication, network, policy
/// resolution, or an invocation that cannot do any work.
const EXIT_OPERATIONAL: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    version,
    about = "Audit a GitHub repository against a release-readiness policy"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit a repository against a policy.
    Audit(AuditArgs),
    /// Manage the read-only credential airlock uses.
    Auth(AuthArgs),
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// Repository to audit, as `owner/repo`.
    target: String,

    /// Policy source: `owner/repo:path[@ref]` or a local file path.
    #[arg(long)]
    policy: Option<String>,

    /// Output format. Defaults to text on a terminal and json otherwise.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Read-only token value.
    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read the token from a file.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<std::path::PathBuf>,

    /// Read the token from standard input.
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,

    /// Configuration profile to use.
    #[arg(long)]
    profile: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// Human-readable output.
    Text,
    /// The findings document as a single JSON object.
    Json,
}

#[derive(Debug, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Acquire a read-only credential through the device flow.
    Login,
    /// Report which credential source would be used, and what it grants.
    Status,
}

fn main() -> ExitCode {
    match run(Cli::parse(), std::io::stdout().is_terminal()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn run(cli: Cli, interactive: bool) -> anyhow::Result<u8> {
    let Some(command) = cli.command else {
        eprintln!("{}", bare_invocation_message(interactive));
        return Ok(EXIT_OPERATIONAL);
    };

    let unimplemented = match command {
        Command::Audit(_) => "audit",
        Command::Auth(AuthArgs {
            command: AuthCommand::Login,
        }) => "auth login",
        Command::Auth(AuthArgs {
            command: AuthCommand::Status,
        }) => "auth status",
    };

    eprintln!("airlock {unimplemented} is not yet implemented");
    Ok(EXIT_OPERATIONAL)
}

/// What to say when `airlock` is run with no subcommand.
///
/// There is no interactive mode yet, so a bare invocation can never do work.
/// It says so and exits 2 either way; on a terminal it also points at the help.
fn bare_invocation_message(interactive: bool) -> &'static str {
    if interactive {
        "airlock has no interactive mode yet. Run a subcommand — \
         `airlock audit <owner/repo>` — or `airlock --help` to see them all."
    } else {
        "TUI not yet available; use a subcommand."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_surface_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_is_an_operational_error() {
        let cli = Cli::parse_from(["airlock"]);
        assert_eq!(run(cli, false).unwrap(), EXIT_OPERATIONAL);
    }

    #[test]
    fn bare_invocation_messages_differ_by_terminal() {
        assert_ne!(
            bare_invocation_message(true),
            bare_invocation_message(false)
        );
    }
}
