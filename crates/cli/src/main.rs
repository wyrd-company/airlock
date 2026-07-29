//! The `airlock` binary.
//!
//! Everything here is read-only. The binary resolves a credential, proves it
//! carries no write permission, resolves a policy to immutable identities, and
//! runs the audit. It never mutates a repository, and it never writes anything
//! outside its own config file.

mod config;
mod credential;
mod device;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use airlock_core::audit::{self, AuditOptions};
use airlock_core::auth::{self, VerifiedGrant, AIRLOCK_SAFE_CLIENT_ID};
use airlock_core::github::{RestClient, RestClientConfig};
use airlock_core::limits::Limits;
use airlock_core::policy::{self, PolicySource};
use airlock_core::render;
use anyhow::{bail, Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::DEFAULT_PROFILE;
use crate::credential::{CredentialInputs, CredentialSelection};
use crate::device::{DeviceFlow, DeviceFlowConfig, GITHUB_LOGIN_BASE};

/// Exit code for an operational failure: authentication, network, policy
/// resolution, or an invocation that cannot do any work.
const EXIT_OPERATIONAL: u8 = 2;

/// The airlock version reported in every result.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Overrides the GitHub API host. Used by the test suite so no test can reach
/// the real api.github.com.
const API_URL_OVERRIDE: &str = "AIRLOCK_GITHUB_API_URL";

/// Overrides the GitHub OAuth host, for the same reason.
const LOGIN_URL_OVERRIDE: &str = "AIRLOCK_GITHUB_LOGIN_URL";

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
    /// List outstanding agent-lane work and check whether that lane is clear.
    AgentWork(AgentWorkArgs),
    /// Print what airlock would change, without changing anything.
    ///
    /// A display, not a work order. It observes the repository with the same
    /// read-only credential the audit uses, and prints the change each open
    /// gap calls for. Nothing reads its output back: aligning re-observes
    /// every rule before it acts, so there is no stored plan to apply.
    Plan(PlanArgs),
    /// Manage the read-only credential airlock uses.
    Auth(AuthArgs),
    /// Write the embedded repository-standards skill to a directory.
    Skill(SkillArgs),
}

#[derive(Debug, Args)]
struct SkillArgs {
    /// Directory to create.
    #[arg(default_value = "repository-standards")]
    target: PathBuf,

    /// Replace an existing target directory and all of its contents.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// Repository to audit, as `owner/repo`.
    #[arg(required_unless_present_any = ["list_checks", "working_tree"])]
    target: Option<String>,

    #[command(flatten)]
    repository: RepositoryArgs,

    /// Print the check registry and exit, without auditing anything.
    #[arg(long)]
    list_checks: bool,
}

#[derive(Debug, Args)]
struct AgentWorkArgs {
    /// Repository to inspect, as `owner/repo`.
    #[arg(required_unless_present = "working_tree")]
    target: Option<String>,

    #[command(flatten)]
    repository: RepositoryArgs,
}

/// Arguments for `airlock plan`.
///
/// Deliberately [`RepositoryArgs`] minus `--format`, which is why it does not
/// simply flatten it. The plan renders for a person to read and has no machine
/// form: a JSON plan would invite a pipeline to consume it, and a consumed
/// plan is a remembered observation. Machine consumers read the audit's
/// findings document, or `airlock agent-work` for the agent lane — both carry
/// the same `remediation_class` a plan is derived from.
#[derive(Debug, Args)]
struct PlanArgs {
    /// Repository to plan for, as `owner/repo`.
    #[arg(required_unless_present = "working_tree")]
    target: Option<String>,

    /// Policy source: `owner/repo:path[@ref]` or a local file path.
    ///
    /// Defaults to the audited owner's `.github` repository.
    #[arg(long)]
    policy: Option<String>,

    /// Plan against a specific commit, branch, or tag.
    #[arg(long = "ref", conflicts_with = "working_tree")]
    reference: Option<String>,

    /// Observe file-level rules from a local working tree instead of the
    /// API tree.
    #[arg(long)]
    working_tree: Option<PathBuf>,

    /// Read-only token value. Insecure: it appears in shell history and in
    /// process listings. Prefer --token-file or --token-stdin.
    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read the token from a file.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,

    /// Read the token from standard input.
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,

    /// Configuration profile to use.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
}

impl PlanArgs {
    /// The observation these arguments ask for.
    ///
    /// The plan reaches its report through the same single path every other
    /// read-only surface uses, which is what keeps "no headless surface can
    /// write" a property of the binary rather than a convention.
    fn repository(self) -> RepositoryArgs {
        RepositoryArgs {
            policy: self.policy,
            reference: self.reference,
            working_tree: self.working_tree,
            // A plan has no machine form; see the type's documentation.
            format: None,
            token: self.token,
            token_file: self.token_file,
            token_stdin: self.token_stdin,
            profile: self.profile,
        }
    }
}

#[derive(Debug, Args)]
struct RepositoryArgs {
    /// Policy source: `owner/repo:path[@ref]` or a local file path.
    ///
    /// Defaults to the audited owner's `.github` repository.
    #[arg(long)]
    policy: Option<String>,

    /// Audit at a specific commit, branch, or tag.
    #[arg(long = "ref", conflicts_with = "working_tree")]
    reference: Option<String>,

    /// Observe file-level rules from a local working tree instead of the
    /// API tree. With a repository and a credential, platform rules still
    /// come from the API; alone, platform rules are reported as not
    /// observed — never as passing.
    #[arg(long)]
    working_tree: Option<PathBuf>,

    /// Output format. Defaults to text on a terminal and json otherwise.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Read-only token value. Insecure: it appears in shell history and in
    /// process listings. Prefer --token-file or --token-stdin.
    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read the token from a file.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,

    /// Read the token from standard input.
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,

    /// Configuration profile to use.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
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
    Login(AuthLoginArgs),
    /// Report which credential source would be used, and what it grants.
    Status(AuthStatusArgs),
    /// Emit the verified token stored in a profile.
    Token(AuthTokenArgs),
}

#[derive(Debug, Args)]
struct AuthLoginArgs {
    /// Configuration profile to write.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
}

#[derive(Debug, Args)]
struct AuthStatusArgs {
    /// Configuration profile to inspect.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,

    /// Read-only token value to inspect instead of the stored profile.
    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read the token to inspect from a file.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,

    /// Read the token to inspect from standard input.
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,
}

#[derive(Debug, Args)]
struct AuthTokenArgs {
    /// Configuration profile to emit.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
}

fn main() -> ExitCode {
    restore_sigpipe_default();

    let cli = Cli::parse();
    let interactive = std::io::stdout().is_terminal();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("airlock could not start its runtime: {error}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };

    match runtime.block_on(run(cli, interactive)) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// Restore the Unix convention for writes to a pipe whose reader has exited.
///
/// Rust ignores `SIGPIPE`, which turns `println!` failures into panics. A CLI
/// should instead terminate silently with signal 13 (usually surfaced by a
/// shell as status 141): that preserves the fact that its output was
/// incomplete and covers every stdout/stderr writer, including clap.
/// The disposition is process-global and also applies to socket writes, so a
/// rare network `EPIPE` terminates via signal 13 rather than an exit-2 error;
/// that is the conventional trade-off accepted by Unix pipeline tools.
#[cfg(unix)]
fn restore_sigpipe_default() {
    // SAFETY: this runs before the runtime or any application threads exist,
    // and installs the operating system's default disposition for SIGPIPE.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_sigpipe_default() {}

async fn run(cli: Cli, interactive: bool) -> Result<u8> {
    let Some(command) = cli.command else {
        eprintln!("{}", bare_invocation_message(interactive));
        return Ok(EXIT_OPERATIONAL);
    };

    match command {
        Command::Audit(args) => audit_command(args, interactive).await,
        Command::AgentWork(args) => agent_work_command(args, interactive).await,
        Command::Plan(args) => plan_command(args).await,
        Command::Auth(AuthArgs {
            command: AuthCommand::Login(args),
        }) => login_command(&args).await,
        Command::Auth(AuthArgs {
            command: AuthCommand::Status(args),
        }) => status_command(&args).await,
        Command::Auth(AuthArgs {
            command: AuthCommand::Token(args),
        }) => token_command(&args).await,
        Command::Skill(args) => skill_command(&args),
    }
}

fn skill_command(args: &SkillArgs) -> Result<u8> {
    airlock_core::skill::emit(&args.target, args.force)
        .with_context(|| format!("cannot write skill to {}", args.target.display()))?;
    println!(
        "Wrote repository-standards skill from registry {} ({}) to {}.\n\
         Cite every rule by id and statement together; a rule id alone is not meaningful.",
        airlock_core::registry::REGISTRY_VERSION,
        airlock_core::registry::digest(),
        args.target.display()
    );
    Ok(0)
}

fn api_base() -> String {
    std::env::var(API_URL_OVERRIDE).unwrap_or_else(|_| RestClientConfig::default().base_url)
}

/// The client configuration for one run.
///
/// Built from the audit's budgets so the page, byte, and time limits the
/// checks reason about are the ones the client actually enforces.
fn client_config(limits: Limits) -> RestClientConfig {
    RestClientConfig {
        base_url: api_base(),
        ..RestClientConfig::from_limits(limits)
    }
}

fn login_base() -> String {
    std::env::var(LOGIN_URL_OVERRIDE).unwrap_or_else(|_| GITHUB_LOGIN_BASE.to_owned())
}

fn resolved_format(requested: Option<Format>, interactive: bool) -> Format {
    match requested {
        Some(format) => format,
        None if interactive => Format::Text,
        None => Format::Json,
    }
}

async fn audit_command(args: AuditArgs, interactive: bool) -> Result<u8> {
    let format = resolved_format(args.repository.format, interactive);

    if args.list_checks {
        match format {
            Format::Text => print!("{}", render::list_checks_text()),
            Format::Json => println!(
                "{}",
                serde_json::to_string_pretty(&render::list_checks_json())
                    .context("cannot render the check registry")?
            ),
        }
        return Ok(0);
    }

    let report = repository_report(args.target.as_deref(), &args.repository).await?;
    render_report(&report, format)?;
    Ok(report.exit_code())
}

async fn agent_work_command(args: AgentWorkArgs, interactive: bool) -> Result<u8> {
    let format = resolved_format(args.repository.format, interactive);
    let report = repository_report(args.target.as_deref(), &args.repository).await?;
    let list = airlock_core::worklist::AgentWorkList::from_report(&report);

    match format {
        Format::Text => print!("{}", render::agent_work_list_text(&list)),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&list)
                .context("cannot render the agent work-list document")?
        ),
    }

    Ok(list.exit_code())
}

/// `airlock plan`: the same observation, rendered as the changes it implies.
///
/// It exits 0 whenever it could observe and render at all. The plan is a
/// display, not a gate: `airlock audit` is the surface whose exit code carries
/// the verdict, and a second gate answering the same question slightly
/// differently is worse than no second gate.
async fn plan_command(args: PlanArgs) -> Result<u8> {
    let target = args.target.clone();
    let report = repository_report(target.as_deref(), &args.repository()).await?;

    print!("{}", render::plan_text(&report));
    Ok(0)
}

fn render_report(report: &airlock_core::findings::Report, format: Format) -> Result<()> {
    match format {
        Format::Text => print!("{}", render::report_text(report)),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(report).context("cannot render the findings document")?
        ),
    }
    Ok(())
}

async fn repository_report(
    target: Option<&str>,
    args: &RepositoryArgs,
) -> Result<airlock_core::findings::Report> {
    // A working tree with no repository target is a local-only audit: no
    // credential, no API, platform rules reported as not observed.
    if target.is_none() {
        let Some(root) = &args.working_tree else {
            bail!("a repository or working tree is required.");
        };
        return local_audit(args, root).await;
    }

    // Both absent returned above. There is no invocation that reaches here
    // without a target.
    let Some(target) = target else {
        bail!("a repository is required.");
    };
    let (owner, repo) = split_target(target)?;

    let inputs = CredentialInputs {
        token: args.token.clone(),
        token_file: args.token_file.clone(),
        token_stdin: args.token_stdin,
        profile: args.profile.clone(),
    };
    let config_path = config::config_path()?;
    let credential =
        credential::resolve(&inputs, &config_path, &login_base(), AIRLOCK_SAFE_CLIENT_ID).await?;

    let limits = Limits::default();
    let client = RestClient::new(credential.token.clone(), client_config(limits))
        .context("cannot build the github client")?;

    let grant = auth::verify(&credential.token, &client)
        .await
        .with_context(|| {
            format!(
                "the credential from {} was refused",
                credential.source.describe()
            )
        })?;

    let source = match &args.policy {
        Some(value) => {
            PolicySource::parse(value).with_context(|| format!("cannot read `--policy {value}`"))?
        }
        None => PolicySource::default_for_owner(owner),
    };
    let policy = policy::resolve(&client, &source, &limits)
        .await
        .with_context(|| format!("cannot resolve the policy at {}", source.label()))?;

    let options = AuditOptions {
        reference: args.reference.clone(),
        limits,
        version: VERSION.to_owned(),
        working_tree: args.working_tree.clone(),
    };
    let report = audit::run(&client, owner, repo, &policy, &options, Some(&grant))
        .await
        .with_context(|| format!("cannot audit {owner}/{repo}"))?;
    Ok(report)
}

/// A local-only audit: file rules from the working tree, platform rules not
/// observed. No credential is resolved and no request is made; the policy
/// must therefore be a local file with no remote references.
async fn local_audit(args: &RepositoryArgs, root: &Path) -> Result<airlock_core::findings::Report> {
    let Some(policy_arg) = &args.policy else {
        bail!(
            "a local-only audit has no credential to fetch a policy with. Name a local policy \
             file as `--policy ./policy.yml`."
        );
    };
    let source = PolicySource::parse(policy_arg)
        .with_context(|| format!("cannot read `--policy {policy_arg}`"))?;

    let limits = Limits::default();
    let offline = airlock_core::github::Offline;
    let policy = policy::resolve(&offline, &source, &limits)
        .await
        .with_context(|| {
            format!(
                "cannot resolve the policy at {} without a credential; a local-only audit needs \
                 a local policy with no remote references",
                source.label()
            )
        })?;

    let options = AuditOptions {
        reference: args.reference.clone(),
        limits,
        version: VERSION.to_owned(),
        working_tree: Some(root.to_path_buf()),
    };
    let report = audit::run_local(&policy, &options, root)
        .with_context(|| format!("cannot audit the working tree at {}", root.display()))?;
    Ok(report)
}

fn split_target(target: &str) -> Result<(&str, &str)> {
    match target.split_once('/') {
        Some((owner, repo)) if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') => {
            Ok((owner, repo))
        }
        _ => bail!("`{target}` is not a repository. Name one as `owner/repo`."),
    }
}

async fn login_command(args: &AuthLoginArgs) -> Result<u8> {
    let limits = Limits::default();
    let flow = DeviceFlow::new(
        AIRLOCK_SAFE_CLIENT_ID,
        DeviceFlowConfig {
            base_url: login_base(),
            connect_timeout: limits.connect_timeout,
            request_timeout: limits.request_timeout,
            ..DeviceFlowConfig::default()
        },
    )?;

    let codes = flow.request_codes().await?;
    println!(
        "Open {} and enter the code {}",
        codes.verification_uri, codes.user_code
    );
    println!("Waiting for the authorisation to complete.");

    let grant = flow.poll_until_granted(&codes).await?;

    // The credential is verified before it is stored: a token airlock would
    // refuse to use is not worth keeping on disk.
    let client = RestClient::new(grant.access_token.clone(), client_config(Limits::default()))
        .context("cannot build the github client")?;
    let verified = auth::verify(&grant.access_token, &client)
        .await
        .context("the credential GitHub issued was refused")?;

    let config_path = config::config_path()?;
    let _lock = config::RotationLock::acquire(&config_path, &args.profile)?;
    let mut stored = config::load(&config_path)?;
    credential::store_grant(&mut stored, &args.profile, &grant, verified.login.clone());
    config::store(&config_path, &stored)?;

    println!(
        "Stored the `{}` profile in {}.",
        args.profile,
        config_path.display()
    );
    print_grant(&verified);
    Ok(0)
}

async fn status_command(args: &AuthStatusArgs) -> Result<u8> {
    let inputs = CredentialInputs {
        token: args.token.clone(),
        token_file: args.token_file.clone(),
        token_stdin: args.token_stdin,
        profile: args.profile.clone(),
    };
    let environment = std::env::var(credential::TOKEN_ENVIRONMENT_VARIABLE).ok();
    let source = credential::selected_source(&inputs, environment.as_deref());
    println!("credential source: {}", source.describe());
    if source == CredentialSelection::Flag {
        println!(
            "note: --token appears in shell history and in process listings. Prefer \
             --token-file or --token-stdin."
        );
    }

    let config_path = config::config_path()?;
    println!("config: {}", config_path.display());
    println!("profile: {}", args.profile);

    let credential =
        credential::resolve(&inputs, &config_path, &login_base(), AIRLOCK_SAFE_CLIENT_ID).await?;

    let client = RestClient::new(credential.token.clone(), client_config(Limits::default()))
        .context("cannot build the github client")?;

    match auth::verify(&credential.token, &client).await {
        Ok(grant) => {
            println!("verified: yes");
            print_grant(&grant);
            Ok(0)
        }
        Err(refusal) => {
            println!("verified: no");
            eprintln!("{refusal}");
            Ok(EXIT_OPERATIONAL)
        }
    }
}

async fn token_command(args: &AuthTokenArgs) -> Result<u8> {
    let config_path = config::config_path()?;
    let credential = credential::resolve_profile(
        &args.profile,
        &config_path,
        &login_base(),
        AIRLOCK_SAFE_CLIENT_ID,
    )
    .await?;
    let client = RestClient::new(credential.token.clone(), client_config(Limits::default()))
        .context("cannot build the github client")?;
    auth::verify(&credential.token, &client)
        .await
        .with_context(|| {
            format!(
                "the credential from the `{}` profile was refused",
                args.profile
            )
        })?;

    println!("{}", credential.token);
    Ok(0)
}

fn print_grant(grant: &VerifiedGrant) {
    println!("token kind: {}", grant.kind.code());
    if let Some(issuer) = &grant.issuer {
        println!("issuer: {issuer}");
    }
    if let Some(login) = &grant.login {
        println!("login: {login}");
    }
    if !grant.scopes.is_empty() {
        println!("scopes: {}", grant.scopes.join(", "));
    }
    for installation in &grant.installations {
        println!(
            "installation {} on {}: {}",
            installation.id,
            installation.account.as_deref().unwrap_or("an account"),
            installation.permissions.join(", ")
        );
    }
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

    #[tokio::test]
    async fn bare_invocation_is_an_operational_error() {
        let cli = Cli::parse_from(["airlock"]);
        assert_eq!(run(cli, false).await.unwrap(), EXIT_OPERATIONAL);
    }

    #[test]
    fn bare_invocation_messages_differ_by_terminal() {
        assert_ne!(
            bare_invocation_message(true),
            bare_invocation_message(false)
        );
    }

    #[test]
    fn a_target_must_be_one_repository() {
        assert_eq!(split_target("owner/repo").unwrap(), ("owner", "repo"));
        for bad in ["owner", "/repo", "owner/", "owner/repo/extra", ""] {
            assert!(split_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_format_defaults_to_text_only_on_a_terminal() {
        assert!(matches!(resolved_format(None, true), Format::Text));
        assert!(matches!(resolved_format(None, false), Format::Json));
        assert!(matches!(
            resolved_format(Some(Format::Text), false),
            Format::Text
        ));
    }

    #[test]
    fn list_checks_needs_no_target() {
        let cli = Cli::parse_from(["airlock", "audit", "--list-checks"]);
        let Some(Command::Audit(args)) = cli.command else {
            panic!("expected the audit command");
        };
        assert!(args.list_checks);
        assert!(args.target.is_none());
    }

    #[test]
    fn auth_token_selects_a_named_profile() {
        let cli = Cli::parse_from(["airlock", "auth", "token", "--profile", "ci"]);
        let Some(Command::Auth(AuthArgs {
            command: AuthCommand::Token(args),
        })) = cli.command
        else {
            panic!("expected the auth token command");
        };
        assert_eq!(args.profile, "ci");
    }
}
