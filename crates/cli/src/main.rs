// ---
// relationships:
//   implements: terminal-interface
//   references: release-process-conformance
// ---

//! The `airlock` binary.
//!
//! Every GitHub surface here is read-only. The file-alignment command may
//! author deterministic content in a caller-supplied working tree, but it
//! never performs a git operation or holds a write credential.

mod admin;
mod config;
mod credential;
mod device;
mod tui;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use airlock_core::audit::{self, AuditOptions};
use airlock_core::auth::{self, Admission, VerifiedGrant, AIRLOCK_SAFE_CLIENT_ID};
use airlock_core::central::{self, CentralConfig, CentralInputs, Endpoints, OidcRequest};
use airlock_core::central_audit;
use airlock_core::github::{GitHub, RestClient, RestClientConfig};
use airlock_core::limits::Limits;
use airlock_core::policy::{self, PolicySource};
use airlock_core::render;
use airlock_core::transport::ReqwestTransport;
use airlock_core::workflow_token::ActionsRun;
use anyhow::{bail, Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

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

/// Overrides Entra ID's sign-in host, for the same reason.
const AZURE_LOGIN_URL_OVERRIDE: &str = "AIRLOCK_AZURE_LOGIN_URL";

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
    /// Author deterministic file fixes in a local working tree.
    AlignFiles(AlignFilesArgs),
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
struct AlignFilesArgs {
    /// Repository to use for read-only platform context.
    target: Option<String>,

    /// Local working tree to align.
    #[arg(long, required = true)]
    working_tree: PathBuf,

    /// Policy source. A local-only run requires a local policy.
    #[arg(long)]
    policy: Option<String>,

    /// Output format. Defaults to text on a terminal and JSON otherwise.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Read-only token value.
    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read the read-only token from a file.
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,

    /// Read the read-only token from standard input.
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,

    /// Configuration profile to use.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
}

impl AlignFilesArgs {
    fn repository(&self) -> RepositoryArgs {
        RepositoryArgs {
            policy: self.policy.clone(),
            reference: None,
            working_tree: Some(self.working_tree.clone()),
            format: self.format,
            token: self.token.clone(),
            token_file: self.token_file.clone(),
            token_stdin: self.token_stdin,
            profile: self.profile.clone(),
        }
    }
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// Repository to audit, as `owner/repo`.
    #[arg(required_unless_present_any = ["list_rules", "working_tree"])]
    target: Option<String>,

    #[command(flatten)]
    repository: RepositoryArgs,

    /// Print the rules and exit, without auditing anything.
    #[arg(long)]
    list_rules: bool,

    /// How the Airlock Action runs this audit.
    ///
    /// `repository` admits the run's own `GITHUB_TOKEN`, inside GitHub
    /// Actions only, for the run's repository only, and only when the job's
    /// declared permissions are all `read`. Without it, an installation token
    /// is refused.
    ///
    /// `central` takes an owner rather than a repository, accepts no
    /// credential, and signs in as Airlock Safe through Azure Key Vault with
    /// the job's OpenID Connect token. It audits every repository the
    /// installation reaches into one report.
    #[arg(long, value_enum, conflicts_with = "working_tree")]
    mode: Option<AuditMode>,

    #[command(flatten)]
    central: CentralArgs,
}

/// The Action's modes, as `--mode` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AuditMode {
    /// One repository, with the run's own token.
    Repository,
    /// Every repository of an owner, signed in as Airlock Safe.
    Central,
}

/// Central mode's inputs, as the audit repository's `airlock-safe`
/// environment holds them.
#[derive(Debug, Args, Default)]
struct CentralArgs {
    /// Central mode: Airlock Safe's App id (`AIRLOCK_SAFE_APP_ID`).
    #[arg(long)]
    app_id: Option<String>,

    /// Central mode: the Key Vault key holding the App's private key
    /// (`AIRLOCK_SAFE_KEY_NAME`).
    #[arg(long)]
    key_name: Option<String>,

    /// Central mode: every repository the installation may reach, which is
    /// `<owner>/*` (`AIRLOCK_SAFE_INSTALLED_ON`).
    #[arg(long)]
    installation_repositories: Option<String>,

    /// Central mode: the vault's `https://` address (`AZURE_KEY_VAULT_URL`).
    #[arg(long)]
    vault_url: Option<String>,

    /// Central mode: the Entra ID tenant (`AZURE_TENANT_ID`).
    #[arg(long)]
    azure_tenant_id: Option<String>,

    /// Central mode: the client id of the identity that trusts the job
    /// (`AZURE_CLIENT_ID`).
    #[arg(long)]
    azure_client_id: Option<String>,
}

impl CentralArgs {
    fn any(&self) -> bool {
        [
            &self.app_id,
            &self.key_name,
            &self.installation_repositories,
            &self.vault_url,
            &self.azure_tenant_id,
            &self.azure_client_id,
        ]
        .iter()
        .any(|value| value.is_some())
    }

    fn inputs(&self) -> CentralInputs {
        let value = |field: &Option<String>| field.clone().unwrap_or_default();
        CentralInputs {
            app_id: value(&self.app_id),
            key_name: value(&self.key_name),
            installation_repositories: value(&self.installation_repositories),
            vault_url: value(&self.vault_url),
            azure_tenant_id: value(&self.azure_tenant_id),
            azure_client_id: value(&self.azure_client_id),
        }
    }
}

#[derive(Debug, Args)]
struct AgentWorkArgs {
    /// Repository to inspect, as `owner/repo`.
    #[arg(required_unless_present = "working_tree")]
    target: Option<String>,

    #[command(flatten)]
    repository: RepositoryArgs,
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
    let interactive = std::io::stdout().is_terminal();
    configure_sigpipe(interactive);
    let cli = Cli::parse();

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

/// Use the Unix pipeline convention only when standard output is not a terminal.
///
/// Rust ignores `SIGPIPE`, which turns `println!` failures into panics. A CLI
/// should instead terminate silently with signal 13 (usually surfaced by a
/// shell as status 141): that preserves the fact that its output was
/// incomplete and covers every stdout/stderr writer, including clap. The
/// disposition is process-global, though, so the long-lived terminal session
/// keeps Rust's inherited `SIG_IGN`; socket `EPIPE` then remains an ordinary
/// transport error that can be reported without killing the process.
fn configure_sigpipe(interactive: bool) {
    if !interactive {
        restore_sigpipe_default();
    }
}

#[cfg(unix)]
fn restore_sigpipe_default() {
    // SAFETY: startup calls this before Airlock creates its runtime or performs
    // application work.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_sigpipe_default() {}

async fn run(cli: Cli, interactive: bool) -> Result<u8> {
    let Some(command) = cli.command else {
        return bare_invocation(interactive);
    };

    match command {
        Command::Audit(args) => audit_command(args, interactive).await,
        Command::AgentWork(args) => agent_work_command(args, interactive).await,
        Command::AlignFiles(args) => align_files_command(args, interactive).await,
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
        "Wrote repository-standards skill from rules {} ({}) to {}.\n\
         Cite every rule by id and statement together; a rule id alone is not meaningful.",
        airlock_core::rules::RULES_VERSION,
        airlock_core::rules::digest(),
        args.target.display()
    );
    Ok(0)
}

#[derive(Debug, Serialize)]
struct ReobservedFinding {
    rule: String,
    status: String,
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct PullRequestContext {
    state: String,
    branch: String,
    detail: String,
    url: Option<String>,
}

#[derive(Debug, Serialize)]
struct AlignFilesOutput {
    schema_version: u32,
    operations: airlock_core::alignment::AuthorReport,
    reobserved: Option<Vec<ReobservedFinding>>,
    pull_request: PullRequestContext,
    default_branch_observation: String,
}

async fn align_files_command(args: AlignFilesArgs, interactive: bool) -> Result<u8> {
    let format = resolved_format(args.format, interactive);
    let repository = args.repository();
    let observed = repository_report_with_client(args.target.as_deref(), &repository, None).await?;
    let pull_request = observe_pull_request(
        args.target.as_deref(),
        observed.report.repository.default_branch.as_str(),
        observed.client.as_ref(),
    )
    .await;
    let authored = match airlock_core::alignment::author(&args.working_tree, &observed.report) {
        Ok(report) => report,
        Err(airlock_core::Error::Alignment { message, report }) => {
            let operations = serde_json::from_str(&report)
                .context("cannot recover the file-alignment failure report")?;
            let output = AlignFilesOutput {
                schema_version: 1,
                operations,
                reobserved: None,
                pull_request,
                default_branch_observation: format!(
                    "The default-branch observation for `{}` stays open until the pull request \
                     merges.",
                    observed.report.repository.default_branch
                ),
            };
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&output)
                        .context("cannot render the file-alignment failure document")?
                ),
                Format::Text => {
                    eprintln!("{message}");
                    render_alignment_text(&output);
                }
            }
            return Ok(EXIT_OPERATIONAL);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot align {}", args.working_tree.display()));
        }
    };
    let after = repository_report(args.target.as_deref(), &repository).await?;

    let affected: std::collections::BTreeSet<_> = authored
        .operations
        .iter()
        .map(|operation| operation.rule.as_str())
        .collect();
    let reobserved = after
        .entries()
        .filter(|finding| affected.contains(finding.rule.as_str()))
        .map(|finding| ReobservedFinding {
            rule: finding.rule.clone(),
            status: finding.status_code().to_owned(),
            source: finding.source.clone(),
        })
        .collect();
    let output = AlignFilesOutput {
        schema_version: 1,
        operations: authored,
        reobserved: Some(reobserved),
        pull_request,
        default_branch_observation: format!(
            "The default-branch observation for `{}` stays open until the pull request merges.",
            after.repository.default_branch
        ),
    };

    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .context("cannot render the file-alignment document")?
        ),
        Format::Text => render_alignment_text(&output),
    }
    Ok(0)
}

fn render_alignment_text(output: &AlignFilesOutput) {
    println!(
        "working tree: {} (dirty before: {}, dirty after: {})",
        output.operations.working_tree,
        dirty_label(output.operations.dirty_before),
        dirty_label(output.operations.dirty_after)
    );
    for operation in &output.operations.operations {
        println!(
            "{} {} [{} / {}]{}",
            operation.outcome,
            operation.path,
            operation.rule,
            operation.fix_code,
            operation
                .reason
                .as_ref()
                .map(|reason| format!(": {reason}"))
                .unwrap_or_default()
        );
    }
    if let Some(findings) = &output.reobserved {
        for finding in findings {
            println!(
                "re-observed {}: {} ({})",
                finding.rule,
                finding.status,
                finding.source.as_deref().unwrap_or("not-observed")
            );
        }
    } else {
        println!("re-observation: not run because authoring stopped after a path failure");
    }
    println!(
        "pull request: {} on `{}` — {}",
        output.pull_request.state, output.pull_request.branch, output.pull_request.detail
    );
    println!("{}", output.default_branch_observation);
    if !output.operations.judgment_findings.is_empty() {
        println!(
            "agent fixes: {} finding(s); emit the repository-standards skill and hand them to an agent.",
            output.operations.judgment_findings.len()
        );
    }
}

async fn observe_pull_request(
    target: Option<&str>,
    base: &str,
    client: Option<&RestClient>,
) -> PullRequestContext {
    const BRANCH: &str = "airlock/align";
    let unknown = |detail: String| PullRequestContext {
        state: "unknown".to_owned(),
        branch: BRANCH.to_owned(),
        detail,
        url: None,
    };
    let Some(target) = target else {
        return unknown("no API repository target or credential was supplied".to_owned());
    };
    let Ok((owner, repo)) = split_target(target) else {
        return unknown("the repository target is invalid".to_owned());
    };
    let Some(client) = client else {
        return unknown("the verified read-only GitHub client is unavailable".to_owned());
    };
    match client.open_pull_requests(owner, repo, BRANCH, base).await {
        Ok(pulls) if pulls.is_empty() => PullRequestContext {
            state: "none".to_owned(),
            branch: BRANCH.to_owned(),
            detail: format!("no open pull request targets `{base}` from the well-known branch"),
            url: None,
        },
        Ok(pulls) => PullRequestContext {
            state: "open".to_owned(),
            branch: BRANCH.to_owned(),
            detail: format!(
                "pull request #{} already targets `{base}`; the caller should not open a duplicate",
                pulls[0].number
            ),
            url: Some(pulls[0].url.clone()),
        },
        Err(error) => unknown(format!(
            "read-only pull-request observation failed: {error}"
        )),
    }
}

fn dirty_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
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

    if args.list_rules {
        match format {
            Format::Text => print!("{}", render::list_rules_text()),
            Format::Json => println!(
                "{}",
                serde_json::to_string_pretty(&render::list_rules_json())
                    .context("cannot render the rules")?
            ),
        }
        return Ok(0);
    }

    if args.mode == Some(AuditMode::Central) {
        return central_command(&args, format).await;
    }
    if args.central.any() {
        bail!("the central inputs (--app-id and the rest) apply only to `--mode central`.");
    }

    let report = repository_report_with_client(args.target.as_deref(), &args.repository, args.mode)
        .await?
        .report;
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
    Ok(repository_report_with_client(target, args, None)
        .await?
        .report)
}

struct RepositoryObservation {
    report: airlock_core::findings::Report,
    client: Option<RestClient>,
}

async fn repository_report_with_client(
    target: Option<&str>,
    args: &RepositoryArgs,
    mode: Option<AuditMode>,
) -> Result<RepositoryObservation> {
    // A working tree with no repository target is a local-only audit: no
    // credential, no API, platform rules reported as not observed.
    if target.is_none() {
        let Some(root) = &args.working_tree else {
            bail!("a repository or working tree is required.");
        };
        return Ok(RepositoryObservation {
            report: local_audit(args, root).await?,
            client: None,
        });
    }

    // Both absent returned above. There is no invocation that reaches here
    // without a target.
    let Some(target) = target else {
        bail!("a repository is required.");
    };
    let (owner, repo) = split_target(target)?;

    // Repository mode is a fact about where Airlock runs, so it is settled
    // before any credential is read.
    let run = match mode {
        Some(AuditMode::Repository) => Some(
            ActionsRun::from_lookup(|name| std::env::var(name).ok())
                .context("repository mode was refused")?,
        ),
        Some(AuditMode::Central) => bail!("central mode audits an owner, not one repository."),
        None => None,
    };

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

    // The reference an installation token is compared with. It is read only
    // in repository mode, never sent anywhere, and overwritten when dropped.
    let run_token = run.as_ref().and_then(|_| {
        std::env::var(credential::RUN_TOKEN_ENVIRONMENT_VARIABLE)
            .ok()
            .map(zeroize::Zeroizing::new)
    });
    let admission = match &run {
        Some(run) => Admission::Repository {
            run,
            owner,
            repo,
            run_token: run_token.as_ref().map(|token| token.as_str()),
        },
        None => Admission::Standard,
    };
    let grant = auth::verify_for(&credential.token, &client, admission)
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
    Ok(RepositoryObservation {
        report,
        client: Some(client),
    })
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

/// Central mode: sign in as Airlock Safe and audit every repository of the
/// owner into one report.
async fn central_command(args: &AuditArgs, format: Format) -> Result<u8> {
    let Some(owner) = args.target.as_deref() else {
        bail!("central mode needs the owner to audit.");
    };
    if owner.contains('/') {
        bail!("central mode audits an owner, not `{owner}`. Name the owner alone.");
    }
    if args.repository.reference.is_some() {
        bail!("central mode audits each repository's default branch; `--ref` does not apply.");
    }

    // Central mode signs for itself, so a credential offered to it is one it
    // would have to ignore, and ignoring a credential is how a run ends up on
    // the wrong one.
    let environment = std::env::var(credential::TOKEN_ENVIRONMENT_VARIABLE).ok();
    let offered = args.repository.token.is_some()
        || args.repository.token_file.is_some()
        || args.repository.token_stdin
        || environment.is_some_and(|value| !value.trim().is_empty());
    if offered {
        bail!(
            "central mode accepts no credential: it signs in as Airlock Safe through Key Vault. \
             Remove --token, --token-file, --token-stdin and {}.",
            credential::TOKEN_ENVIRONMENT_VARIABLE
        );
    }

    let stopped = |error: central::CentralError| anyhow::anyhow!("central mode stopped at {error}");
    let config = CentralConfig::parse(owner, &args.central.inputs()).map_err(stopped)?;
    let oidc = OidcRequest::from_lookup(|name| std::env::var(name).ok()).map_err(stopped)?;
    // Every input that can be refused is read before a token exists, so no
    // early return can leave a minted token unrevoked.
    let policy_source = match &args.repository.policy {
        Some(value) => Some(
            PolicySource::parse(value)
                .with_context(|| format!("cannot read `--policy {value}`"))?,
        ),
        None => None,
    };
    let endpoints = Endpoints {
        github_api: api_base(),
        azure_login: std::env::var(AZURE_LOGIN_URL_OVERRIDE)
            .unwrap_or_else(|_| central::AZURE_LOGIN_BASE.to_owned()),
    };
    let limits = Limits::default();
    let options = AuditOptions {
        reference: None,
        limits,
        version: VERSION.to_owned(),
        working_tree: None,
    };
    let client_config = client_config(limits);
    let transport = ReqwestTransport::new(limits.connect_timeout)
        .map_err(|error| anyhow::anyhow!("central mode stopped at inputs: {error}"))?;
    let session = central::sign_in(
        &config,
        &oidc.into(),
        &endpoints,
        limits,
        Arc::new(transport),
    )
    .await
    .map_err(stopped)?;

    // From the minted token to its revocation nothing returns early: the
    // audit and its rendering are collected first, as text, and printed only
    // after the token is revoked.
    let result = central_audit::run(&session, owner, &client_config, policy_source, &options).await;
    let outcome: std::result::Result<(String, u8), String> = match result {
        Ok(report) => match format {
            Format::Text => Ok((report.text(), report.exit_code())),
            Format::Json => serde_json::to_string_pretty(&report)
                .map(|json| (format!("{json}\n"), report.exit_code()))
                .map_err(|error| format!("cannot render the central report: {error}")),
        },
        Err(error) => Err(format!("cannot audit the repositories of {owner}: {error}")),
    };

    // A failed revocation leaves a read-only token to expire on its own,
    // which is worth saying and not worth failing an audit that completed.
    if let Err(error) = session.revoke().await {
        eprintln!("warning: {}", session.redact(&error.to_string()));
    }

    // Whatever central mode prints passes through the session's redaction
    // last, so an echo of its token that got past every other guard prints
    // as `[redacted]`.
    match outcome {
        Ok((rendered, code)) => {
            print!("{}", session.redact(&rendered));
            Ok(code)
        }
        Err(message) => bail!("{}", session.redact(&message)),
    }
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
    if let Some(run) = &grant.run {
        println!(
            "job {} of {} in {}: {}",
            run.job,
            run.workflow,
            run.repository,
            run.permissions.join(", ")
        );
    }
}

/// What a bare `airlock` does.
///
/// This is the whole entry point to the interactive console, and it is the only
/// one. There is no subcommand for it and no flag that makes it run headlessly,
/// so an agent holding this binary has nothing to invoke: the guarantee is the
/// absence of the code path rather than a check declining to take it.
///
/// Off a terminal it exits non-zero without rendering anything at all. A
/// scheduler that captured a half-drawn alternate screen would be worse served
/// than one that captured an error naming what to run instead.
fn bare_invocation(interactive: bool) -> Result<u8> {
    if !interactive || !tui::is_interactive() {
        eprintln!("{}", tui::non_interactive_message());
        return Ok(EXIT_OPERATIONAL);
    }
    tui::run(VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_surface_is_valid() {
        Cli::command().debug_assert();
    }

    #[cfg(unix)]
    #[test]
    fn the_tui_entry_path_leaves_sigpipe_ignored() {
        // SAFETY: this test changes and restores the process disposition while
        // no application thread exists. `configure_sigpipe(true)` must be a
        // no-op so the TUI retains the Rust runtime's ignored disposition.
        unsafe {
            let original = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            configure_sigpipe(true);
            let disposition = libc::signal(libc::SIGPIPE, original);
            assert_eq!(disposition, libc::SIG_IGN);
        }
    }

    #[tokio::test]
    async fn a_bare_invocation_off_a_terminal_is_an_operational_error() {
        let cli = Cli::parse_from(["airlock"]);
        assert_eq!(run(cli, false).await.unwrap(), EXIT_OPERATIONAL);
    }

    #[test]
    fn no_subcommand_and_no_flag_reaches_the_interface() {
        // The console has no invocation of its own. If one is ever added, this
        // fails, because the boundary is that there is nothing to invoke.
        let command = Cli::command();
        for subcommand in command.get_subcommands() {
            let name = subcommand.get_name();
            assert!(
                !name.contains("tui") && !name.contains("console"),
                "{name} would give an agent something to invoke"
            );
        }
        for argument in command.get_arguments() {
            let name = argument.get_id().as_str();
            assert!(
                !name.contains("tui") && !name.contains("interactive"),
                "{name} would make the console reachable by flag"
            );
        }
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
    fn list_rules_needs_no_target() {
        let cli = Cli::parse_from(["airlock", "audit", "--list-rules"]);
        let Some(Command::Audit(args)) = cli.command else {
            panic!("expected the audit command");
        };
        assert!(args.list_rules);
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
