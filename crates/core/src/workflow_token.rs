//! Repository mode: the run's own `GITHUB_TOKEN`.
//!
//! GitHub offers no way to list an installation token's permissions, so a
//! `ghs_` token is unverifiable everywhere else in Airlock. The run's
//! `GITHUB_TOKEN` is the exception, because its whole grant is written down:
//! it holds exactly the permissions of the job that runs, and those are in
//! the workflow file GitHub ran. Airlock reads that file at
//! `GITHUB_WORKFLOW_SHA` through the API, finds the job named by
//! `GITHUB_JOB`, and accepts the token only when every permission it states
//! is `read`.
//!
//! The enumeration holds only inside Actions and only for the repository the
//! token was issued for, so both are required before anything is read.

use crate::auth::{Refusal, RefusalCode, RunGrant, TokenKind, VerifiedGrant};
use crate::github::GitHub;
use crate::limits::YamlLimits;
use crate::yaml::{self, Yaml};

/// The environment variables that describe the run, as GitHub sets them.
pub const ACTIONS_VARIABLES: &[&str] = &[
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_JOB",
];

/// The run Airlock is executing in, as GitHub Actions describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionsRun {
    /// `owner/repo` the run, and so its token, belongs to.
    pub repository: String,
    /// The workflow file's path within that repository.
    pub workflow_path: String,
    /// The commit GitHub read the workflow file from.
    pub workflow_sha: String,
    /// The id of the job that is running.
    pub job: String,
}

impl ActionsRun {
    /// Read the run from the variables GitHub Actions sets.
    ///
    /// `lookup` answers one variable by name; the front end passes the
    /// process environment, and tests pass a map.
    ///
    /// # Errors
    ///
    /// Returns a refusal when Airlock is not running inside Actions, or when
    /// a variable that names the run is absent or malformed.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, Refusal> {
        if lookup("GITHUB_ACTIONS").as_deref() != Some("true") {
            return Err(Refusal::new(
                RefusalCode::OutsideActions,
                "Repository mode runs only inside GitHub Actions, where the job's permissions \
                 name the token's whole grant. Outside Actions no file states what an \
                 installation token may do.",
            ));
        }
        let required = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Refusal::new(
                        RefusalCode::RunUndescribed,
                        format!(
                            "GitHub Actions did not set `{name}`, so the job whose permissions \
                             bound the token cannot be found."
                        ),
                    )
                })
        };
        let repository = required("GITHUB_REPOSITORY")?;
        let workflow_ref = required("GITHUB_WORKFLOW_REF")?;
        let workflow_sha = required("GITHUB_WORKFLOW_SHA")?;
        let job = required("GITHUB_JOB")?;

        let workflow_path = workflow_path(&repository, &workflow_ref)?;
        let hex = workflow_sha.chars().all(|c| c.is_ascii_hexdigit());
        if !hex || !matches!(workflow_sha.len(), 40 | 64) {
            return Err(Refusal::new(
                RefusalCode::RunUndescribed,
                "`GITHUB_WORKFLOW_SHA` is not a full commit id.",
            ));
        }

        Ok(Self {
            repository,
            workflow_path,
            workflow_sha: workflow_sha.to_ascii_lowercase(),
            job,
        })
    }

    /// Whether `owner/repo` is the repository this run belongs to.
    #[must_use]
    pub fn is_for(&self, owner: &str, repo: &str) -> bool {
        self.repository
            .eq_ignore_ascii_case(&format!("{owner}/{repo}"))
    }
}

/// The workflow file's path, from `GITHUB_WORKFLOW_REF`.
///
/// GitHub writes the ref as `owner/repo/.github/workflows/file.yml@ref`. A
/// ref that names another repository, or a path outside the workflows
/// directory, is not one Airlock can read the permissions of.
fn workflow_path(repository: &str, workflow_ref: &str) -> Result<String, Refusal> {
    let undescribed = || {
        Refusal::new(
            RefusalCode::RunUndescribed,
            "`GITHUB_WORKFLOW_REF` does not name a workflow file in the run's own repository.",
        )
    };
    let prefix = format!("{repository}/");
    let Some(head) = workflow_ref.get(..prefix.len()) else {
        return Err(undescribed());
    };
    if !head.eq_ignore_ascii_case(&prefix) {
        return Err(undescribed());
    }
    let rest = &workflow_ref[prefix.len()..];
    let path = rest.split_once('@').map_or(rest, |(path, _)| path);
    let in_workflows = path.starts_with(".github/workflows/")
        && (path.ends_with(".yml") || path.ends_with(".yaml"))
        && !path
            .split('/')
            .any(|segment| segment == ".." || segment.is_empty());
    if in_workflows {
        Ok(path.to_owned())
    } else {
        Err(undescribed())
    }
}

/// Verify the run's own token for an audit of `owner/repo`.
///
/// The caller has already classified the token as an installation token.
///
/// # Errors
///
/// Returns a refusal when the target is not the run's repository, when the
/// workflow file cannot be read at the run's commit, when the job is absent
/// or calls a reusable workflow, when no permissions are declared for it, or
/// when any declared permission is not `read`.
pub async fn verify_run_token<G: GitHub>(
    client: &G,
    run: &ActionsRun,
    owner: &str,
    repo: &str,
) -> Result<VerifiedGrant, Refusal> {
    if !run.is_for(owner, repo) {
        return Err(Refusal::new(
            RefusalCode::ForeignRepository,
            format!(
                "The run's token belongs to {}, and repository mode audits that one \
                 repository only, not {owner}/{repo}.",
                run.repository
            ),
        ));
    }

    let (run_owner, run_repo) = run.repository.split_once('/').unwrap_or((owner, repo));
    let bytes = client
        .file_at_commit(run_owner, run_repo, &run.workflow_sha, &run.workflow_path)
        .await
        .map_err(|error| {
            Refusal::new(
                RefusalCode::WorkflowUnreadable,
                format!(
                    "The workflow file {} could not be read at {}, so the job's permissions are \
                     unknown: {error}",
                    run.workflow_path, run.workflow_sha
                ),
            )
        })?;
    let text = String::from_utf8(bytes).map_err(|_| {
        Refusal::new(
            RefusalCode::WorkflowUnreadable,
            format!("The workflow file {} is not UTF-8.", run.workflow_path),
        )
    })?;
    let document = yaml::parse_mapping(&text, YamlLimits::default()).map_err(|error| {
        Refusal::new(
            RefusalCode::WorkflowUnreadable,
            format!(
                "The workflow file {} could not be parsed: {error}",
                run.workflow_path
            ),
        )
    })?;

    let permissions = job_permissions(&document, &run.job, &run.workflow_path)?;
    Ok(VerifiedGrant {
        kind: TokenKind::Installation,
        issuer: None,
        login: None,
        scopes: Vec::new(),
        installations: Vec::new(),
        run: Some(RunGrant {
            repository: run.repository.clone(),
            workflow: format!("{}@{}", run.workflow_path, run.workflow_sha),
            job: run.job.clone(),
            permissions,
        }),
    })
}

/// The job's effective permissions, as `name=read` pairs, when every one is
/// a read.
///
/// A job without `permissions` takes the workflow's. A workflow that states
/// neither leaves the token with the repository's default permissions, which
/// no file Airlock can read states.
fn job_permissions(document: &Yaml, job_id: &str, path: &str) -> Result<Vec<String>, Refusal> {
    let Some(job) = document.get("jobs").and_then(|jobs| jobs.get(job_id)) else {
        return Err(Refusal::new(
            RefusalCode::JobNotFound,
            format!("{path} has no job `{job_id}`, so the token's permissions are unknown."),
        ));
    };
    if job.get("uses").is_some() {
        return Err(Refusal::new(
            RefusalCode::JobNotFound,
            format!(
                "Job `{job_id}` of {path} calls a reusable workflow, whose job's permissions \
                 this file does not state."
            ),
        ));
    }

    let declared = match job.get("permissions") {
        Some(permissions) => permissions,
        None => document.get("permissions").ok_or_else(|| {
            Refusal::new(
                RefusalCode::PermissionsUndeclared,
                format!(
                    "Neither job `{job_id}` nor {path} declares `permissions`, so the token \
                     holds the repository's default permissions, which no file states."
                ),
            )
        })?,
    };

    match declared {
        Yaml::String(shorthand) if shorthand == "read-all" => Ok(vec!["*=read".to_owned()]),
        Yaml::Map(entries) => {
            let refused: Vec<String> = entries
                .iter()
                .filter(|(_, level)| level.as_str() != Some("read"))
                .map(|(name, level)| match level.as_str() {
                    Some(level) => format!("{name}={level}"),
                    None => format!("{name}={}", level.kind()),
                })
                .collect();
            if refused.is_empty() {
                Ok(entries
                    .iter()
                    .map(|(name, _)| format!("{name}=read"))
                    .collect())
            } else {
                Err(Refusal::new(
                    RefusalCode::WritePermission,
                    format!(
                        "Job `{job_id}` of {path} grants its token {}. Repository mode accepts \
                         the run's token only when every permission the job declares is `read`.",
                        refused.join(", ")
                    ),
                ))
            }
        }
        Yaml::String(other) => Err(Refusal::new(
            RefusalCode::WritePermission,
            format!(
                "Job `{job_id}` of {path} grants its token `{other}`. Repository mode accepts \
                 the run's token only when every permission the job declares is `read`."
            ),
        )),
        other => Err(Refusal::new(
            RefusalCode::PermissionsUndeclared,
            format!(
                "The `permissions` that bound job `{job_id}` of {path} are a {}, not a \
                 mapping or `read-all`.",
                other.kind()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn environment(overrides: &[(&str, Option<&str>)]) -> BTreeMap<String, String> {
        let mut map: BTreeMap<String, String> = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_REPOSITORY", "wyrd-company/example"),
            (
                "GITHUB_WORKFLOW_REF",
                "wyrd-company/example/.github/workflows/audit.yml@refs/heads/main",
            ),
            ("GITHUB_WORKFLOW_SHA", SHA),
            ("GITHUB_JOB", "audit"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        for (name, value) in overrides {
            match value {
                Some(value) => map.insert((*name).to_owned(), (*value).to_owned()),
                None => map.remove(*name),
            };
        }
        map
    }

    fn run(overrides: &[(&str, Option<&str>)]) -> Result<ActionsRun, Refusal> {
        let map = environment(overrides);
        ActionsRun::from_lookup(|name| map.get(name).cloned())
    }

    fn permissions(workflow: &str, job: &str) -> Result<Vec<String>, Refusal> {
        let document = yaml::parse_mapping(workflow, YamlLimits::default()).unwrap();
        job_permissions(&document, job, ".github/workflows/audit.yml")
    }

    #[test]
    fn a_run_is_read_from_the_variables_actions_sets() {
        let run = run(&[]).unwrap();
        assert_eq!(run.repository, "wyrd-company/example");
        assert_eq!(run.workflow_path, ".github/workflows/audit.yml");
        assert_eq!(run.workflow_sha, SHA);
        assert_eq!(run.job, "audit");
        assert!(run.is_for("Wyrd-Company", "Example"));
        assert!(!run.is_for("wyrd-company", "other"));
    }

    #[test]
    fn outside_actions_there_is_no_run() {
        for value in [None, Some("false"), Some("")] {
            let refusal = run(&[("GITHUB_ACTIONS", value)]).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::OutsideActions, "{value:?}");
        }
    }

    #[test]
    fn a_run_missing_any_variable_is_undescribed() {
        for name in &ACTIONS_VARIABLES[1..] {
            let refusal = run(&[(name, None)]).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::RunUndescribed, "{name}");
        }
    }

    #[test]
    fn a_workflow_ref_outside_the_run_or_its_workflows_is_undescribed() {
        for workflow_ref in [
            "someone-else/example/.github/workflows/audit.yml@refs/heads/main",
            "wyrd-company/example/scripts/audit.yml@refs/heads/main",
            "wyrd-company/example/.github/workflows/../../audit.yml@refs/heads/main",
            "wyrd-company/example/.github/workflows/audit.sh@refs/heads/main",
            "wyrd",
        ] {
            let refusal = run(&[("GITHUB_WORKFLOW_REF", Some(workflow_ref))]).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::RunUndescribed, "{workflow_ref}");
        }
    }

    #[test]
    fn a_workflow_sha_must_be_a_full_commit_id() {
        for sha in ["main", "0123456", &"z".repeat(40)] {
            let refusal = run(&[("GITHUB_WORKFLOW_SHA", Some(sha))]).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::RunUndescribed, "{sha}");
        }
    }

    #[test]
    fn every_declared_read_is_the_grant() {
        let workflow = "\
permissions: {}
jobs:
  audit:
    permissions:
      contents: read
      actions: read
      attestations: read
    steps: []
";
        assert_eq!(
            permissions(workflow, "audit").unwrap(),
            vec!["contents=read", "actions=read", "attestations=read"]
        );
    }

    #[test]
    fn a_job_with_a_write_permission_is_refused() {
        let workflow = "\
jobs:
  audit:
    permissions:
      contents: read
      issues: write
    steps: []
";
        let refusal = permissions(workflow, "audit").unwrap_err();
        assert_eq!(refusal.code, RefusalCode::WritePermission);
        assert!(
            refusal.detail.contains("issues=write"),
            "{}",
            refusal.detail
        );
    }

    #[test]
    fn id_token_write_is_a_write() {
        let workflow = "\
jobs:
  audit:
    permissions:
      contents: read
      id-token: write
    steps: []
";
        let refusal = permissions(workflow, "audit").unwrap_err();
        assert_eq!(refusal.code, RefusalCode::WritePermission);
    }

    #[test]
    fn a_permission_of_none_is_not_read() {
        // The design accepts the token when every permission is `read`; `none`
        // is not, so it is refused until that reading changes.
        let workflow = "\
jobs:
  audit:
    permissions:
      contents: read
      issues: none
    steps: []
";
        let refusal = permissions(workflow, "audit").unwrap_err();
        assert_eq!(refusal.code, RefusalCode::WritePermission);
    }

    #[test]
    fn a_job_inherits_the_workflow_permissions() {
        let workflow = "\
permissions:
  contents: read
jobs:
  audit:
    steps: []
";
        assert_eq!(
            permissions(workflow, "audit").unwrap(),
            vec!["contents=read"]
        );

        let writing = "\
permissions: write-all
jobs:
  audit:
    steps: []
";
        assert_eq!(
            permissions(writing, "audit").unwrap_err().code,
            RefusalCode::WritePermission
        );
    }

    #[test]
    fn read_all_is_every_permission_read() {
        let workflow = "\
jobs:
  audit:
    permissions: read-all
    steps: []
";
        assert_eq!(permissions(workflow, "audit").unwrap(), vec!["*=read"]);
    }

    #[test]
    fn an_empty_permission_map_grants_nothing_to_refuse() {
        let workflow = "\
jobs:
  audit:
    permissions: {}
    steps: []
";
        assert_eq!(
            permissions(workflow, "audit").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn undeclared_permissions_are_the_repository_default_and_refused() {
        let workflow = "\
jobs:
  audit:
    steps: []
";
        assert_eq!(
            permissions(workflow, "audit").unwrap_err().code,
            RefusalCode::PermissionsUndeclared
        );
    }

    #[test]
    fn a_missing_job_or_a_reusable_workflow_call_is_refused() {
        let workflow = "\
permissions:
  contents: read
jobs:
  audit:
    uses: ./.github/workflows/other.yml
";
        assert_eq!(
            permissions(workflow, "audit").unwrap_err().code,
            RefusalCode::JobNotFound
        );
        assert_eq!(
            permissions(workflow, "elsewhere").unwrap_err().code,
            RefusalCode::JobNotFound
        );
    }
}
