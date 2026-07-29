//! The repository-standards skill carried by the Airlock binary.
//!
//! Hand-written guidance and templates are embedded verbatim. The conformance
//! reference is rendered from the compiled registry so its rule identity can
//! never drift from the questions this binary asks.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::registry::{self, Evaluation, Section};

const FILES: &[(&str, &str)] = &[
    ("SKILL.md", include_str!("../skills/repository-standards/SKILL.md")),
    ("references/topics.md", include_str!("../skills/repository-standards/references/topics.md")),
    ("references/platform/README.md", include_str!("../skills/repository-standards/references/platform/README.md")),
    ("references/platform/custom-properties.md", include_str!("../skills/repository-standards/references/platform/custom-properties.md")),
    ("references/platform/github-apps.md", include_str!("../skills/repository-standards/references/platform/github-apps.md")),
    ("references/platform/rulesets.md", include_str!("../skills/repository-standards/references/platform/rulesets.md")),
    ("references/platform/secrets-and-environments.md", include_str!("../skills/repository-standards/references/platform/secrets-and-environments.md")),
    ("references/platform/profile-repo/CODE_OF_CONDUCT.md", include_str!("../skills/repository-standards/references/platform/profile-repo/CODE_OF_CONDUCT.md")),
    ("references/platform/profile-repo/PULL_REQUEST_TEMPLATE.md", include_str!("../skills/repository-standards/references/platform/profile-repo/PULL_REQUEST_TEMPLATE.md")),
    ("references/platform/profile-repo/README.md", include_str!("../skills/repository-standards/references/platform/profile-repo/README.md")),
    ("references/platform/profile-repo/SECURITY.md", include_str!("../skills/repository-standards/references/platform/profile-repo/SECURITY.md")),
    ("references/platform/profile-repo/SUPPORT.md", include_str!("../skills/repository-standards/references/platform/profile-repo/SUPPORT.md")),
    ("references/platform/profile-repo/default.json", include_str!("../skills/repository-standards/references/platform/profile-repo/default.json")),
    ("references/platform/profile-repo/profile/README.md", include_str!("../skills/repository-standards/references/platform/profile-repo/profile/README.md")),
    ("references/platform/profile-repo/ISSUE_TEMPLATE/bug_report.yml", include_str!("../skills/repository-standards/references/platform/profile-repo/ISSUE_TEMPLATE/bug_report.yml")),
    ("references/platform/profile-repo/ISSUE_TEMPLATE/config.yml", include_str!("../skills/repository-standards/references/platform/profile-repo/ISSUE_TEMPLATE/config.yml")),
    ("references/platform/profile-repo/ISSUE_TEMPLATE/idea.yml", include_str!("../skills/repository-standards/references/platform/profile-repo/ISSUE_TEMPLATE/idea.yml")),
    ("references/templates/README.md", include_str!("../skills/repository-standards/references/templates/README.md")),
    ("references/templates/ci.yml", include_str!("../skills/repository-standards/references/templates/ci.yml")),
    ("references/templates/editorconfig", include_str!("../skills/repository-standards/references/templates/editorconfig")),
    ("references/templates/gitattributes", include_str!("../skills/repository-standards/references/templates/gitattributes")),
    ("references/templates/lefthook.yml", include_str!("../skills/repository-standards/references/templates/lefthook.yml")),
    ("references/templates/reconcile-settings.yml", include_str!("../skills/repository-standards/references/templates/reconcile-settings.yml")),
    ("references/templates/renovate.json", include_str!("../skills/repository-standards/references/templates/renovate.json")),
    ("references/templates/repo-settings.yml", include_str!("../skills/repository-standards/references/templates/repo-settings.yml")),
    ("references/templates/taskfile.yml", include_str!("../skills/repository-standards/references/templates/taskfile.yml")),
];

/// Write the complete skill tree to `target`.
///
/// An existing target is refused unless `force` is explicit. The new tree is
/// staged beside the target and renamed into place, so a generation failure
/// cannot leave a partially emitted skill.
pub fn emit(target: &Path, force: bool) -> io::Result<()> {
    if target.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; pass --force to replace it",
                target.display()
            ),
        ));
    }

    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = staging_path(parent, target);
    fs::create_dir(&staging)?;

    let result = (|| {
        for (relative, contents) in FILES {
            write_file(&staging, relative, contents)?;
        }
        write_file(&staging, "references/conformance.md", &conformance())?;

        if target.exists() && !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} appeared while the skill was being staged; pass --force to replace it",
                    target.display()
                ),
            ));
        }
        if target.exists() {
            if target.is_dir() {
                fs::remove_dir_all(target)?;
            } else {
                fs::remove_file(target)?;
            }
        }
        fs::rename(&staging, target)
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn staging_path(parent: &Path, target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository-standards");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(".{name}.airlock-{}-{nonce}", std::process::id()))
}

fn write_file(root: &Path, relative: &str, contents: &str) -> io::Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

/// Render the registry-owned conformance reference.
#[must_use]
pub fn conformance() -> String {
    let mut output = format!(
        "# Conformance Checklist\n\n\
         This reference is generated from Airlock check registry **{}** \
         (`{}`). The registry is authoritative for every rule id, statement, \
         default severity, section, and evaluation mode in this document.\n\n\
         **Always cite a rule by id and statement together.** A rule id alone \
         is not a meaningful finding.\n\n\
         `REPO-GIT-09`, `REPO-TASK-04`, and `REPO-LIC-04` apply only when the \
         repository declares at least one release unit.\n\n\
         ## Severity\n\n\
         | Level | Meaning |\n\
         | --- | --- |\n\
         | **Blocking** | The repository should not be public in this state |\n\
         | **Required** | A genuine gap; raise it |\n\
         | **Observation** | Report it; it may be a deliberate choice or a not-yet-live practice |\n",
        registry::REGISTRY_VERSION,
        registry::digest()
    );

    for section in Section::ALL {
        let _ = write!(
            output,
            "\n## {}\n\n| Id | Assertion | Severity | Evaluation |\n\
             | --- | --- | --- | --- |\n",
            section_title(*section)
        );
        for check in registry::in_section(*section) {
            let _ = writeln!(
                output,
                "| `{}` | {} | {} | {} |",
                check.id,
                escape_table(check.statement),
                severity_title(check.severity.code()),
                evaluation_title(check.evaluation)
            );
        }
    }
    output
}

fn section_title(section: Section) -> &'static str {
    match section {
        Section::Identity => "Identity",
        Section::Licensing => "Licensing",
        Section::Files => "Files",
        Section::Readme => "README",
        Section::Git => "Git configuration",
        Section::Automation => "Automation",
        Section::Agent => "Agent affordances",
        Section::Docs => "Documentation",
        Section::Release => "Release",
        Section::Classification => "Classification",
    }
}

fn severity_title(code: &str) -> &'static str {
    match code {
        "blocking" => "Blocking",
        "required" => "Required",
        "observation" => "Observation",
        _ => unreachable!("all registry severities are known"),
    }
}

fn evaluation_title(evaluation: Evaluation) -> &'static str {
    match evaluation {
        Evaluation::Mechanical => "Mechanical — evaluated by Airlock",
        Evaluation::Manual => "Manual — human judgment",
        Evaluation::Unimplemented => "Unimplemented — audit is incomplete",
    }
}

fn escape_table(value: &str) -> String {
    value.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn generated_conformance_carries_registry_identity_and_every_rule_once() {
        let document = conformance();
        assert!(document.contains(registry::REGISTRY_VERSION));
        assert!(document.contains(&registry::digest()));
        for check in registry::CHECKS {
            assert_eq!(
                document.matches(&format!("| `{}` |", check.id)).count(),
                1,
                "{} should appear exactly once",
                check.id
            );
            assert!(document.contains(check.statement));
        }
    }

    #[test]
    fn embedded_paths_are_unique() {
        let paths = FILES.iter().map(|(path, _)| *path).collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), FILES.len());
    }

    #[test]
    fn emission_refuses_existing_targets_and_force_replaces_them() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("repository-standards");

        emit(&target, false).unwrap();
        fs::write(target.join("local-change"), "keep me").unwrap();
        let error = emit(&target, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(target.join("local-change").exists());

        emit(&target, true).unwrap();
        assert!(!target.join("local-change").exists());
        assert_eq!(
            fs::read_to_string(target.join("references/conformance.md")).unwrap(),
            conformance()
        );
    }
}
