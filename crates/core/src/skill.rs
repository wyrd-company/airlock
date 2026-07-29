//! The repository-standards skill carried by the Airlock binary.
//!
//! Hand-written guidance and templates are embedded verbatim. The conformance
//! reference is rendered from the compiled registry so its rule identity can
//! never drift from the questions this binary asks.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::registry::{self, Evaluation, Section};

const EMISSION_MARKER_PATH: &str = ".airlock-skill";
const EMISSION_MARKER: &str = "airlock:repository-standards\n";

const FILES: &[(&str, &str)] = &[
    ("SKILL.md", include_str!("../skills/repository-standards/SKILL.md")),
    (
        "references/check-guidance.md",
        include_str!("../skills/repository-standards/references/check-guidance.md"),
    ),
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
    if target.exists() {
        verify_previous_emission(target)?;
    }

    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = staging_path(parent, target);
    fs::create_dir(&staging)?;
    let mut staging_guard = CleanupGuard::new(staging.clone());

    for (relative, contents) in FILES {
        write_file(&staging, relative, contents)?;
    }
    write_file(&staging, "references/conformance.md", &conformance()?)?;
    write_file(&staging, EMISSION_MARKER_PATH, EMISSION_MARKER)?;

    if target.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} appeared while the skill was being staged; pass --force to replace it",
                target.display()
            ),
        ));
    }
    if !target.exists() {
        fs::rename(&staging, target)?;
        staging_guard.disarm();
        return Ok(());
    }

    verify_previous_emission(target)?;
    let backup = backup_path(&staging)?;
    fs::rename(target, &backup)?;
    if let Err(error) = fs::rename(&staging, target) {
        let _ = fs::rename(&backup, target);
        return Err(error);
    }
    staging_guard.disarm();
    let _ = remove_path(&backup);
    Ok(())
}

fn verify_previous_emission(target: &Path) -> io::Result<()> {
    let marker = target.join(EMISSION_MARKER_PATH);
    match fs::read_to_string(&marker) {
        Ok(contents) if contents == EMISSION_MARKER => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a repository-standards skill previously emitted by Airlock; \
                 expected marker {}",
                target.display(),
                marker.display()
            ),
        )),
    }
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

fn backup_path(staging: &Path) -> io::Result<PathBuf> {
    let name = staging.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("staging path {} has no file name", staging.display()),
        )
    })?;
    let mut backup_name = name.to_os_string();
    backup_name.push(".replaced");
    Ok(staging.with_file_name(backup_name))
}

struct CleanupGuard {
    path: PathBuf,
    armed: bool,
}

impl CleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_path(&self.path);
        }
    }
}

fn write_file(root: &Path, relative: &str, contents: &str) -> io::Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

fn remove_path(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// Render the registry-owned conformance reference.
pub fn conformance() -> io::Result<String> {
    let guidance = guidance_by_rule()?;
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
            "\n## {}\n\n| Id | Assertion | Severity | Evaluation | Guidance |\n\
             | --- | --- | --- | --- | --- |\n",
            section_title(*section)
        );
        for check in registry::in_section(*section) {
            let _ = writeln!(
                output,
                "| `{}` | {} | {} | {} | {} |",
                check.id,
                escape_table(check.statement),
                severity_title(check.severity.code()),
                evaluation_title(check.evaluation),
                escape_table(&guidance[check.id])
            );
        }
    }
    Ok(output)
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
    value.replace('\\', "\\\\").replace('|', "\\|")
}

fn guidance_by_rule() -> io::Result<BTreeMap<String, String>> {
    const DOCUMENT: &str =
        include_str!("../skills/repository-standards/references/check-guidance.md");
    let mut entries = BTreeMap::new();

    for line in DOCUMENT.lines() {
        let cells = split_table_row(line);
        let Some(id) = cells
            .first()
            .and_then(|cell| cell.strip_prefix('`'))
            .and_then(|cell| cell.strip_suffix('`'))
        else {
            continue;
        };
        if !id.starts_with("REPO-") {
            continue;
        }
        let value = cells
            .get(1)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_data(format!("{id} has no hand-written check guidance")))?;
        if registry::find(id).is_none() {
            return Err(invalid_data(format!(
                "check guidance names {id}, which is not in the registry"
            )));
        }
        if entries.insert(id.to_owned(), value.to_owned()).is_some() {
            return Err(invalid_data(format!(
                "check guidance names {id} more than once"
            )));
        }
    }

    for check in registry::CHECKS {
        if !entries.contains_key(check.id) {
            return Err(invalid_data(format!(
                "{} has no hand-written check guidance",
                check.id
            )));
        }
    }
    Ok(entries)
}

fn split_table_row(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for character in line.trim_matches('|').chars() {
        if escaped {
            cell.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '|' {
            cells.push(cell.trim().to_owned());
            cell.clear();
        } else {
            cell.push(character);
        }
    }
    if escaped {
        cell.push('\\');
    }
    cells.push(cell.trim().to_owned());
    cells
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn generated_conformance_carries_registry_identity_and_every_rule_once() {
        let document = conformance().unwrap();
        assert!(document.contains(registry::REGISTRY_VERSION));
        assert!(document.contains(&registry::digest()));
        for check in registry::CHECKS {
            assert_eq!(
                document.matches(&format!("| `{}` |", check.id)).count(),
                1,
                "{} should appear exactly once",
                check.id
            );
            assert!(document.contains(&escape_table(check.statement)));
        }
    }

    #[test]
    fn embedded_paths_are_unique() {
        let paths = FILES.iter().map(|(path, _)| *path).collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), FILES.len());
    }

    #[test]
    fn embedded_manifest_covers_the_on_disk_skill_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("skills/repository-standards");
        let mut on_disk = BTreeSet::new();
        collect_files(&root, &root, &mut on_disk);
        let embedded = FILES
            .iter()
            .map(|(path, _)| PathBuf::from(path))
            .collect::<BTreeSet<_>>();
        assert_eq!(embedded, on_disk);
    }

    #[test]
    fn hand_written_skill_files_do_not_restate_registry_rules() {
        for (path, contents) in FILES {
            if *path == "references/check-guidance.md" {
                continue;
            }
            assert!(
                !contents.contains("REPO-"),
                "{path} contains a registry rule id"
            );
            for check in registry::CHECKS {
                assert!(
                    !contents.contains(check.statement),
                    "{path} restates {}",
                    check.id
                );
            }
        }
    }

    #[test]
    fn hand_written_guidance_and_registry_name_the_same_rules() {
        let guidance = guidance_by_rule().unwrap();
        let registry = registry::CHECKS
            .iter()
            .map(|check| check.id.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(guidance.keys().cloned().collect::<BTreeSet<_>>(), registry);
    }

    #[test]
    fn table_cells_escape_and_unescape_pipes_and_backslashes() {
        let value = r"read a | b from c:\file";
        let row = format!("| id | {} |", escape_table(value));
        assert_eq!(split_table_row(&row), ["id", value]);
    }

    #[test]
    fn backup_paths_retain_the_unique_staging_name() {
        let first = Path::new("/tmp/.repository-standards.airlock-1-100");
        let second = Path::new("/tmp/.repository-standards.airlock-1-200");
        assert_eq!(
            backup_path(first).unwrap().file_name(),
            Some(OsStr::new(".repository-standards.airlock-1-100.replaced"))
        );
        assert_ne!(backup_path(first).unwrap(), backup_path(second).unwrap());
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
            conformance().unwrap()
        );
        assert_eq!(
            fs::read_to_string(target.join(EMISSION_MARKER_PATH)).unwrap(),
            EMISSION_MARKER
        );
    }

    #[test]
    fn force_refuses_a_target_airlock_did_not_emit() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("other-skills");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("SKILL.md"), "unrelated").unwrap();

        let error = emit(&target, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("previously emitted by Airlock"));
        assert_eq!(
            fs::read_to_string(target.join("SKILL.md")).unwrap(),
            "unrelated"
        );
    }

    fn collect_files(root: &Path, directory: &Path, files: &mut BTreeSet<PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                collect_files(root, &path, files);
            } else {
                files.insert(path.strip_prefix(root).unwrap().to_owned());
            }
        }
    }
}
