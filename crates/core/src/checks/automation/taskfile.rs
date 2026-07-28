use super::*;

pub(super) fn parse_taskfile(context: &AuditContext) -> Result<Yaml, Box<Verdict>> {
    match context.yaml("taskfile.yml") {
        ParsedFile::Parsed(document) => Ok(document),
        ParsedFile::Undecided(verdict) => Err(verdict),
        ParsedFile::Missing | ParsedFile::NotAFile(_) => Err(Box::new(Verdict::fail_at(
            "file_missing",
            "taskfile.yml",
            "there is no taskfile.yml to read tasks from",
            Remediation::new("add_taskfile", "Add a taskfile.yml at the repository root."),
        ))),
    }
}

pub(super) fn required_tasks(context: &AuditContext) -> Verdict {
    let taskfile = try_verdict!(parse_taskfile(context));
    let defined: Vec<&str> = taskfile
        .get("tasks")
        .map(|tasks| tasks.keys().collect())
        .unwrap_or_default();

    let missing: Vec<&&str> = REQUIRED_TASKS
        .iter()
        .filter(|task| !defined.contains(&**task))
        .collect();

    if missing.is_empty() {
        Verdict::pass_at(
            "required_tasks_defined",
            "taskfile.yml",
            "test, lint, format, and check are all defined",
        )
    } else {
        Verdict::fail_at(
            "required_tasks_missing",
            "taskfile.yml",
            format!(
                "{} not defined",
                missing
                    .iter()
                    .map(|task| format!("`{task}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "define_tasks",
                "Define test, lint, format, and check in taskfile.yml.",
            ),
        )
    }
}

pub(super) fn per_unit_taskfiles(context: &AuditContext) -> Verdict {
    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so per-unit taskfiles could not be checked",
        );
    };
    if units.len() <= 1 {
        return Verdict::pass(
            "single_release_unit",
            "the repository declares one release unit, so per-unit taskfiles do not apply",
        );
    }

    let missing: Vec<String> = units
        .iter()
        .map(|(_, path)| {
            if path == "." {
                "taskfile.yml".to_owned()
            } else {
                format!("{path}/taskfile.yml")
            }
        })
        .filter(|path| !context.has_file(path))
        .collect();

    if missing.is_empty() {
        Verdict::pass(
            "per_unit_taskfiles_present",
            format!(
                "every one of the {} release units has a taskfile.yml",
                units.len()
            ),
        )
    } else {
        Verdict::fail(
            "per_unit_taskfile_missing",
            format!("{} absent", missing.join(", ")),
            Remediation::new(
                "add_unit_taskfile",
                "Add a taskfile.yml at each release unit's declared path.",
            ),
        )
    }
}

pub(super) fn includes(context: &AuditContext) -> Result<Vec<(String, Yaml)>, Box<Verdict>> {
    let taskfile = parse_taskfile(context)?;
    Ok(taskfile
        .get("includes")
        .and_then(Yaml::as_map)
        .map(|entries| entries.to_vec())
        .unwrap_or_default())
}

pub(super) fn includes_set_dir(context: &AuditContext) -> Verdict {
    let includes = try_verdict!(includes(context));
    if includes.is_empty() {
        return Verdict::pass_at(
            "no_includes",
            "taskfile.yml",
            "the taskfile declares no includes",
        );
    }

    let missing: Vec<&String> = includes
        .iter()
        .filter(|(_, include)| include.get("dir").and_then(Yaml::as_str).is_none())
        .map(|(name, _)| name)
        .collect();

    if missing.is_empty() {
        Verdict::pass_at(
            "includes_set_dir",
            "taskfile.yml",
            format!("all {} includes set `dir:`", includes.len()),
        )
    } else {
        Verdict::fail_at(
            "include_without_dir",
            "taskfile.yml",
            format!(
                "{} set no `dir:`",
                missing
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new("set_include_dir", "Set `dir:` on every taskfile include."),
        )
    }
}

pub(super) fn include_namespaces(context: &AuditContext) -> Verdict {
    let includes = try_verdict!(includes(context));
    if includes.is_empty() {
        return Verdict::pass_at(
            "no_includes",
            "taskfile.yml",
            "the taskfile declares no includes",
        );
    }

    let Some(units) = context.release_units() else {
        return Verdict::inconclusive(
            "no_release_units_declared",
            "the repository declares no release units, so include namespaces could not be \
             compared against them",
        );
    };
    let unit_ids: Vec<&String> = units.iter().map(|(id, _)| id).collect();

    let unmatched: Vec<&String> = includes
        .iter()
        .map(|(name, _)| name)
        .filter(|name| !unit_ids.contains(name))
        .collect();

    if unmatched.is_empty() {
        Verdict::pass_at(
            "include_namespaces_match",
            "taskfile.yml",
            "every include namespace names a declared release unit",
        )
    } else {
        Verdict::fail_at(
            "include_namespace_unmatched",
            "taskfile.yml",
            format!(
                "{} names no declared release unit",
                unmatched
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Remediation::new(
                "align_include_namespaces",
                "Name each include after the release unit id it covers.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::fixtures::*;
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        CheckFixture::new(files).verdict(id).status
    }

    const TASKFILE: &str = "\
version: '3'
tasks:
  test:
    cmds: [cargo test]
  lint:
    cmds: [cargo clippy]
  format:
    cmds: [cargo fmt]
  check:
    cmds: [cargo test]
";
    #[test]
    fn required_task_verbs_must_all_exist() {
        assert_eq!(
            verdict("REPO-TASK-01", &[("taskfile.yml", TASKFILE)]),
            Status::Pass
        );
        assert_eq!(
            verdict(
                "REPO-TASK-01",
                &[(
                    "taskfile.yml",
                    "version: '3'\ntasks:\n  test:\n    cmds: []\n"
                )]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_missing_taskfile_fails_rather_than_passing_vacuously() {
        assert_eq!(verdict("REPO-TASK-01", &[]), Status::Fail);
    }

    #[test]
    fn includes_must_set_dir() {
        let with_dir = "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n    dir: ./core\n";
        let without = "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n";
        assert_eq!(
            verdict("REPO-TASK-05", &[("taskfile.yml", with_dir)]),
            Status::Pass
        );
        assert_eq!(
            verdict("REPO-TASK-05", &[("taskfile.yml", without)]),
            Status::Fail
        );
    }

    #[test]
    fn include_namespaces_must_name_release_units() {
        let files = [
            (
                "taskfile.yml",
                "version: '3'\nincludes:\n  core:\n    taskfile: ./core\n    dir: ./core\n",
            ),
            (
                ".intentional/config.yml",
                "release-units:\n  core:\n    path: core\n  cli:\n    path: cli\n",
            ),
        ];
        assert_eq!(verdict("REPO-TASK-06", &files), Status::Pass);

        let mismatched = [
            (
                "taskfile.yml",
                "version: '3'\nincludes:\n  other:\n    taskfile: ./x\n    dir: ./x\n",
            ),
            files[1],
        ];
        assert_eq!(verdict("REPO-TASK-06", &mismatched), Status::Fail);
    }
}
