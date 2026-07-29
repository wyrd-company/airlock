//! README presentation checks whose assertions are decidable from the tree.

use crate::findings::Remediation;
use crate::policy::RuleInstance;

use super::{AuditContext, Verdict};

pub(crate) fn run(id: &str, _rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    match id {
        "REPO-README-06" => Some(demo_tape(context)),
        _ => None,
    }
}

fn demo_tape(context: &AuditContext) -> Verdict {
    if context.snapshot.tree_is_truncated() {
        return Verdict::inconclusive(
            "tree_truncated",
            context
                .snapshot
                .truncation_detail("whether every committed demo has `.tape` source"),
        );
    }

    let demos: Vec<_> = context
        .snapshot
        .tree
        .entries
        .iter()
        .filter(|entry| {
            entry.kind.is_file()
                && entry
                    .path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("demo.gif"))
        })
        .collect();
    if demos.is_empty() {
        return Verdict::pass(
            "no_demo_gif_committed",
            "no committed file with basename `demo.gif` exists; other names and media are outside \
             this mechanical proxy",
        );
    }

    let missing = demos.iter().find(|demo| {
        tape_directories(&demo.path)
            .iter()
            .all(|directory| !has_tape_under(context, directory))
    });
    let Some(missing) = missing else {
        return Verdict::pass(
            "tape_sources_committed",
            format!(
                "every committed demo.gif has `.tape` source ({} demo{})",
                demos.len(),
                if demos.len() == 1 { "" } else { "s" }
            ),
        );
    };

    Verdict::fail_at(
        "tape_source_missing",
        &missing.path,
        format!(
            "{} is committed without related `.tape` source",
            missing.path
        ),
        Remediation::new("commit_tape_source", "Commit the demo's `.tape` source."),
    )
}

fn tape_directories(demo: &str) -> Vec<&str> {
    let directory = demo.rsplit_once('/').map_or("", |(directory, _)| directory);
    let mut directories = vec![directory];
    if let Some(parent) = directory
        .strip_suffix("/assets")
        .or_else(|| (directory == "assets").then_some(""))
    {
        directories.push(parent);
    }
    directories
}

fn has_tape_under(context: &AuditContext, directory: &str) -> bool {
    let prefix = (!directory.is_empty()).then(|| format!("{directory}/"));
    context.snapshot.tree.entries.iter().any(|entry| {
        entry.kind.is_file()
            && prefix
                .as_deref()
                .is_none_or(|prefix| entry.path.starts_with(prefix))
            && entry
                .path
                .rsplit_once('.')
                .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("tape"))
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::CheckFixture;
    use crate::findings::Status;

    #[test]
    fn a_repository_without_a_demo_passes() {
        assert_eq!(
            CheckFixture::new(&[]).verdict("REPO-README-06").status,
            Status::Pass
        );
    }

    #[test]
    fn a_demo_with_tape_source_passes_even_when_the_paths_differ() {
        let fixture = CheckFixture::new(&[
            ("docs/assets/demo.gif", "gif"),
            ("docs/demo.tape", "source"),
        ]);
        assert_eq!(fixture.verdict("REPO-README-06").status, Status::Pass);
    }

    #[test]
    fn an_unrelated_tape_does_not_satisfy_a_demo() {
        let fixture = CheckFixture::new(&[
            ("docs/assets/demo.gif", "gif"),
            ("legacy/old.tape", "source"),
        ]);
        assert_eq!(fixture.verdict("REPO-README-06").status, Status::Fail);
    }

    #[test]
    fn a_demo_accepts_named_tape_sources_in_its_directory() {
        let fixture = CheckFixture::new(&[
            ("demo/owl-reconstruction/demo.gif", "gif"),
            ("demo/owl-reconstruction/01-first-pass.tape", "source"),
            ("demo/owl-reconstruction/04-inspect.tape", "source"),
            ("demo/owl-reconstruction/build-demo.sh", "script"),
        ]);
        assert_eq!(fixture.verdict("REPO-README-06").status, Status::Pass);
    }

    #[test]
    fn every_demo_needs_related_tape_source() {
        let fixture = CheckFixture::new(&[
            ("docs/assets/demo.gif", "gif"),
            ("docs/demo.tape", "source"),
            ("examples/demo.gif", "gif"),
        ]);
        assert_eq!(fixture.verdict("REPO-README-06").status, Status::Fail);
    }

    #[test]
    fn a_demo_without_tape_source_fails() {
        let fixture = CheckFixture::new(&[("docs/assets/demo.gif", "gif")]);
        let verdict = fixture.verdict("REPO-README-06");
        assert_eq!(verdict.status, Status::Fail);
        assert_eq!(verdict.evidence.unwrap().code, "tape_source_missing");
    }

    #[test]
    fn a_truncated_tree_never_proves_demo_or_tape_absence() {
        let mut no_demo = CheckFixture::new(&[]);
        no_demo.snapshot.tree.truncated = true;
        assert_eq!(
            no_demo.verdict("REPO-README-06").status,
            Status::Inconclusive
        );

        let mut demo = CheckFixture::new(&[("docs/assets/demo.gif", "gif")]);
        demo.snapshot.tree.truncated = true;
        assert_eq!(demo.verdict("REPO-README-06").status, Status::Inconclusive);

        let mut complete_pair = CheckFixture::new(&[
            ("docs/assets/demo.gif", "gif"),
            ("docs/demo.tape", "source"),
        ]);
        complete_pair.snapshot.tree.truncated = true;
        assert_eq!(
            complete_pair.verdict("REPO-README-06").status,
            Status::Inconclusive
        );
    }
}
