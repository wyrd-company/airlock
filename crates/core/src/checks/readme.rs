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
    let tapes: Vec<_> = context
        .snapshot
        .tree
        .entries
        .iter()
        .filter(|entry| {
            entry.kind.is_file()
                && entry
                    .path
                    .rsplit_once('.')
                    .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("tape"))
        })
        .collect();

    if demos.is_empty() {
        return if context.snapshot.tree_is_truncated() {
            Verdict::inconclusive(
                "tree_truncated",
                context
                    .snapshot
                    .truncation_detail("whether a committed demo exists"),
            )
        } else {
            Verdict::pass("no_demo_committed", "no committed demo.gif exists")
        };
    }

    if let Some(tape) = tapes.first() {
        return Verdict::pass_at(
            "tape_source_committed",
            &tape.path,
            format!(
                "{} has committed `.tape` source at {}",
                demos[0].path, tape.path
            ),
        );
    }

    if context.snapshot.tree_is_truncated() {
        return Verdict::inconclusive(
            "tree_truncated",
            context.snapshot.truncation_detail(&format!(
                "whether committed `.tape` source exists for {}",
                demos[0].path
            )),
        );
    }

    Verdict::fail_at(
        "tape_source_missing",
        &demos[0].path,
        format!("{} is committed without `.tape` source", demos[0].path),
        Remediation::new("commit_tape_source", "Commit the demo's `.tape` source."),
    )
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
    }
}
