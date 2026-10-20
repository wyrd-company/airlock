//! Maturity records, reachability, and rung boundaries.
//
// relationships:
//   references: maturity

use super::*;

fn tag(name: &str, version: &str, baseline: bool) -> HistoryTag {
    HistoryTag {
        has_tagger: true, target_kind: "commit".into(),
        name: name.into(), commit: "commit".into(),
        message: format!("intentional release record\n\ncontract: contract-1\ngenerator: intentional 0.2.0\nplan-digest: sha256:{}\ntag-id: release-unit/sample/primary\nversion: {version}\nbaseline: {baseline}\n", "a".repeat(64)),
    }
}

fn inputs() -> Inputs {
    Inputs {
        complete: true,
        head: "commit".into(),
        commits: BTreeMap::from([("commit".into(), Vec::new())]),
        ..Inputs::default()
    }
}

#[test]
fn incomplete_evidence_has_no_fallback_rung() {
    assert!(observe(&Inputs::default()).is_err());
}

#[test]
fn arbitrary_semver_tags_do_not_end_seeding() {
    let mut input = inputs();
    let mut arbitrary = tag("9.0.0", "9.0.0", false);
    arbitrary.message = "an ordinary tag".into();
    input.tags.push(arbitrary);
    assert_eq!(observe(&input).unwrap().rung, Lifecycle::Seeded);
}

#[test]
fn takeover_baseline_ends_seeded_without_establishing_a_release() {
    let mut input = inputs();
    input.tags.push(tag("sample@5.0.0", "5.0.0", true));

    let observed = observe(&input).unwrap();
    assert_eq!(observed.rung, Lifecycle::Building);
    assert!(observed.release_tags.is_empty());
}

#[test]
fn non_releasing_history_stays_on_two_rungs() {
    let mut input = inputs();
    input.commits.insert("parent".into(), Vec::new());
    assert_eq!(observe(&input).unwrap().rung, Lifecycle::Seeded);
    input.tags.push(tag("0.0.0", "0.0.0", true));
    let mut workspace = tag("3.0.0", "3.0.0", false);
    workspace.message = workspace
        .message
        .replace("release-unit/sample/primary", "workspace/global");
    input.tags.push(workspace);
    assert_eq!(observe(&input).unwrap().rung, Lifecycle::Building);
}

#[test]
fn release_records_distinguish_released_stable_and_prerelease() {
    for (version, expected) in [
        ("0.2.0", Lifecycle::Released),
        ("1.0.0-rc.1", Lifecycle::Released),
        ("1.0.0", Lifecycle::Stable),
    ] {
        let mut input = inputs();
        input.tags.push(tag("baseline", "0.0.0", true));
        input
            .tags
            .push(tag(&format!("sample@{version}"), version, false));
        assert_eq!(observe(&input).unwrap().rung, expected);
    }
}

#[test]
fn tags_outside_audited_history_do_not_raise_maturity() {
    let mut input = inputs();
    let mut other = tag("sample@2.0.0", "2.0.0", true);
    other.commit = "other-branch".into();
    input.tags.push(other);
    assert_eq!(observe(&input).unwrap().rung, Lifecycle::Seeded);
}

#[test]
fn malformed_records_and_workspace_tags_do_not_establish_releases() {
    let mut input = inputs();
    input.tags.push(tag("baseline", "0.0.0", true));
    let mut projection = tag("sample@2.0.0", "2.0.0", false);
    projection.message = projection
        .message
        .replace("release-unit/sample/primary", "workspace/global");
    input.tags.push(projection);
    let mut malformed = tag("2.0.0", "2.0.0", false);
    malformed.message = malformed
        .message
        .replace("baseline: false", "baseline: false\nbaseline: true");
    input.tags.push(malformed);
    assert_eq!(observe(&input).unwrap().rung, Lifecycle::Building);
}

#[test]
fn releases_before_or_beside_the_baseline_do_not_raise_maturity() {
    for (baseline_commit, parents) in [
        ("newer", vec!["older".into()]),
        ("sibling", vec!["older".into(), "sibling".into()]),
    ] {
        let mut input = inputs();
        input.head = "newer".into();
        input.commits = BTreeMap::from([
            ("newer".into(), parents),
            ("older".into(), Vec::new()),
            ("sibling".into(), Vec::new()),
        ]);
        let mut baseline = tag("baseline", "0.0.0", true);
        baseline.commit = baseline_commit.into();
        let mut release = tag("sample@2.0.0", "2.0.0", false);
        release.commit = "older".into();
        input.tags = vec![baseline, release];
        assert_eq!(observe(&input).unwrap().rung, Lifecycle::Building);
    }
}

#[test]
fn annotations_require_a_tagger_and_a_direct_commit_target() {
    for missing_tagger in [true, false] {
        let mut input = inputs();
        let mut baseline = tag("baseline", "0.0.0", true);
        if missing_tagger {
            baseline.has_tagger = false;
        } else {
            baseline.target_kind = "tag".into();
        }
        input.tags.push(baseline);
        assert_eq!(observe(&input).unwrap().rung, Lifecycle::Seeded);
    }
}
