//! The catalogue and a real run must say the same thing about every rule.
//!
//! `airlock audit --list-checks` publishes what closing each rule's gap would
//! take, and adopters read it to know what airlock would do to a repository
//! before pointing it at one. That promise is only worth anything if the
//! catalogue matches what a run actually reports.
//!
//! The two are produced by different code: the catalogue by the registry
//! listing, and a finding's classification by the audit's own assembly as it
//! builds a report. This test runs a real audit over a real repository with
//! every registered rule enabled, and compares the two rule by rule. Comparing
//! the catalogue against itself would pass even if audit assembly stopped
//! carrying a classification at all.
//!
//! Test-only note: the shipped binary never shells out, but this test uses the
//! `git` binary to build a real repository to observe.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use airlock_core::audit::{self, AuditOptions};
use airlock_core::findings::Gate;
use airlock_core::limits::Limits;
use airlock_core::policy::{Condition, ResolvedPolicy, RuleInstance};
use airlock_core::{registry, render};
use serde_json::Value;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A repository with enough in it that the run reaches real verdicts rather
/// than failing early. Conformance is beside the point here: what matters is
/// that every registered rule produces a finding.
fn committed_repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    for (path, content) in [
        ("README.md", "# widget\n\nA thing that widgets.\n"),
        ("LICENSE", "Apache License\nVersion 2.0, January 2004\n"),
        ("CONTRIBUTING.md", "Run `task check`.\n"),
        (
            ".intentional/config.yml",
            "release-units:\n  widget:\n    path: .\n",
        ),
        (
            "Cargo.toml",
            "[package]\nname = \"widget\"\nlicense = \"Apache-2.0\"\n",
        ),
    ] {
        let on_disk = root.join(path);
        std::fs::create_dir_all(on_disk.parent().expect("a parent")).expect("mkdir");
        std::fs::write(on_disk, content).expect("write");
    }
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "fixture"]);
    dir
}

/// A policy enabling every registered rule at its registered severity, so the
/// comparison covers the whole registry rather than a convenient corner.
fn full_policy() -> ResolvedPolicy {
    ResolvedPolicy {
        name: "catalogue".to_owned(),
        source: "./policy.yml".to_owned(),
        commit: None,
        bundle_digest: "sha256:0".to_owned(),
        sources: Vec::new(),
        gate: Gate::Blocking,
        rules: registry::CHECKS
            .iter()
            .map(|def| RuleInstance {
                def,
                severity: def.severity,
                params: BTreeMap::new(),
                provenance: "catalogue".to_owned(),
                condition: Condition::Always,
            })
            .collect(),
        suppressions: Default::default(),
        reference_data: BTreeMap::new(),
    }
}

fn options() -> AuditOptions {
    AuditOptions {
        reference: None,
        limits: Limits::default(),
        version: "0.0.0-test".to_owned(),
        working_tree: None,
    }
}

/// The catalogue's classification for every rule, keyed by rule id.
fn catalogued() -> BTreeMap<String, Value> {
    render::list_checks_json()["checks"]
        .as_array()
        .expect("checks is an array")
        .iter()
        .map(|check| {
            (
                check["id"].as_str().expect("an id").to_owned(),
                check["remediation_class"].clone(),
            )
        })
        .collect()
}

#[test]
fn a_run_reports_the_classification_the_catalogue_publishes_for_every_rule() {
    let repository = committed_repository();
    let report = audit::run_local(&full_policy(), &options(), repository.path())
        .expect("the working tree is audited");
    let catalogue = catalogued();

    // Without this the comparison could pass over a handful of rules and
    // prove nothing about the rest.
    let observed: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule.as_str())
        .collect();
    let registered: BTreeSet<&str> = registry::CHECKS.iter().map(|check| check.id).collect();
    assert_eq!(
        observed, registered,
        "the run must reach every registered rule for this comparison to mean anything"
    );
    assert_eq!(catalogue.len(), registered.len());

    for finding in &report.findings {
        let from_run =
            serde_json::to_value(&finding.remediation_class).expect("a finding serialises");
        let from_catalogue = catalogue
            .get(&finding.rule)
            .unwrap_or_else(|| panic!("{} is not in the catalogue", finding.rule));

        assert_eq!(
            &from_run, from_catalogue,
            "{} is catalogued differently from how a run reports it",
            finding.rule
        );
        assert!(
            from_run["code"].is_string() || from_run["none_reason"].is_string(),
            "{} says neither what would close it nor why nothing would",
            finding.rule
        );
    }
}

#[test]
fn a_run_carries_a_classification_for_every_finding_it_produces() {
    // The failure this guards against is assembly quietly dropping the
    // classification: the equality test above would still pass if both sides
    // became empty, so assert the content is really there.
    let repository = committed_repository();
    let report = audit::run_local(&full_policy(), &options(), repository.path())
        .expect("the working tree is audited");

    let classified = report
        .findings
        .iter()
        .filter(|finding| {
            finding.remediation_class.code.is_some()
                || finding.remediation_class.none_reason.is_some()
        })
        .count();

    assert_eq!(
        classified,
        report.findings.len(),
        "every finding a run produces carries a declared remediation or a declared reason there is none"
    );
    assert!(
        report
            .findings
            .iter()
            .filter(|finding| finding.remediation_class.code.is_some())
            .count()
            > 50,
        "most registered rules declare a remediation; a near-empty result means assembly regressed"
    );
}
