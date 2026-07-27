//! Licensing: the licence file and its declaration in package metadata.

use crate::findings::Remediation;
use crate::policy::RuleInstance;

use super::{presence, AuditContext, Verdict};

/// The manifests airlock knows how to read a licence out of.
const MANIFESTS: &[&str] = &["Cargo.toml", "package.json", "pubspec.yaml"];

/// The dual-licence pattern the standard rejects, in both orders.
const DUAL_SPDX: &[&str] = &["MIT OR Apache-2.0", "Apache-2.0 OR MIT"];

pub(crate) fn run(id: &str, _rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-LIC-01" => presence(context, "LICENSE", "a LICENSE file"),
        "REPO-LIC-03" => not_dual_licensed(context),
        "REPO-LIC-04" => license_declared_in_metadata(context),
        _ => return None,
    })
}

fn not_dual_licensed(context: &AuditContext) -> Verdict {
    let mut evidence = Vec::new();

    if context.snapshot.entry("LICENSE-MIT").is_some()
        && context.snapshot.entry("LICENSE-APACHE").is_some()
    {
        evidence.push("both LICENSE-MIT and LICENSE-APACHE are present".to_owned());
    }

    for manifest in MANIFESTS {
        let Some(text) = context.text(manifest) else {
            continue;
        };
        for pattern in DUAL_SPDX {
            if text.contains(pattern) {
                evidence.push(format!("{manifest} declares `{pattern}`"));
            }
        }
    }

    if evidence.is_empty() {
        Verdict::pass(
            "not_dual_licensed",
            "no MIT OR Apache-2.0 dual licence is declared",
        )
    } else {
        Verdict::fail(
            "dual_licensed",
            evidence.join("; "),
            Remediation::new(
                "choose_one_license",
                "Pick one licence. The dual MIT OR Apache-2.0 arrangement is a Rust ecosystem \
                 convention the standard does not follow.",
            ),
        )
    }
}

fn license_declared_in_metadata(context: &AuditContext) -> Verdict {
    let present: Vec<&&str> = MANIFESTS
        .iter()
        .filter(|manifest| context.has_file(manifest))
        .collect();

    if present.is_empty() {
        return Verdict::inconclusive(
            "no_package_manifest",
            "the repository carries no Cargo.toml, package.json, or pubspec.yaml, so whether it \
             publishes to a registry could not be determined",
        );
    }

    let mut declared = Vec::new();
    let mut undeclared = Vec::new();
    for manifest in present {
        if manifest_declares_license(context, manifest) {
            declared.push(*manifest);
        } else {
            undeclared.push(*manifest);
        }
    }

    if undeclared.is_empty() {
        Verdict::pass(
            "license_declared_in_metadata",
            format!("{} declares a licence", declared.join(", ")),
        )
    } else {
        Verdict::fail(
            "license_missing_from_metadata",
            format!("{} declares no licence", undeclared.join(", ")),
            Remediation::new(
                "declare_license",
                "Add the licence identifier to the package metadata.",
            ),
        )
    }
}

fn manifest_declares_license(context: &AuditContext, manifest: &str) -> bool {
    let Some(text) = context.text(manifest) else {
        return false;
    };
    match manifest {
        "Cargo.toml" => cargo_declares_license(text),
        "package.json" => serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|value| {
                value
                    .get("license")
                    .and_then(|license| license.as_str().map(ToOwned::to_owned))
            })
            .is_some_and(|license| !license.trim().is_empty()),
        _ => text.lines().any(|line| {
            line.trim_start().starts_with("license:")
                && line
                    .split_once(':')
                    .is_some_and(|(_, value)| !value.trim().is_empty())
        }),
    }
}

/// A Cargo manifest declares a licence directly, through workspace
/// inheritance, or as a workspace root others inherit from.
fn cargo_declares_license(text: &str) -> bool {
    let Ok(manifest) = text.parse::<toml::Value>() else {
        return false;
    };

    let workspace_license = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("license"))
        .is_some();

    let package_license = manifest
        .get("package")
        .and_then(|package| package.get("license"));

    match package_license {
        Some(toml::Value::String(license)) => !license.trim().is_empty(),
        // `license.workspace = true` only declares a licence if the workspace
        // has one, and airlock is reading the root manifest here.
        Some(toml::Value::Table(table)) => {
            table.get("workspace").and_then(toml::Value::as_bool) == Some(true)
        }
        _ => workspace_license,
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let policy = policy();
        let context = context(&snapshot, &policy, Vec::new());
        evaluate(&rule(id), &context).status
    }

    #[test]
    fn a_license_file_passes() {
        assert_eq!(
            verdict("REPO-LIC-01", &[("LICENSE", "Apache License")]),
            Status::Pass
        );
        assert_eq!(verdict("REPO-LIC-01", &[]), Status::Fail);
    }

    #[test]
    fn a_dual_license_pair_fails() {
        assert_eq!(
            verdict(
                "REPO-LIC-03",
                &[("LICENSE-MIT", "MIT"), ("LICENSE-APACHE", "Apache")]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_dual_spdx_expression_in_a_manifest_fails() {
        assert_eq!(
            verdict(
                "REPO-LIC-03",
                &[("Cargo.toml", "[package]\nlicense = \"MIT OR Apache-2.0\"\n")]
            ),
            Status::Fail
        );
    }

    #[test]
    fn a_single_license_passes() {
        assert_eq!(
            verdict(
                "REPO-LIC-03",
                &[("Cargo.toml", "[package]\nlicense = \"Apache-2.0\"\n")]
            ),
            Status::Pass
        );
    }

    #[test]
    fn a_repository_with_no_manifest_is_inconclusive_not_passing() {
        assert_eq!(verdict("REPO-LIC-04", &[]), Status::Inconclusive);
    }

    #[test]
    fn a_manifest_without_a_license_fails() {
        assert_eq!(
            verdict(
                "REPO-LIC-04",
                &[("Cargo.toml", "[package]\nname = \"x\"\n")]
            ),
            Status::Fail
        );
    }

    #[test]
    fn workspace_inheritance_counts_as_a_declaration() {
        assert_eq!(
            verdict(
                "REPO-LIC-04",
                &[(
                    "Cargo.toml",
                    "[workspace]\nmembers = []\n[workspace.package]\nlicense = \"Apache-2.0\"\n"
                )]
            ),
            Status::Pass
        );
    }

    #[test]
    fn a_package_json_license_counts() {
        assert_eq!(
            verdict(
                "REPO-LIC-04",
                &[(
                    "package.json",
                    "{\"name\":\"x\",\"license\":\"Apache-2.0\"}"
                )]
            ),
            Status::Pass
        );
    }
}
