//! Classification: custom properties stay an organisation concern.

use crate::findings::Remediation;
use crate::policy::RuleInstance;

use super::{repo_settings, AuditContext, Verdict};

/// Ways a workflow reaches the custom-properties endpoints.
const PROPERTY_WRITE_SIGNALS: &[&str] = &[
    "properties/values",
    "properties/schema",
    "/orgs/{org}/properties",
];

pub(crate) fn run(id: &str, _rule: &RuleInstance, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-PROP-03" => no_declared_custom_properties(context),
        "REPO-PROP-04" => no_workflow_writes_properties(context),
        _ => return None,
    })
}

fn no_declared_custom_properties(context: &AuditContext) -> Verdict {
    let settings = match repo_settings(context) {
        Ok(settings) => settings,
        Err(verdict) => return *verdict,
    };

    let declared: Vec<&str> = ["properties", "custom-properties", "custom_properties"]
        .into_iter()
        .filter(|key| settings.get(key).is_some())
        .collect();

    if declared.is_empty() {
        Verdict::pass_at(
            "no_custom_properties_declared",
            ".github/repo-settings.yml",
            "no custom property values are declared",
        )
    } else {
        Verdict::fail_at(
            "custom_properties_declared",
            ".github/repo-settings.yml",
            format!("the declared settings file carries {}", declared.join(", ")),
            Remediation::new(
                "remove_custom_properties",
                "Remove custom property values. Classification is set on the organisation, not \
                 claimed by the repository.",
            ),
        )
    }
}

fn no_workflow_writes_properties(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::inconclusive(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget, so the absence of a property-writing \
             workflow could not be established",
        );
    }

    let offenders: Vec<String> = context
        .workflows
        .iter()
        .filter_map(|workflow| {
            let found: Vec<&&str> = PROPERTY_WRITE_SIGNALS
                .iter()
                .filter(|signal| workflow.text.contains(**signal))
                .collect();
            if found.is_empty() {
                None
            } else {
                Some(format!(
                    "{} references {}",
                    workflow.path,
                    found
                        .iter()
                        .map(|signal| (**signal).to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        })
        .collect();

    if offenders.is_empty() {
        Verdict::pass(
            "no_workflow_writes_properties",
            "no workflow reaches the custom-properties endpoints",
        )
    } else {
        Verdict::fail(
            "workflow_writes_properties",
            offenders.join("; "),
            Remediation::new(
                "remove_property_writes",
                "Set organisation custom properties from the organisation, not from a repository \
                 workflow.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate;
    use super::super::fixtures::*;
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Status {
        let snapshot = snapshot(files);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        evaluate(&rule(id), &context).status
    }

    #[test]
    fn declared_custom_properties_fail() {
        assert_eq!(
            verdict(
                "REPO-PROP-03",
                &[(".github/repo-settings.yml", "properties:\n  tier: gold\n")]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict(
                "REPO-PROP-03",
                &[(".github/repo-settings.yml", "description: x\n")]
            ),
            Status::Pass
        );
    }

    #[test]
    fn a_workflow_touching_the_properties_endpoints_fails() {
        assert_eq!(
            verdict(
                "REPO-PROP-04",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - run: gh api -X PATCH repos/o/n/properties/values\n"
                )]
            ),
            Status::Fail
        );
        assert_eq!(
            verdict(
                "REPO-PROP-04",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - run: task check\n"
                )]
            ),
            Status::Pass
        );
    }
}
