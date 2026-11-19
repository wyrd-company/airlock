//! Classification: custom properties stay an organisation concern.

use crate::findings::Fix;
use crate::policy::EffectiveRule;
use crate::FixGroup;

use super::{repo_settings, AuditContext, Verdict};

/// Resolve the declared prerequisite without consulting repository-owned files.
/// The shared applicability boundary calls this after known maturity scope.
pub(crate) fn prerequisites(
    rule: &EffectiveRule,
    context: &AuditContext,
) -> Result<(), Box<Verdict>> {
    for property in crate::classification::Property::required_by(rule.def.id) {
        let values = context.custom_properties.as_ref().map_err(|error| {
            Box::new(
                if context.credential == crate::rules::CredentialCapability::Unauthenticated
                    && error.cause == crate::github::ErrorCause::Unauthenticated
                {
                    Verdict::needs_github_api()
                } else {
                    Verdict::from_api_error(error)
                },
            )
        })?;
        let value = property
            .read(values)
            .map_err(|detail| Box::new(Verdict::run_error("classification_malformed", detail)))?;
        if value.is_none() {
            return Err(Box::new(Verdict {
                status: None,
                evidence: Some(crate::findings::Evidence::new(
                    property.undeclared_code(),
                    format!(
                        "The organization has not declared `{}` for this repository",
                        property.name()
                    ),
                )),
                fix: None,
                error: None,
                routing: Some(crate::findings::Routing {
                    reason: "out-of-scope".to_owned(),
                    settling_surface: "Declare classification through the interactive session"
                        .to_owned(),
                }),
            }));
        }
    }
    Ok(())
}

/// Ways a workflow reaches the custom-properties endpoints.
const PROPERTY_WRITE_SIGNALS: &[&str] = &[
    "properties/values",
    "properties/schema",
    "/orgs/{org}/properties",
];

pub(crate) fn run(id: &str, _rule: &EffectiveRule, context: &AuditContext) -> Option<Verdict> {
    Some(match id {
        "REPO-PROP-03" => no_declared_custom_properties(context),
        "REPO-PROP-04" => no_workflow_writes_properties(context),
        _ => return None,
    })
}

fn no_declared_custom_properties(context: &AuditContext) -> Verdict {
    let settings = try_verdict!(repo_settings(context));

    let declared: Vec<&str> = ["properties", "custom-properties", "custom_properties"]
        .into_iter()
        .filter(|key| settings.get(key).is_some())
        .collect();

    if declared.is_empty() {
        Verdict::pass_at(
            "no_custom_properties_declared",
            ".github/airlock.yml",
            "no custom property values are declared",
        )
    } else {
        Verdict::fail_at(
            "custom_properties_declared",
            ".github/airlock.yml",
            format!("the declared settings file carries {}", declared.join(", ")),
            Fix::new(
                FixGroup::REMOVE_CUSTOM_PROPERTIES,
                "Remove custom property values. Classification is set on the organisation, not \
                 claimed by the repository.",
            ),
        )
    }
}

fn no_workflow_writes_properties(context: &AuditContext) -> Verdict {
    if context.workflows_truncated {
        return Verdict::run_error(
            "workflow_listing_truncated",
            "the workflow listing was cut short by a budget, so the absence of a property-writing \
             workflow could not be established",
        );
    }

    let offenders: Vec<String> = context
        .workflows
        .iter()
        .filter_map(|workflow| {
            let found = super::workflow_signals(&workflow.text, PROPERTY_WRITE_SIGNALS);
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
            Fix::new(
                FixGroup::REMOVE_PROPERTY_WRITES,
                "Set organisation custom properties from the organisation, not from a repository \
                 workflow.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{evaluate, Verdict};
    use crate::findings::Status;

    fn verdict(id: &str, files: &[(&str, &str)]) -> Option<Status> {
        let snapshot = snapshot(files);
        let workflows = workflows(&snapshot);
        let policy = policy();
        let context = context(&snapshot, &policy, workflows);
        evaluate(&rule(id), &context).status
    }

    fn prerequisite(id: &str, values: Vec<crate::github::CustomPropertyValue>) -> Verdict {
        let snapshot = snapshot(&[(
            ".github/airlock.yml",
            "classification:\n  audience: forged\n  family: forged\n  category: forged\n",
        )]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, Vec::new());
        context.custom_properties = Ok(values);
        super::prerequisites(&rule(id), &context)
            .expect_err("undeclared prerequisite")
            .as_ref()
            .clone()
    }

    macro_rules! missing {
        ($name:ident, $id:literal, $property:literal) => {
            #[test]
            fn $name() {
                let verdict = prerequisite($id, Vec::new());
                assert_eq!(verdict.status, None);
                assert_eq!(verdict.error, None);
                assert_eq!(verdict.routing.unwrap().reason, "out-of-scope");
                assert_eq!(
                    verdict.evidence.unwrap().code,
                    concat!("classification_", $property, "_undeclared")
                );
            }
        };
    }

    missing!(
        placement_needs_org_owned_audience,
        "REPO-ORG-01",
        "audience"
    );
    missing!(
        graduation_needs_org_owned_audience,
        "REPO-ORG-02",
        "audience"
    );
    missing!(
        dotted_name_needs_org_owned_category,
        "REPO-NAME-02",
        "category"
    );
    missing!(
        family_prefix_needs_org_owned_family,
        "REPO-NAME-03",
        "family"
    );
    missing!(
        family_agreement_needs_org_owned_family,
        "REPO-NAME-04",
        "family"
    );
    missing!(
        family_topic_needs_org_owned_family,
        "REPO-META-08",
        "family"
    );
    missing!(license_needs_org_owned_category, "REPO-LIC-02", "category");

    #[test]
    fn property_read_failure_remains_a_run_error() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, Vec::new());
        context.custom_properties = Err(crate::github::ApiError::local(
            crate::github::ErrorCause::Permission,
            "GET /repos/sample-owner/sample-repository/properties/values",
            "read refused",
        ));
        let verdict = super::prerequisites(&rule("REPO-ORG-01"), &context).unwrap_err();
        assert_eq!(verdict.status, None);
        assert_eq!(verdict.routing, None);
        assert_eq!(verdict.error.as_ref().unwrap().cause, "permission");
    }

    #[test]
    fn local_unobserved_classification_routes_to_an_api_audit() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, Vec::new());
        context.credential = crate::rules::CredentialCapability::Unauthenticated;
        context.custom_properties = Err(crate::github::ApiError::local(
            crate::github::ErrorCause::Unauthenticated,
            "local://not-observed/classification",
            "not observed",
        ));
        let verdict = super::prerequisites(&rule("REPO-ORG-01"), &context).unwrap_err();
        assert_eq!(verdict.status, None);
        assert_eq!(verdict.error, None);
        assert_eq!(verdict.routing.as_ref().unwrap().reason, "needs-github-api");
    }

    #[test]
    fn unrelated_rules_do_not_read_classification() {
        let snapshot = snapshot(&[]);
        let policy = policy();
        let mut context = context(&snapshot, &policy, Vec::new());
        context.custom_properties = Err(crate::github::ApiError::local(
            crate::github::ErrorCause::Permission,
            "fixture://unavailable",
            "not observed",
        ));
        assert!(super::prerequisites(&rule("REPO-META-01"), &context).is_ok());
    }

    #[test]
    fn declared_custom_properties_fail() {
        assert_eq!(
            verdict(
                "REPO-PROP-03",
                &[(".github/airlock.yml", "properties:\n  tier: gold\n")]
            ),
            Some(Status::Gap)
        );
        assert_eq!(
            verdict(
                "REPO-PROP-03",
                &[(".github/airlock.yml", "description: x\n")]
            ),
            Some(Status::Met)
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
            Some(Status::Gap)
        );
        assert_eq!(
            verdict(
                "REPO-PROP-04",
                &[(
                    ".github/workflows/x.yml",
                    "jobs:\n  a:\n    steps:\n      - run: task check\n"
                )]
            ),
            Some(Status::Met)
        );
    }
}
