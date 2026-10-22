// ---
// relationships:
//   references: fix
// ---

//! Coded fix plans only. Applying them belongs to a separately authorized adapter.

use super::{
    config::{Condition, FixDeclaration, ProbeRequest},
    report::{Fix, Fixer},
};
use serde_json::{json, Value};

pub(crate) fn derive(probe: &ProbeRequest, condition: &Condition, expected: &Value) -> Fix {
    if condition.evaluation == "equal" {
        if probe.kind == "file-content" && condition.pointer == "/contents" && expected.is_string()
        {
            return action(
                "set-file-content",
                json!({"path":probe.input["path"],"contents":expected}),
            )
            .expect("coded derivation is valid");
        }
        if probe.kind == "repository"
            && [
                "/has-wiki",
                "/has-projects",
                "/has-discussions",
                "/has-issues",
                "/allow-merge-commit",
                "/allow-squash-merge",
                "/allow-rebase-merge",
                "/delete-branch-on-merge",
            ]
            .contains(&condition.pointer.as_str())
            && expected.is_boolean()
        {
            return action(
                "set-repository-setting",
                json!({"setting":&condition.pointer[1..],"value":expected}),
            )
            .expect("coded derivation is valid");
        }
    }
    Fix::NotFixable {
        reason:
            "this probe and evaluation have no unambiguous coded fix; supply a rule fix declaration"
                .into(),
    }
}

pub(crate) fn validate(declaration: &FixDeclaration) -> Result<(), String> {
    match declaration {
        FixDeclaration::Action {
            action: kind,
            input,
        } => action(kind, input.clone()).map(|_| ()),
        FixDeclaration::Agent { guidance } if guidance.trim().is_empty() => {
            Err("agent fix needs guidance".into())
        }
        FixDeclaration::Block { reason } if reason.trim().is_empty() => {
            Err("blocked fix needs a reason".into())
        }
        FixDeclaration::Complete { input } if !input.is_object() => {
            Err("fix completion input must be an object".into())
        }
        _ => Ok(()),
    }
}

pub(crate) fn apply(derived: Fix, declaration: Option<&FixDeclaration>) -> Fix {
    match declaration {
        None => derived,
        Some(FixDeclaration::Agent { guidance }) => Fix::Agent {
            guidance: guidance.clone(),
        },
        Some(FixDeclaration::Block { reason }) => Fix::NotFixable {
            reason: reason.clone(),
        },
        Some(FixDeclaration::Action {
            action: kind,
            input,
        }) => action(kind, input.clone()).unwrap_or_else(|reason| Fix::NotFixable { reason }),
        Some(FixDeclaration::Complete { input: completion }) => {
            if let Fix::Action {
                action: kind,
                mut input,
                ..
            } = derived
            {
                if let (Some(values), Some(extra)) = (input.as_object_mut(), completion.as_object())
                {
                    for (key, value) in extra {
                        if values.get(key).is_some_and(|known| known != value) {
                            return Fix::NotFixable { reason: format!("fix completion conflicts with derived input {key}; use mode: action for an explicit replacement") };
                        }
                    }
                    for (key, value) in extra {
                        values.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                }
                action(&kind, input).unwrap_or_else(|reason| Fix::NotFixable { reason })
            } else {
                Fix::NotFixable { reason: "there is no derived coded action to complete; declare an action or agent guidance".into() }
            }
        }
    }
}

fn action(kind: &str, input: Value) -> Result<Fix, String> {
    let schema = match kind {
        "set-file-content" => {
            json!({"type":"object","required":["path","contents"],"properties":{"path":{"type":"string","minLength":1},"contents":{"type":"string"}},"additionalProperties":false})
        }
        "set-repository-setting" => {
            json!({"type":"object","required":["setting","value"],"properties":{"setting":{"enum":["has-wiki","has-projects","has-discussions","has-issues","allow-merge-commit","allow-squash-merge","allow-rebase-merge","delete-branch-on-merge"]},"value":{"type":"boolean"}},"additionalProperties":false})
        }
        _ => return Err(format!("unknown coded fix action {kind}")),
    };
    super::validate_schema(&schema, &input)?;
    Ok(Fix::Action {
        fixer: if kind == "set-file-content" {
            Fixer::Airlock
        } else {
            Fixer::Person
        },
        action: kind.into(),
        input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_fills_missing_plan_inputs_and_accepts_identical_known_values() {
        let derived = Fix::Action {
            fixer: Fixer::Airlock,
            action: "set-file-content".into(),
            input: json!({"path":"assets/handbook.txt"}),
        };
        let completion = FixDeclaration::Complete {
            input: json!({"path":"assets/handbook.txt","contents":"sample"}),
        };
        let completed = apply(derived, Some(&completion));
        assert!(
            matches!(completed,Fix::Action {input,..} if input==json!({"path":"assets/handbook.txt","contents":"sample"}))
        );
    }

    #[test]
    fn conflicting_completion_is_unavailable_while_explicit_replacement_can_retarget() {
        for (action_name, known, conflicting) in [
            (
                "set-file-content",
                json!({"path":"assets/handbook.txt","contents":"sample"}),
                json!({"path":"assets/other.txt","contents":"sample"}),
            ),
            (
                "set-repository-setting",
                json!({"setting":"has-wiki","value":false}),
                json!({"setting":"has-projects","value":false}),
            ),
        ] {
            let derived = Fix::Action {
                fixer: Fixer::Airlock,
                action: action_name.into(),
                input: known,
            };
            let completion = FixDeclaration::Complete {
                input: conflicting.clone(),
            };
            assert!(
                matches!(apply(derived.clone(),Some(&completion)),Fix::NotFixable {reason} if reason.contains("conflicts") && reason.contains("mode: action"))
            );
            let replacement = FixDeclaration::Action {
                action: action_name.into(),
                input: conflicting.clone(),
            };
            assert!(
                matches!(apply(derived,Some(&replacement)),Fix::Action {input,..} if input==conflicting)
            );
        }
    }
}
