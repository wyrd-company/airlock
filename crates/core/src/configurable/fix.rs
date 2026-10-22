// ---
// relationships:
//   implements: configurable-rules
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
                    values.extend(extra.clone());
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
