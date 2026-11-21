//! Reasoned configuration shared by organization grants and repository requests.
//
// relationships:
//   implements: release-process-conformance

use super::*;

pub(super) fn parse(document: &Yaml, repository: bool) -> Result<BTreeMap<String, Exception>> {
    let Some(value) = document.get("exceptions") else {
        return Ok(BTreeMap::new());
    };
    let entries = value
        .as_map()
        .ok_or_else(|| Error::Policy("exceptions must be a mapping".into()))?;
    entries
        .iter()
        .map(|(id, value)| {
            let def = rules::find(id)
                .ok_or_else(|| Error::Policy(format!("unknown rule {id} in exceptions")))?;
            Ok((id.clone(), parse_entry(def, value, repository, true)?))
        })
        .collect()
}

fn parse_entry(
    def: &'static RuleDefinition,
    value: &Yaml,
    repository: bool,
    nested: bool,
) -> Result<Exception> {
    let fields = value
        .as_map()
        .ok_or_else(|| Error::Policy(format!("exceptions.{} must be a mapping", def.id)))?;
    let reason = value
        .get("reason")
        .and_then(Yaml::as_str)
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| Error::Policy(format!("exceptions.{} requires a reason", def.id)))?
        .to_owned();
    let severity = value
        .get("severity")
        .map(|v| {
            v.as_str()
                .and_then(Severity::parse)
                .ok_or_else(|| Error::Policy(format!("invalid severity in exceptions.{}", def.id)))
        })
        .transpose()?;
    let allow_override = value
        .get("allow-override")
        .map(|v| {
            v.as_bool().ok_or_else(|| {
                Error::Policy(format!("allow-override on {} must be boolean", def.id))
            })
        })
        .transpose()?;
    if !repository && allow_override == Some(true) && !def.allow_override() {
        return Err(Error::Policy(format!(
            "{} forbids repository overrides; organization may only tighten",
            def.id
        )));
    }
    let mut result = Exception {
        reason,
        severity,
        allow_override,
        ..Exception::default()
    };
    for (key, value) in fields {
        match key.as_str() {
            "reason" | "severity" | "allow-override" => {}
            "repositories" if nested && !repository => {
                let entries = value
                    .as_map()
                    .ok_or_else(|| Error::Policy("repositories must be a mapping".into()))?;
                for (name, value) in entries {
                    if !name.split_once('/').is_some_and(|(owner, repo)| {
                        !owner.is_empty() && !repo.is_empty() && !repo.contains('/')
                    }) {
                        return Err(Error::Policy(
                            "repository exception must name owner/repo".into(),
                        ));
                    }
                    result
                        .repositories
                        .insert(name.clone(), parse_entry(def, value, false, false)?);
                }
            }
            name if def.params.iter().any(|p| p.name == name) => {
                result.params.insert(name.into(), to_json(value));
            }
            _ => {
                return Err(Error::Policy(format!(
                    "unknown key {key} in exceptions.{}",
                    def.id
                )))
            }
        }
    }
    let mut probe = EffectiveRule {
        def,
        severity: def.severity,
        params: BTreeMap::new(),
        provenance: String::new(),
    };
    apply(&mut probe, &result)?;
    Ok(result)
}

pub(super) fn apply(rule: &mut EffectiveRule, exception: &Exception) -> Result<()> {
    if let Some(severity) = exception.severity {
        rule.severity = severity;
    }
    rule.params.extend(exception.params.clone());
    rule.provenance
        .push_str(&format!(";exception:{}", exception.reason));
    for parameter in rule.def.params {
        let Some(value) = rule.params.get(parameter.name) else {
            continue;
        };
        let valid = match parameter.default {
            rules::ParameterDefault::Integer(_) => value.as_u64().is_some(),
            rules::ParameterDefault::String(_) => value.is_string(),
            rules::ParameterDefault::Strings(_) => value
                .as_array()
                .is_some_and(|v| v.iter().all(serde_json::Value::is_string)),
            rules::ParameterDefault::Required => true,
        };
        if !valid {
            return Err(Error::Policy(format!(
                "invalid {} parameter on {}",
                parameter.name, rule.def.id
            )));
        }
    }
    if rule.def.required_topic_categories().is_some() {
        if let Some(value) = rule.params.get("topics") {
            let categories = value.as_object().ok_or_else(|| {
                Error::Policy("topics must map categories to string lists".into())
            })?;
            if categories.values().any(|v| {
                !v.as_array()
                    .is_some_and(|a| a.iter().all(serde_json::Value::is_string))
            }) {
                return Err(Error::Policy(
                    "topic categories must contain string lists".into(),
                ));
            }
        }
    }
    if rule.def.id == crate::template_identity::config::RULE {
        crate::template_identity::config::validate(rule)?;
    }
    Ok(())
}

pub(super) fn validate_required(rule: &mut EffectiveRule) -> Result<()> {
    if rule.def.params.iter().any(|p| {
        matches!(p.default, rules::ParameterDefault::Required) && !rule.params.contains_key(p.name)
    }) {
        rule.severity = Severity::None;
    }
    if rule.def.id == crate::template_identity::config::RULE
        && crate::template_identity::config::expected(rule)?.is_empty()
    {
        rule.severity = Severity::None;
    }
    Ok(())
}
