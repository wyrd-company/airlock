use super::*;

pub(super) fn compile(
    source: &PolicySource,
    document: &Yaml,
    reference_data: BTreeMap<String, Yaml>,
    sources: Vec<BundleSource>,
) -> Result<ResolvedPolicy> {
    reject_unknown_keys(document, KNOWN_TOP_LEVEL_KEYS, |key| {
        Error::Policy(format!(
            "unknown policy key `{key}`; airlock accepts {}",
            KNOWN_TOP_LEVEL_KEYS.join(", ")
        ))
    })?;

    match document.get("version").and_then(Yaml::as_i64) {
        Some(POLICY_SCHEMA_VERSION) => {}
        Some(other) => {
            return Err(Error::Policy(format!(
                "policy schema version {other} is not supported; airlock understands version \
                 {POLICY_SCHEMA_VERSION}"
            )))
        }
        None => {
            return Err(Error::Policy(
                "the policy must declare `version: 1`".to_owned(),
            ))
        }
    }

    let name = document
        .get("name")
        .and_then(Yaml::as_str)
        .ok_or_else(|| Error::Policy("the policy must declare a `name`".to_owned()))?
        .to_owned();

    check_registry_requirement(document)?;

    let gate = match document.get("gate").and_then(Yaml::as_str) {
        Some(value) => Gate::parse(value).ok_or_else(|| {
            Error::Policy(format!(
                "unknown gate `{value}`; airlock accepts `blocking` or `required`"
            ))
        })?,
        None => {
            return Err(Error::Policy(
                "the policy must declare a `gate` of `blocking` or `required`".to_owned(),
            ))
        }
    };

    let capabilities = read_capabilities(document)?;
    let conditions = read_apply(document, &capabilities)?;
    let mut rules = expand_capabilities(&capabilities, &conditions);
    apply_check_refinements(document, &mut rules)?;

    let suppressions = read_suppressions(document, &rules)?;

    let mut rules: Vec<RuleInstance> = rules.into_values().collect();
    rules.sort_by(|left, right| left.def.id.cmp(right.def.id));

    let bundle_digest = bundle_digest(&sources, &rules, gate);

    Ok(ResolvedPolicy {
        name,
        source: source.label(),
        commit: sources.first().and_then(|first| first.commit.clone()),
        bundle_digest,
        sources,
        gate,
        rules,
        suppressions,
        reference_data,
    })
}

fn check_registry_requirement(document: &Yaml) -> Result<()> {
    let Some(requirement) = document.get("requires-registry") else {
        return Ok(());
    };
    let Some(requirement) = requirement.as_str() else {
        return Err(Error::Policy(
            "`requires-registry` should be a semver requirement string".to_owned(),
        ));
    };
    let requirement = semver::VersionReq::parse(requirement).map_err(|error| {
        Error::Policy(format!(
            "`requires-registry: {requirement}` is not a semver requirement: {error}"
        ))
    })?;
    let version = semver::Version::parse(REGISTRY_VERSION).map_err(|error| {
        Error::Policy(format!("the compiled registry version is invalid: {error}"))
    })?;
    if !requirement.matches(&version) {
        return Err(Error::Policy(format!(
            "this airlock carries check registry {REGISTRY_VERSION}, which does not satisfy the \
             policy's `requires-registry: {requirement}`"
        )));
    }
    Ok(())
}

fn read_capabilities(document: &Yaml) -> Result<Vec<(String, Vec<Section>)>> {
    let Some(capabilities) = document.get("capabilities") else {
        return Err(Error::Policy(
            "the policy must declare at least one capability".to_owned(),
        ));
    };
    let Some(entries) = capabilities.as_map() else {
        return Err(Error::Policy(format!(
            "`capabilities` should be a mapping of capability name to sections, found {}",
            capabilities.kind()
        )));
    };
    if entries.is_empty() {
        return Err(Error::Policy(
            "the policy must declare at least one capability".to_owned(),
        ));
    }

    let mut capabilities = Vec::new();
    for (capability, value) in entries {
        let Some(sections) = value.as_seq() else {
            return Err(Error::Policy(format!(
                "capability `{capability}` should list sections, found {}",
                value.kind()
            )));
        };
        let mut parsed = Vec::new();
        for section in sections {
            let Some(section) = section.as_str() else {
                return Err(Error::Policy(format!(
                    "capability `{capability}` should list section names as strings"
                )));
            };
            let section = Section::parse(section).ok_or_else(|| {
                Error::Policy(format!(
                    "unknown section `{section}` in capability `{capability}`; airlock knows {}",
                    Section::ALL
                        .iter()
                        .map(|section| section.code())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            parsed.push(section);
        }
        capabilities.push((capability.clone(), parsed));
    }
    Ok(capabilities)
}

fn read_apply(
    document: &Yaml,
    capabilities: &[(String, Vec<Section>)],
) -> Result<BTreeMap<String, Condition>> {
    let mut conditions: BTreeMap<String, Condition> = capabilities
        .iter()
        .map(|(name, _)| (name.clone(), Condition::Always))
        .collect();

    let Some(apply) = document.get("apply") else {
        return Ok(conditions);
    };
    let Some(entries) = apply.as_map() else {
        return Err(Error::Policy(format!(
            "`apply` should be a mapping of capability name to condition, found {}",
            apply.kind()
        )));
    };

    for (capability, value) in entries {
        if !conditions.contains_key(capability) {
            return Err(Error::Policy(format!(
                "`apply` names capability `{capability}`, which `capabilities` does not declare"
            )));
        }
        let condition = match value {
            Yaml::String(name) => Condition::parse(name).ok_or_else(|| {
                Error::Policy(format!(
                    "unknown condition `{name}` on capability `{capability}`"
                ))
            })?,
            Yaml::Map(_) => {
                let when = value.get("when").and_then(Yaml::as_str).ok_or_else(|| {
                    Error::Policy(format!(
                        "capability `{capability}` should be applied `always` or under a `when:` \
                         condition"
                    ))
                })?;
                for key in value.keys() {
                    if key != "when" {
                        return Err(Error::Policy(format!(
                            "unknown key `{key}` in the `apply` entry for `{capability}`"
                        )));
                    }
                }
                Condition::parse(when).ok_or_else(|| {
                    Error::Policy(format!(
                        "unknown condition `{when}` on capability `{capability}`"
                    ))
                })?
            }
            other => {
                return Err(Error::Policy(format!(
                    "the `apply` entry for `{capability}` should be a condition name or a `when:` \
                     mapping, found {}",
                    other.kind()
                )))
            }
        };
        conditions.insert(capability.clone(), condition);
    }
    Ok(conditions)
}

/// Expand capabilities into rule instances.
///
/// A rule reachable through more than one capability is instantiated once; the
/// first capability that names it, in declaration order, owns its provenance.
fn expand_capabilities(
    capabilities: &[(String, Vec<Section>)],
    conditions: &BTreeMap<String, Condition>,
) -> BTreeMap<&'static str, RuleInstance> {
    let mut rules: BTreeMap<&'static str, RuleInstance> = BTreeMap::new();
    for (capability, sections) in capabilities {
        let condition = conditions
            .get(capability)
            .copied()
            .unwrap_or(Condition::Always);
        for section in sections {
            for def in registry::in_section(*section) {
                rules.entry(def.id).or_insert_with(|| RuleInstance {
                    def,
                    severity: def.severity,
                    params: BTreeMap::new(),
                    provenance: format!("capability:{capability}/{section}"),
                    condition,
                });
            }
        }
    }
    rules
}

fn apply_check_refinements(
    document: &Yaml,
    rules: &mut BTreeMap<&'static str, RuleInstance>,
) -> Result<()> {
    let Some(checks) = document.get("checks") else {
        return Ok(());
    };
    let Some(entries) = checks.as_map() else {
        return Err(Error::Policy(format!(
            "`checks` should be a mapping of rule id to refinement, found {}",
            checks.kind()
        )));
    };

    for (id, refinement) in entries {
        let def = registry::find(id).ok_or_else(|| {
            Error::Policy(format!(
                "`checks` names `{id}`, which is not a rule airlock knows"
            ))
        })?;
        if !rules.contains_key(def.id) {
            return Err(Error::Policy(format!(
                "`checks` refines `{id}`, which no enabled capability brings in"
            )));
        }
        let Some(fields) = refinement.as_map() else {
            return Err(Error::Policy(format!(
                "the `checks` entry for `{id}` should be a mapping, found {}",
                refinement.kind()
            )));
        };
        for (key, _) in fields {
            if !["params", "severity", "enabled"].contains(&key.as_str()) {
                return Err(Error::Policy(format!(
                    "unknown key `{key}` in the `checks` entry for `{id}`; airlock accepts \
                     params, severity, enabled"
                )));
            }
        }

        // `enabled: false` always wins, whatever else the entry says.
        if refinement.get("enabled").and_then(Yaml::as_bool) == Some(false) {
            rules.remove(def.id);
            continue;
        }

        let rule = rules.get_mut(def.id).expect("membership checked above");
        rule.provenance = format!("{};refined-by:checks", rule.provenance);

        if let Some(severity) = refinement.get("severity") {
            let Some(severity) = severity.as_str().and_then(Severity::parse) else {
                return Err(Error::Policy(format!(
                    "unknown severity in the `checks` entry for `{id}`; airlock accepts blocking, \
                     required, observation"
                )));
            };
            rule.severity = severity;
        }

        if let Some(params) = refinement.get("params") {
            let Some(params) = params.as_map() else {
                return Err(Error::Policy(format!(
                    "`params` in the `checks` entry for `{id}` should be a mapping, found {}",
                    params.kind()
                )));
            };
            for (name, value) in params {
                if !def.params.contains(&name.as_str()) {
                    return Err(Error::Policy(format!(
                        "`{id}` declares no parameter `{name}`; it accepts {}",
                        if def.params.is_empty() {
                            "none".to_owned()
                        } else {
                            def.params.join(", ")
                        }
                    )));
                }
                rule.params.insert(name.clone(), to_json(value));
            }
        }
    }
    Ok(())
}

fn to_json(value: &Yaml) -> serde_json::Value {
    match value {
        Yaml::Null => serde_json::Value::Null,
        Yaml::Bool(value) => serde_json::Value::Bool(*value),
        Yaml::Int(value) => serde_json::Value::from(*value),
        Yaml::Float(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Yaml::String(value) => serde_json::Value::String(value.clone()),
        Yaml::Seq(values) => serde_json::Value::Array(values.iter().map(to_json).collect()),
        Yaml::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect(),
        ),
    }
}
