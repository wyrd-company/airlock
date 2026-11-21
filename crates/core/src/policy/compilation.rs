use super::*;

pub(super) fn compile(
    source: &PolicySource,
    document: &Yaml,
    sources: Vec<BundleSource>,
) -> Result<ResolvedPolicy> {
    validate_document(document)?;
    let accepted_version = accepted_version(document)?;
    // Organization declarations are misplaced, never silently ignored.
    if document
        .keys()
        .any(|key| !["version", "exceptions"].contains(&key))
    {
        return Err(Error::Policy(
            "repository declarations belong in the repository .github/airlock.yml".into(),
        ));
    }
    let exceptions = super::exceptions::parse(document, false)?;
    let mut rules: Vec<_> = rules::RULES
        .iter()
        .map(|def| EffectiveRule {
            def,
            severity: def.severity,
            params: BTreeMap::new(),
            provenance: "compiled".into(),
        })
        .collect();
    for rule in &mut rules {
        if let Some(exception) = exceptions.get(rule.def.id) {
            super::exceptions::apply(rule, exception)?;
        }
        super::exceptions::validate_required(rule)?;
    }
    rules.sort_by_key(|rule| rule.def.id);
    let bundle_digest = bundle_digest(&sources, &rules);
    Ok(ResolvedPolicy {
        accepted_version,
        exceptions,
        name: match source {
            PolicySource::Remote { owner, .. } => owner.clone(),
            PolicySource::Local(path) => path.display().to_string(),
        },
        source: source.label(),
        commit: sources.first().and_then(|first| first.commit.clone()),
        bundle_digest,
        sources,
        rules,
        suppressions: SuppressionAuthority::default(),
    })
}

pub(crate) fn validate_document(document: &Yaml) -> Result<()> {
    reject_unknown_keys(document, KNOWN_TOP_LEVEL_KEYS, |key| {
        Error::Policy(format!(
            "unknown policy key `{key}`; airlock accepts {}",
            KNOWN_TOP_LEVEL_KEYS.join(", ")
        ))
    })?;
    for (name, keys) in [
        (
            "merge",
            &["squash", "rebase", "merge_commit", "delete_branch_on_merge"][..],
        ),
        (
            "features",
            &["wiki", "projects", "discussions", "issues"][..],
        ),
    ] {
        if let Some(group) = document.get(name) {
            if group.as_map().is_none() {
                return Err(Error::Policy(format!("{name} must be a mapping")));
            }
            reject_unknown_keys(group, keys, |key| {
                Error::Policy(format!("unknown key {key} in {name}"))
            })?;
        }
    }
    Ok(())
}

pub(crate) fn accepted_version(document: &Yaml) -> Result<semver::Version> {
    let value = document.get("version").and_then(Yaml::as_str)
        .ok_or_else(|| Error::Policy("configuration must declare version as an accepted Airlock release, for example 0.6.0".into()))?;
    semver::Version::parse(value)
        .map_err(|e| Error::Policy(format!("invalid accepted Airlock version: {e}")))
}

pub(super) fn to_json(value: &Yaml) -> serde_json::Value {
    match value {
        Yaml::Null => serde_json::Value::Null,
        Yaml::Bool(value) => (*value).into(),
        Yaml::Int(value) => (*value).into(),
        Yaml::Float(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Yaml::String(value) => value.clone().into(),
        Yaml::Seq(values) => serde_json::Value::Array(values.iter().map(to_json).collect()),
        Yaml::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect(),
        ),
    }
}
