use super::*;

pub(super) fn read_suppressions(
    document: &Yaml,
    rules: &BTreeMap<&'static str, RuleInstance>,
) -> Result<SuppressionAuthority> {
    let Some(suppressions) = document.get("suppressions") else {
        return Ok(SuppressionAuthority::default());
    };
    let Some(_) = suppressions.as_map() else {
        return Err(Error::Policy(format!(
            "`suppressions` should be a mapping, found {}",
            suppressions.kind()
        )));
    };
    reject_unknown_keys(suppressions, &["direct", "allow-repo-requests"], |key| {
        Error::Policy(format!(
            "unknown key `{key}` under `suppressions`; airlock accepts direct, \
                 allow-repo-requests"
        ))
    })?;

    let mut authority = SuppressionAuthority::default();

    if let Some(direct) = suppressions.get("direct") {
        let Some(items) = direct.as_seq() else {
            return Err(Error::Policy(format!(
                "`suppressions.direct` should be a sequence, found {}",
                direct.kind()
            )));
        };
        for item in items {
            reject_unknown_keys(item, &["rule", "repository", "reason"], |key| {
                Error::Policy(format!(
                    "unknown key `{key}` in a direct suppression; airlock accepts rule, \
                         repository, reason"
                ))
            })?;
            let rule = item.get("rule").and_then(Yaml::as_str).ok_or_else(|| {
                Error::Policy("every direct suppression must name a `rule`".to_owned())
            })?;
            registry::find(rule).ok_or_else(|| {
                Error::Policy(format!(
                    "a direct suppression names `{rule}`, which is not a rule airlock knows"
                ))
            })?;
            let reason = item
                .get("reason")
                .and_then(Yaml::as_str)
                .unwrap_or_default();
            if reason.trim().is_empty() {
                return Err(Error::Policy(format!(
                    "the direct suppression for `{rule}` must state a reason"
                )));
            }
            authority.direct.push(DirectSuppression {
                rule: rule.to_owned(),
                repository: item
                    .get("repository")
                    .and_then(Yaml::as_str)
                    .map(ToOwned::to_owned),
                reason: reason.to_owned(),
            });
        }
    }

    if let Some(allowed) = suppressions.get("allow-repo-requests") {
        let Some(items) = allowed.as_seq() else {
            return Err(Error::Policy(format!(
                "`suppressions.allow-repo-requests` should be a sequence, found {}",
                allowed.kind()
            )));
        };
        for item in items {
            let rule = item.as_str().ok_or_else(|| {
                Error::Policy(
                    "`suppressions.allow-repo-requests` should list rule ids as strings".to_owned(),
                )
            })?;
            registry::find(rule).ok_or_else(|| {
                Error::Policy(format!(
                    "`suppressions.allow-repo-requests` names `{rule}`, which is not a rule \
                     airlock knows"
                ))
            })?;
            authority.allow_repo_requests.insert(rule.to_owned());
        }
    }

    // A suppression for a rule nothing enables is dead policy, and dead policy
    // hides intent. Say so rather than carrying it silently.
    for suppression in &authority.direct {
        if !rules.contains_key(suppression.rule.as_str()) {
            return Err(Error::Policy(format!(
                "`suppressions.direct` suppresses `{}`, which no enabled capability brings in",
                suppression.rule
            )));
        }
    }

    Ok(authority)
}
