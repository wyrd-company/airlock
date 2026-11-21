//! Pinned, bounded topic vocabulary parameters.

use super::*;

/// Resolve topic parameters without moving organization facts outside their rule.
pub(super) async fn resolve_references<G: GitHub>(
    client: &G,
    root: &PolicySource,
    document: &mut Yaml,
    limits: &Limits,
    bundle: &mut Vec<BundleSource>,
    budget: &mut ByteBudget,
) -> Result<()> {
    let mut queue = vec![document];
    let mut count = 0;
    while let Some(document) = queue.pop() {
        let Yaml::Map(entries) = document else {
            continue;
        };
        for (key, value) in entries {
            if key == "topics" && value.as_str().is_some() {
                let mut source =
                    resolve_reference_source(root, value.as_str().expect("checked above"))?;
                let mut seen = BTreeSet::new();
                let mut depth = 0;
                loop {
                    count += 1;
                    if count > limits.max_policy_references {
                        return Err(Error::Policy("too many topic vocabulary references".into()));
                    }
                    if depth > limits.max_policy_reference_depth {
                        return Err(Error::Policy(
                            "topic vocabulary reference is too deep".into(),
                        ));
                    }
                    if !seen.insert(source.label()) {
                        return Err(Error::Policy("topic vocabulary reference is cyclic".into()));
                    }
                    let loaded = load_source(client, &source, limits, budget).await?;
                    let text = to_text(&source.label(), loaded.bytes)?;
                    bundle.push(BundleSource {
                        name: "topics".into(),
                        source: source.label(),
                        commit: loaded.commit,
                        blob_sha: loaded.blob_sha,
                        content_digest: content_digest(&text),
                    });
                    let parsed = yaml::parse(&text, limits.yaml)
                        .map_err(|e| Error::Policy(format!("{}: {e}", source.label())))?;
                    if let Some(reference) = parsed.as_str() {
                        source = resolve_reference_source(&source, reference)?;
                        depth += 1;
                    } else {
                        *value = parsed;
                        break;
                    }
                }
            } else if value.as_map().is_some() {
                queue.push(value);
            }
        }
    }
    Ok(())
}

fn resolve_reference_source(root: &PolicySource, reference: &str) -> Result<PolicySource> {
    let source = PolicySource::parse(reference)?;
    match (&source, root) {
        (PolicySource::Local(path), PolicySource::Remote { .. }) => Err(Error::Policy(format!(
            "a remote config cannot reference the local file {}",
            path.display()
        ))),
        (PolicySource::Local(path), PolicySource::Local(root)) => Ok(PolicySource::Local(
            root.parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
                .components()
                .collect(),
        )),
        _ => Ok(source),
    }
}
