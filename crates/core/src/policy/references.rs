use super::*;

/// Resolve `reference-data`, transitively, pinned, bounded, and cycle-free.
pub(super) async fn resolve_references<G: GitHub>(
    client: &G,
    root: &PolicySource,
    document: &Yaml,
    limits: &Limits,
    bundle: &mut Vec<BundleSource>,
    budget: &mut ByteBudget,
) -> Result<BTreeMap<String, Yaml>> {
    let mut resolved = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<(String, String, usize)> = Vec::new();

    collect_references(document, 0, &mut queue)?;

    let mut count = 0;
    while let Some((name, reference, depth)) = queue.pop() {
        if depth > limits.max_policy_reference_depth {
            return Err(Error::Policy(format!(
                "reference `{name}` is nested deeper than the {} level limit",
                limits.max_policy_reference_depth
            )));
        }
        count += 1;
        if count > limits.max_policy_references {
            return Err(Error::Policy(format!(
                "the policy bundle has more than the {} reference limit",
                limits.max_policy_references
            )));
        }
        if !seen.insert(reference.clone()) {
            return Err(Error::Policy(format!(
                "reference `{reference}` is reached twice; the policy bundle must be acyclic"
            )));
        }

        let source = resolve_reference_source(root, &reference)?;
        let loaded = load_source(client, &source, limits, budget).await?;
        let text = to_text(&source.label(), loaded.bytes)?;
        bundle.push(BundleSource {
            name: name.clone(),
            source: source.label(),
            commit: loaded.commit,
            blob_sha: loaded.blob_sha,
            content_digest: content_digest(&text),
        });

        let parsed = yaml::parse_mapping(&text, limits.yaml)
            .map_err(|error| Error::Policy(format!("{}: {error}", source.label())))?;
        collect_references(&parsed, depth + 1, &mut queue)?;
        resolved.insert(name, parsed);
    }

    Ok(resolved)
}

fn collect_references(
    document: &Yaml,
    depth: usize,
    queue: &mut Vec<(String, String, usize)>,
) -> Result<()> {
    let Some(references) = document.get("reference-data") else {
        return Ok(());
    };
    let Some(entries) = references.as_map() else {
        return Err(Error::Policy(format!(
            "`reference-data` should be a mapping of name to source, found {}",
            references.kind()
        )));
    };
    for (name, value) in entries {
        let Some(reference) = value.as_str() else {
            return Err(Error::Policy(format!(
                "reference `{name}` should be a string source, found {}",
                value.kind()
            )));
        };
        queue.push((name.clone(), reference.to_owned(), depth));
    }
    Ok(())
}

/// A reference resolves relative to the policy it came from: a local policy may
/// reference local files, a remote one may not reach the auditing machine's
/// disk.
pub(super) fn resolve_reference_source(
    root: &PolicySource,
    reference: &str,
) -> Result<PolicySource> {
    let source = PolicySource::parse(reference)?;
    match (&source, root) {
        (PolicySource::Local(path), PolicySource::Remote { .. }) => Err(Error::Policy(format!(
            "a remote policy cannot reference the local file `{}`",
            path.display()
        ))),
        (PolicySource::Local(path), PolicySource::Local(root)) => {
            // Resolve relative to the policy file, not the working directory.
            let base = root.parent().unwrap_or_else(|| Path::new("."));
            Ok(PolicySource::Local(base.join(path)))
        }
        _ => Ok(source),
    }
}
