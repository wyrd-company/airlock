use super::*;

pub(super) fn bundle_digest(
    sources: &[BundleSource],
    rules: &[RuleInstance],
    gate: Gate,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"airlock-policy-bundle-1\x1e");
    hasher.update(gate.code().as_bytes());
    hasher.update(b"\x1e");
    for source in sources {
        hasher.update(source.name.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(source.identity().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(source.content_digest.as_bytes());
        hasher.update(b"\x1e");
    }
    for rule in rules {
        hasher.update(rule.def.id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(rule.severity.code().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(rule.condition.code().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(
            serde_json::to_string(&rule.params)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(b"\x1e");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
