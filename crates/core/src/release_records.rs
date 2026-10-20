//! Gather release-record evidence before compiled evaluation.
//
// relationships:
//   implements: release-process-conformance

use crate::document;
use crate::github::{
    AnnotatedTag, ApiError, ApiResult, ErrorCause, GitHub, Paged, ReleaseRecord, TagRef,
};
use crate::snapshot::{FileState, RepoSnapshot};
use std::collections::BTreeMap;

pub(crate) const MODEL_PATH: &str = ".intentional/release-model.json";

/// Live release observations, captured once per audit.
#[derive(Debug, Clone, Default)]
pub struct ReleaseInputs {
    /// Complete published/draft listing, retained for evaluation.
    pub releases: Vec<ReleaseRecord>,
    /// Annotated objects indexed by ref-object SHA.
    pub tags: BTreeMap<String, AnnotatedTag>,
}

/// Match literal template text and one canonical SemVer, without an implicit v.
pub(crate) fn matched_version(template: &str, id: &str, name: &str) -> Option<String> {
    let template = template.replace("{id}", id);
    let mut pieces = template.split("{version}");
    let prefix = pieces.next()?;
    let suffix = pieces.next()?;
    if pieces.next().is_some() {
        return None;
    }
    let version = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let parsed = semver::Version::parse(version).ok()?;
    (parsed.to_string() == version).then(|| version.to_owned())
}

pub(crate) fn candidates(model: &serde_json::Value, name: &str) -> bool {
    model["release_units"]
        .as_object()
        .into_iter()
        .flatten()
        .any(|(id, unit)| {
            unit["release_record"] == "required"
                && unit["tags"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .any(|(_, tag)| {
                        tag["role"] == "primary"
                            && tag["template"].as_str().is_some_and(|template| {
                                matched_version(template, id, name).is_some()
                            })
                    })
        })
}

pub(crate) async fn gather<G: GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    snapshot: &RepoSnapshot,
    tags: &ApiResult<Paged<TagRef>>,
    enabled: bool,
) -> ApiResult<ReleaseInputs> {
    if !enabled {
        return Ok(ReleaseInputs::default());
    }
    // Invalid or absent models are evaluated before live release inputs.
    let FileState::Content { bytes, .. } = snapshot.file(MODEL_PATH) else {
        return Ok(ReleaseInputs::default());
    };
    let Ok(model) = document::model(bytes) else {
        return Ok(ReleaseInputs::default());
    };
    if !model["release_units"]
        .as_object()
        .expect("validated units")
        .values()
        .any(|unit| unit["release_record"] == "required")
    {
        return Ok(ReleaseInputs::default());
    }
    let tags = tags.as_ref().map_err(Clone::clone)?;
    complete(
        tags.truncated,
        &format!("GET /repos/{owner}/{repo}/git/matching-refs/tags/"),
    )?;
    let releases = client.releases(owner, repo).await?;
    complete(
        releases.truncated,
        &format!("GET /repos/{owner}/{repo}/releases"),
    )?;
    let mut objects = BTreeMap::new();
    for tag in tags
        .iter()
        .filter(|tag| tag.object_type == "tag" && candidates(&model, &tag.name))
    {
        if !objects.contains_key(&tag.sha) {
            objects.insert(
                tag.sha.clone(),
                client.annotated_tag(owner, repo, &tag.sha).await?,
            );
        }
    }
    Ok(ReleaseInputs {
        releases: releases.items,
        tags: objects,
    })
}

#[allow(clippy::result_large_err)] // Preserve the API diagnostic used by the rest of the client.
pub(crate) fn complete(truncated: bool, endpoint: &str) -> ApiResult<()> {
    if truncated {
        Err(ApiError::local(
            ErrorCause::Budget,
            endpoint,
            "listing truncated or page budget exhausted; absence was not established",
        ))
    } else {
        Ok(())
    }
}
