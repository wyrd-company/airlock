//! Capture the Git objects consumed by the pure maturity observer.
//
// relationships:
//   references: maturity

use super::{observe, HistoryTag, Inputs, ObservationError, Observed};
use std::collections::BTreeMap;

/// Capture annotated objects once alongside the API audit's other Git inputs.
pub(crate) async fn gather_tags<G: crate::github::GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    tags: &crate::github::ApiResult<crate::github::Paged<crate::github::TagRef>>,
) -> crate::github::ApiResult<BTreeMap<String, crate::github::AnnotatedTag>> {
    let tags = tags.as_ref().map_err(Clone::clone)?;
    crate::release_records::complete(
        tags.truncated,
        &format!("GET /repos/{owner}/{repo}/git/matching-refs/tags/"),
    )?;
    let mut objects = BTreeMap::new();
    for tag in tags.iter().filter(|tag| tag.object_type == "tag") {
        if !objects.contains_key(&tag.sha) {
            objects.insert(
                tag.sha.clone(),
                client.annotated_tag(owner, repo, &tag.sha).await?,
            );
        }
    }
    Ok(objects)
}

pub(crate) fn captured(
    snapshot: &crate::snapshot::RepoSnapshot,
    tags: &crate::github::ApiResult<crate::github::Paged<crate::github::TagRef>>,
    objects: &crate::github::ApiResult<BTreeMap<String, crate::github::AnnotatedTag>>,
    history: &crate::github::ApiResult<crate::github::Paged<crate::github::CommitSummary>>,
) -> Result<Observed, ObservationError> {
    let tags = tags
        .as_ref()
        .map_err(|error| ObservationError::Api(Box::new(error.clone())))?;
    let objects = objects
        .as_ref()
        .map_err(|error| ObservationError::Api(Box::new(error.clone())))?;
    let history = history
        .as_ref()
        .map_err(|error| ObservationError::Api(Box::new(error.clone())))?;
    let mut inputs = Inputs {
        head: snapshot.commit.clone(),
        complete: !tags.truncated && !history.truncated,
        commits: history
            .iter()
            .map(|commit| (commit.sha.clone(), commit.parent_shas.clone()))
            .collect(),
        tags: Vec::new(),
    };
    for tag in tags.iter().filter(|tag| tag.object_type == "tag") {
        let object = objects
            .get(&tag.sha)
            .ok_or("An annotated tag object was not captured")?;
        inputs.tags.push(HistoryTag {
            has_tagger: object.has_tagger,
            target_kind: object.target_kind.clone(),
            name: tag.name.clone(),
            commit: object.commit.clone(),
            message: object.message.clone(),
        });
    }
    observe(&inputs).map_err(Into::into)
}

/// Read local Git objects with the same observer as an API audit.
pub fn read_local(
    root: &std::path::Path,
    max_commits: usize,
) -> Result<Observed, ObservationError> {
    let repo = gix::open(root).map_err(|error| {
        ObservationError::Git(format!("Local Git could not be opened: {error}"))
    })?;
    let head = repo
        .head_id()
        .map_err(|error| ObservationError::Git(format!("Local HEAD could not be read: {error}")))?;
    read_local_at(root, &head.to_string(), max_commits)
}

pub(crate) fn read_local_at(
    root: &std::path::Path,
    commit: &str,
    max_commits: usize,
) -> Result<Observed, ObservationError> {
    let read = || -> Result<Inputs, Box<dyn std::error::Error + Send + Sync>> {
        let repo = gix::open(root)?;
        let head = repo.find_commit(gix::hash::ObjectId::from_hex(commit.as_bytes())?)?;
        let mut inputs = Inputs {
            head: head.id.to_string(),
            complete: !repo.is_shallow(),
            ..Inputs::default()
        };
        for step in head.ancestors().all()?.take(max_commits.saturating_add(1)) {
            let commit = repo.find_commit(step?.id)?;
            if inputs.commits.len() == max_commits {
                inputs.complete = false;
                break;
            }
            inputs.commits.insert(
                commit.id.to_string(),
                commit.parent_ids().map(|id| id.to_string()).collect(),
            );
        }
        let references = repo.references()?;
        for reference in references.tags()? {
            let reference = reference?;
            let Some(id) = reference.try_id() else {
                continue;
            };
            let object = id.object()?;
            if object.kind != gix::objs::Kind::Tag {
                continue;
            }
            let tag = object.try_into_tag()?;
            let decoded = tag.decode()?;
            // Intentional records are annotated tags directly naming commits.
            if decoded.target_kind != gix::objs::Kind::Commit || decoded.tagger.is_none() {
                continue;
            }
            inputs.tags.push(HistoryTag {
                has_tagger: true,
                target_kind: "commit".into(),
                name: reference.name().shorten().to_string(),
                commit: tag.target_id()?.to_string(),
                message: decoded.message.to_string(),
            });
        }
        Ok(inputs)
    };
    observe(&read().map_err(|error| {
        ObservationError::Git(format!(
            "Local Git maturity evidence could not be read: {error}"
        ))
    })?)
    .map_err(Into::into)
}
