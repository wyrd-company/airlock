//! Maturity derived from captured Git tag records and ancestry.
//
// relationships:
//   implements: release-process-conformance
//   references: maturity

use std::collections::{BTreeMap, BTreeSet};

use crate::document;
use crate::rules::Lifecycle;

mod capture;
mod forecast;
pub use capture::read_local;
pub(crate) use capture::{captured, gather_tags, read_local_at};
pub(crate) use forecast::report;
pub use forecast::{MaturityReport, Transition, TransitionRule};

/// An observation error retains the source diagnostic for the report.
#[derive(Debug, Clone)]
pub enum ObservationError {
    Api(Box<crate::github::ApiError>),
    Git(String),
}

impl From<String> for ObservationError {
    fn from(detail: String) -> Self {
        Self::Git(detail)
    }
}

impl From<&str> for ObservationError {
    fn from(detail: &str) -> Self {
        Self::Git(detail.to_owned())
    }
}

impl ObservationError {
    pub(crate) fn verdict(&self) -> crate::checks::Verdict {
        match self {
            Self::Api(error) => crate::checks::Verdict::from_api_error(error),
            Self::Git(detail) => crate::checks::Verdict::run_error("maturity_unobserved", detail),
        }
    }

    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Api(error) => error.to_string(),
            Self::Git(detail) => detail.clone(),
        }
    }
}

/// An annotated Git tag and the commit it directly names.
#[derive(Debug, Clone)]
pub struct HistoryTag {
    pub has_tagger: bool,
    pub target_kind: String,
    pub name: String,
    pub commit: String,
    pub message: String,
}

/// Immutable inputs to maturity observation. No clock, network or binary version.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub tags: Vec<HistoryTag>,
    pub head: String,
    pub commits: BTreeMap<String, Vec<String>>,
    pub complete: bool,
}

/// A resolved rung and the Git evidence that establishes it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Observed {
    pub rung: Lifecycle,
    pub baseline_tags: Vec<String>,
    pub release_tags: Vec<String>,
}

/// Observe only from a complete, captured history at the audited commit.
/// Incomplete observation is a run error, never a guessed rung.
pub fn observe(inputs: &Inputs) -> Result<Observed, String> {
    if !inputs.complete {
        return Err("Git history or tags were not observed in full".to_owned());
    }
    let mut baseline_tags = Vec::new();
    let mut release_tags = Vec::new();
    let mut releases = Vec::new();
    let reachable = ancestors(&inputs.head, &inputs.commits);
    for tag in &inputs.tags {
        if !tag.has_tagger || tag.target_kind != "commit" || !reachable.contains(&tag.commit) {
            continue;
        }
        let Ok(record) = document::tag(&tag.message) else {
            continue;
        };
        if record["baseline"] == true {
            baseline_tags.push(tag.name.clone());
        } else if record["tag-id"]
            .as_str()
            .is_some_and(|id| id.starts_with("release-unit/"))
        {
            let version =
                semver::Version::parse(record["version"].as_str().expect("validated version"))
                    .map_err(|_| "Invalid release version".to_owned())?;
            let rung = if version >= semver::Version::new(1, 0, 0) {
                Lifecycle::Stable
            } else {
                Lifecycle::Released
            };
            releases.push((tag, rung));
        }
    }
    let mut release_rung = None;
    for (tag, rung) in releases {
        let prior = ancestors(&tag.commit, &inputs.commits);
        if inputs.tags.iter().any(|baseline| {
            baseline_tags.contains(&baseline.name) && prior.contains(&baseline.commit)
        }) {
            release_rung =
                Some(release_rung.map_or(rung, |previous: Lifecycle| previous.max(rung)));
            release_tags.push(tag.name.clone());
        }
    }
    baseline_tags.sort();
    release_tags.sort();
    let rung = if baseline_tags.is_empty() {
        Lifecycle::Seeded
    } else {
        release_rung.unwrap_or(Lifecycle::Building)
    };
    Ok(Observed {
        rung,
        baseline_tags,
        release_tags,
    })
}

fn ancestors(head: &str, commits: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let mut pending = vec![head.to_owned()];
    while let Some(id) = pending.pop() {
        if result.insert(id.clone()) {
            if let Some(parents) = commits.get(&id) {
                pending.extend(parents.iter().cloned());
            }
        }
    }
    result
}

#[cfg(test)]
mod tests;
