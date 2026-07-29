//! The repository snapshot.
//!
//! An audit reads one repository at one commit. Every git-backed fact — trees,
//! blobs, file contents, history — comes from that single resolved sha, so a
//! finding describes a repository state that actually existed and can be
//! reproduced. Live settings are a second snapshot domain: they are recorded
//! with the time the response was observed, because they are not part of any
//! commit.
//!
//! Reading is budgeted. A file that does not fit the budget is recorded as
//! unread, never as absent, so a check over it can only ever be inconclusive.

use std::collections::BTreeMap;

use crate::github::{ApiError, EntryKind, GitHub, Repository, Tree, TreeEntry};
use crate::limits::Limits;

/// What airlock knows about one path at the audited commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// No entry at that path, in a tree airlock saw all of.
    Missing,
    /// The path was not in the tree, but GitHub truncated the tree — so its
    /// absence was never established.
    TreeTruncated,
    /// An entry exists but is not a file airlock reads — a directory, a
    /// submodule, or a symlink. The kind is preserved.
    NotAFile {
        /// What the entry actually is.
        kind: EntryKind,
        /// The raw git mode.
        mode: String,
    },
    /// A symbolic link, with its target read from the blob.
    Symlink {
        /// The link target, exactly as stored.
        target: String,
    },
    /// The file was read.
    Content {
        /// The blob sha.
        sha: String,
        /// The file bytes.
        bytes: Vec<u8>,
    },
    /// The file exists but exceeds a byte budget, so it was not read.
    OverBudget {
        /// The file's size in bytes.
        size: u64,
        /// The budget it exceeded.
        limit: usize,
    },
    /// The file exists but could not be read.
    Unreadable(ApiError),
    /// A working-tree file that exists but could not be read from disk.
    ///
    /// Distinct from [`FileState::Unreadable`] because it is not an API
    /// failure: checks report it as inconclusive rather than as an error,
    /// and it is never a false pass.
    LocalUnreadable {
        /// What went wrong, with the path.
        detail: String,
    },
}

impl FileState {
    /// The file's text, when it was read and is valid UTF-8.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            FileState::Content { bytes, .. } => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Whether the path holds readable file content.
    #[must_use]
    pub fn is_content(&self) -> bool {
        matches!(self, FileState::Content { .. })
    }

    /// Whether airlock knows conclusively that nothing is at this path.
    #[must_use]
    pub fn is_conclusively_missing(&self) -> bool {
        matches!(self, FileState::Missing)
    }

    /// Whether the state leaves the question open.
    #[must_use]
    pub fn is_undecided(&self) -> bool {
        matches!(
            self,
            FileState::OverBudget { .. }
                | FileState::Unreadable(_)
                | FileState::LocalUnreadable { .. }
                | FileState::TreeTruncated
        )
    }
}

/// One repository, read at one commit.
#[derive(Debug, Clone)]
pub struct RepoSnapshot {
    /// The repository settings, and when they were observed.
    pub repository: Repository,
    /// The declared topics.
    pub topics: Result<Vec<String>, ApiError>,
    /// The commit every git-backed fact was read at.
    pub commit: String,
    /// The recursive tree at that commit.
    pub tree: Tree,
    /// Paths airlock has read, with what it found.
    pub files: BTreeMap<String, FileState>,
    /// Bytes read so far, against the aggregate budget.
    pub bytes_read: usize,
    /// The budgets this snapshot was read under.
    pub limits: Limits,
}

impl RepoSnapshot {
    /// Read a repository at `reference`, or at its default branch.
    ///
    /// # Errors
    ///
    /// Returns the API error that stopped the snapshot. A snapshot that cannot
    /// be built is an operational failure, not a finding: there is nothing to
    /// audit.
    pub async fn read<G: GitHub>(
        client: &G,
        owner: &str,
        repo: &str,
        reference: Option<&str>,
        limits: Limits,
    ) -> Result<Self, ApiError> {
        let repository = client.repository(owner, repo).await?;
        let reference = reference.unwrap_or(&repository.default_branch);
        let commit = client.resolve_commit(owner, repo, reference).await?;
        let tree = client.tree(owner, repo, &commit).await?;
        let topics = client.topics(owner, repo).await;

        Ok(Self {
            repository,
            topics,
            commit,
            tree,
            files: BTreeMap::new(),
            bytes_read: 0,
            limits,
        })
    }

    /// The tree entry at `path`, if there is one.
    #[must_use]
    pub fn entry(&self, path: &str) -> Option<&TreeEntry> {
        self.tree.entries.iter().find(|entry| entry.path == path)
    }

    /// Whether a directory exists at `path`.
    ///
    /// A submodule at the path is not a directory, and says so.
    #[must_use]
    pub fn has_directory(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.tree.entries.iter().any(|entry| {
            (entry.path == path && entry.kind == EntryKind::Tree) || entry.path.starts_with(&prefix)
        })
    }

    /// Every tree entry directly or transitively under `path`.
    #[must_use]
    pub fn entries_under(&self, path: &str) -> Vec<&TreeEntry> {
        let prefix = format!("{path}/");
        self.tree
            .entries
            .iter()
            .filter(|entry| entry.path.starts_with(&prefix))
            .collect()
    }

    /// What airlock knows about `path`.
    ///
    /// A path that was never read reports as missing — callers load the paths
    /// they care about first — unless the tree was truncated, in which case
    /// nothing about an unseen path was ever established.
    #[must_use]
    pub fn file(&self, path: &str) -> &FileState {
        const MISSING: FileState = FileState::Missing;
        const TRUNCATED: FileState = FileState::TreeTruncated;
        self.files.get(path).unwrap_or({
            if self.tree.truncated {
                &TRUNCATED
            } else {
                &MISSING
            }
        })
    }

    /// Whether GitHub truncated the recursive tree.
    ///
    /// Any check whose answer depends on something *not* being in the tree has
    /// to consult this: a truncated tree can prove presence but never absence.
    #[must_use]
    pub fn tree_is_truncated(&self) -> bool {
        self.tree.truncated
    }

    /// The evidence detail explaining a truncated tree, for a check that
    /// cannot conclude because of it.
    #[must_use]
    pub fn truncation_detail(&self, subject: &str) -> String {
        format!(
            "GitHub truncated the recursive tree at {}, so {subject} was never established",
            self.commit
        )
    }

    /// Read the given paths into the snapshot, under budget.
    ///
    /// Paths already read are not read again. Failures are recorded per path
    /// rather than aborting: one unreadable file makes one check inconclusive,
    /// not the whole audit.
    pub async fn load_files<G: GitHub>(
        &mut self,
        client: &G,
        owner: &str,
        repo: &str,
        paths: &[String],
    ) {
        for path in paths {
            if self.files.contains_key(path) {
                continue;
            }
            let state = self.read_path(client, owner, repo, path).await;
            self.files.insert(path.clone(), state);
        }
    }

    async fn read_path<G: GitHub>(
        &mut self,
        client: &G,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> FileState {
        let Some(entry) = self.entry(path).cloned() else {
            // A path missing from a truncated tree is a path airlock did not
            // look for everywhere. That is not absence.
            return if self.tree.truncated {
                FileState::TreeTruncated
            } else {
                FileState::Missing
            };
        };

        if entry.kind == EntryKind::Tree || entry.kind == EntryKind::Submodule {
            return FileState::NotAFile {
                kind: entry.kind,
                mode: entry.mode,
            };
        }

        let size = entry.size.unwrap_or_default();
        if size as usize > self.limits.max_blob_bytes {
            return FileState::OverBudget {
                size,
                limit: self.limits.max_blob_bytes,
            };
        }
        if self.bytes_read + size as usize > self.limits.max_total_bytes {
            return FileState::OverBudget {
                size,
                limit: self.limits.max_total_bytes,
            };
        }

        match client.blob(owner, repo, &entry.sha).await {
            Ok(bytes) => {
                self.bytes_read += bytes.len();
                if entry.kind == EntryKind::Symlink {
                    FileState::Symlink {
                        target: String::from_utf8_lossy(&bytes).into_owned(),
                    }
                } else {
                    FileState::Content {
                        sha: entry.sha,
                        bytes,
                    }
                }
            }
            Err(error) => FileState::Unreadable(error),
        }
    }
}

/// Read one file from a repository at a resolved commit.
///
/// Used by policy resolution, which reads from repositories it is not
/// auditing. The returned tuple is the blob sha and its bytes.
///
/// # Errors
///
/// Returns the API error that stopped the read.
pub async fn read_file_at<G: GitHub>(
    client: &G,
    owner: &str,
    repo: &str,
    commit: &str,
    path: &str,
    max_bytes: usize,
) -> Result<Option<(String, Vec<u8>)>, ApiError> {
    let tree = client.tree(owner, repo, commit).await?;
    let Some(entry) = tree.entries.iter().find(|entry| entry.path == path) else {
        return Ok(None);
    };
    if !entry.kind.is_file() {
        // A policy that is a symlink or a submodule is not a policy. Airlock
        // never follows a link to reach a file it is going to trust.
        return Ok(None);
    }
    if entry.size.unwrap_or_default() as usize > max_bytes {
        return Err(ApiError::local(
            crate::github::ErrorCause::Budget,
            format!("GET /repos/{owner}/{repo}/git/blobs/{}", entry.sha),
            format!(
                "{path} is {} bytes, over the {max_bytes} byte limit",
                entry.size.unwrap_or_default()
            ),
        ));
    }
    let bytes = client.blob(owner, repo, &entry.sha).await?;
    Ok(Some((entry.sha.clone(), bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Tree;

    fn snapshot(entries: Vec<TreeEntry>) -> RepoSnapshot {
        RepoSnapshot {
            repository: Repository {
                full_name: "owner/name".to_owned(),
                id: 1,
                owner: "owner".to_owned(),
                name: "name".to_owned(),
                default_branch: "main".to_owned(),
                visibility: "public".to_owned(),
                description: None,
                license_spdx: None,
                allow_merge_commit: false,
                allow_squash_merge: true,
                allow_rebase_merge: true,
                delete_branch_on_merge: true,
                has_wiki: false,
                has_projects: false,
                has_discussions: false,
                has_issues: true,
                observed_at: None,
            },
            topics: Ok(Vec::new()),
            commit: "a".repeat(40),
            tree: Tree {
                entries,
                truncated: false,
            },
            files: BTreeMap::new(),
            bytes_read: 0,
            limits: Limits::default(),
        }
    }

    fn entry(path: &str, kind: EntryKind, mode: &str) -> TreeEntry {
        TreeEntry {
            path: path.to_owned(),
            kind,
            mode: mode.to_owned(),
            sha: "1".to_owned(),
            size: Some(10),
        }
    }

    #[test]
    fn a_directory_is_recognised_by_its_children() {
        let snapshot = snapshot(vec![entry(
            ".devcontainer/devcontainer.json",
            EntryKind::Blob,
            "100644",
        )]);
        assert!(snapshot.has_directory(".devcontainer"));
        assert!(!snapshot.has_directory(".claude"));
    }

    #[test]
    fn a_submodule_is_not_a_directory() {
        let snapshot = snapshot(vec![entry("vendor", EntryKind::Submodule, "160000")]);
        assert!(!snapshot.has_directory("vendor"));
    }

    #[test]
    fn a_path_absent_from_a_truncated_tree_is_undecided_not_missing() {
        // Asserted through `file()`, the accessor every check uses, so
        // inverting the production branch fails here.
        let mut snapshot = snapshot(Vec::new());
        snapshot.tree.truncated = true;

        assert!(snapshot.tree_is_truncated());
        assert_eq!(*snapshot.file("README.md"), FileState::TreeTruncated);
        assert!(snapshot.file("README.md").is_undecided());
        assert!(!snapshot.file("README.md").is_conclusively_missing());
    }

    #[test]
    fn a_path_absent_from_a_complete_tree_is_conclusively_missing() {
        // The other side of the same branch: without both, an inverted
        // condition still passes one of them.
        let snapshot = snapshot(vec![entry("README.md", EntryKind::Blob, "100644")]);

        assert!(!snapshot.tree_is_truncated());
        assert_eq!(*snapshot.file("CONTRIBUTING.md"), FileState::Missing);
        assert!(snapshot.file("CONTRIBUTING.md").is_conclusively_missing());
        assert!(!snapshot.file("CONTRIBUTING.md").is_undecided());
    }

    #[test]
    fn a_read_path_is_reported_from_what_was_read_whatever_the_tree_says() {
        // A path already in `files` answers from that record, so truncation
        // never overrides something airlock actually read.
        let mut snapshot = snapshot(vec![entry("README.md", EntryKind::Blob, "100644")]);
        snapshot.tree.truncated = true;
        snapshot.files.insert(
            "README.md".to_owned(),
            FileState::Content {
                sha: "1".to_owned(),
                bytes: b"# example".to_vec(),
            },
        );

        assert!(snapshot.file("README.md").is_content());
        assert_eq!(snapshot.file("README.md").text(), Some("# example"));
        // A sibling that was never read is still undecided under truncation.
        assert_eq!(*snapshot.file("AGENTS.md"), FileState::TreeTruncated);
    }

    #[test]
    fn an_unread_path_reports_as_missing() {
        let snapshot = snapshot(Vec::new());
        assert!(snapshot.file("README.md").is_conclusively_missing());
    }

    #[test]
    fn an_over_budget_file_is_undecided_rather_than_absent() {
        let state = FileState::OverBudget { size: 1, limit: 0 };
        assert!(state.is_undecided());
        assert!(!state.is_conclusively_missing());
    }

    #[test]
    fn entries_under_a_prefix_are_listed() {
        let snapshot = snapshot(vec![
            entry(".github/workflows/ci.yml", EntryKind::Blob, "100644"),
            entry(".github/workflows/cd.yml", EntryKind::Blob, "100644"),
            entry("README.md", EntryKind::Blob, "100644"),
        ]);
        assert_eq!(snapshot.entries_under(".github/workflows").len(), 2);
    }
}
