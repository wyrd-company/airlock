//! The local working tree as an observation source.
//!
//! File-level rules can be evaluated against a working tree on disk instead
//! of the API tree — the case of an agent that has just written changes and
//! wants to know whether it is done. The tree is observed **as it stands**,
//! including uncommitted and untracked content, and the audit output states
//! that rather than assuming a reader will guess it.
//!
//! The choices this module makes deliberately, recorded here and in the
//! run-level observation block:
//!
//! - **Ignored files are excluded.** A rule satisfied only by a gitignored
//!   file is not satisfied: that file is not destined for the repository.
//!   Tracked files are read even when an ignore rule matches them, because
//!   git ignores ignore rules for tracked paths.
//! - **Dirtiness is reported, not hidden.** The reader of a local result can
//!   tell whether it describes something committed. When dirtiness cannot be
//!   established it is reported as undetermined, never as clean.
//! - **A working tree must be a git repository with a commit.** Airlock never
//!   requires a clone — the API path remains the default — but when a local
//!   tree is offered it must carry the identity (HEAD) that makes the result
//!   reproducible enough to talk about.
//! - **No subprocess.** Git facts are read in-process with `gix`; the walk
//!   honours gitignore semantics via the `ignore` crate. The binary never
//!   shells out.
//!
//! - **Raw bytes, not filtered bytes.** Dirtiness and blob identities are
//!   computed over on-disk content. A checkout whose attributes rewrite
//!   content (CRLF normalisation off-Linux) can read as dirty and carry
//!   different blob identities than the API would report for the same
//!   logical content; nothing compares identities across sources, and
//!   over-reporting dirt is the safe direction.
//!
//! Platform facts — settings, rulesets, tags, history — are never derived
//! from a working tree. They stay with the API or are reported as not
//! observed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::github::{EntryKind, Tree, TreeEntry};
use crate::limits::Limits;
use crate::snapshot::FileState;

/// What airlock observed about a working tree, before any file is read.
#[derive(Debug, Clone)]
pub struct WorkingTreeFacts {
    /// The root of the working tree.
    pub root: PathBuf,
    /// The commit HEAD points at.
    ///
    /// The observed tree may differ from it; `dirty` says whether it does.
    pub head_commit: String,
    /// Whether the working tree differs from HEAD.
    ///
    /// `None` when dirtiness could not be established — reported as
    /// undetermined, never as clean.
    pub dirty: Option<bool>,
    /// `owner/name` parsed from the `origin` remote, when there is one.
    pub remote_full_name: Option<String>,
    /// The default branch observed from `refs/remotes/origin/HEAD`, when the
    /// clone recorded one. Without it the audit assumes `main` and says so.
    pub observed_default_branch: Option<String>,
    /// The walked tree, in the same shape the API tree takes.
    pub tree: Tree,
}

/// Read the facts of a working tree: identity, dirtiness, and the tree
/// listing. File contents are read later, per path and under budget, exactly
/// like the API source.
///
/// # Errors
///
/// Returns [`Error::WorkingTree`] when the path is not a git repository or
/// has no commit, and [`Error::Io`] when the walk itself fails.
pub fn read_facts(root: &Path) -> Result<WorkingTreeFacts> {
    let repo = gix::open(root).map_err(|error| {
        Error::WorkingTree(format!(
            "{} is not a git repository airlock can read: {error}",
            root.display()
        ))
    })?;
    let workdir = repo
        .workdir()
        .ok_or_else(|| {
            Error::WorkingTree(format!(
                "{} is a bare repository; a working tree is required",
                root.display()
            ))
        })?
        .to_path_buf();

    let head_commit = repo
        .head_id()
        .map_err(|error| {
            Error::WorkingTree(format!(
                "{} has no commit airlock can anchor the audit to: {error}",
                root.display()
            ))
        })?
        .to_string();

    let remote_full_name = repo
        .find_remote("origin")
        .ok()
        .and_then(|remote| {
            remote
                .url(gix::remote::Direction::Fetch)
                .map(|url| url.to_bstring().to_string())
        })
        .and_then(|url| full_name_from_url(&url));

    let observed_default_branch = repo
        .find_reference("refs/remotes/origin/HEAD")
        .ok()
        .and_then(|reference| match reference.target() {
            gix::refs::TargetRef::Symbolic(name) => name
                .as_bstr()
                .to_string()
                .strip_prefix("refs/remotes/origin/")
                .map(ToOwned::to_owned),
            gix::refs::TargetRef::Object(_) => None,
        });

    let walked = walk(&repo, &workdir)?;

    // gix's `is_dirty` covers tracked modifications; untracked and deleted
    // files were established by the walk. A tree with either is dirty even
    // when the status engine cannot answer, and an unanswerable status with
    // a matching walk is undetermined — never clean.
    let dirty = match repo.is_dirty() {
        Ok(modified) => Some(modified || walked.untracked || walked.deleted),
        Err(_) if walked.untracked || walked.deleted => Some(true),
        Err(_) => None,
    };

    Ok(WorkingTreeFacts {
        root: workdir,
        head_commit,
        dirty,
        remote_full_name,
        observed_default_branch,
        tree: walked.tree,
    })
}

/// What the walk established beyond the tree itself.
struct Walked {
    tree: Tree,
    /// A non-ignored file exists that HEAD does not track.
    untracked: bool,
    /// HEAD tracks a file that no longer exists on disk.
    deleted: bool,
}

/// `owner/name` from a git remote URL, whatever transport it uses.
fn full_name_from_url(url: &str) -> Option<String> {
    let path = url
        .rsplit_once(':')
        .map_or(url, |(_, path)| path)
        .rsplit_once("//")
        .map_or_else(
            || url.rsplit_once(':').map_or(url, |(_, path)| path),
            |(_, rest)| rest.split_once('/').map_or(rest, |(_, path)| path),
        );
    let path = path.trim_end_matches(".git").trim_matches('/');
    let (owner, name) = path.rsplit_once('/')?;
    if owner.is_empty() || name.is_empty() || owner.contains('/') {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

/// Walk the working tree with gitignore semantics, then union in tracked
/// paths an ignore rule would otherwise hide.
fn walk(repo: &gix::Repository, workdir: &Path) -> Result<Walked> {
    let mut paths: BTreeMap<String, TreeEntry> = BTreeMap::new();

    let mut builder = ignore::WalkBuilder::new(workdir);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .require_git(true)
        .filter_entry(|entry| {
            // Never descend into git metadata or nested repositories: a
            // submodule's contents are not this repository's files.
            let is_dir = entry.file_type().is_some_and(|kind| kind.is_dir());
            !(is_dir
                && (entry.file_name() == ".git"
                    || (entry.depth() > 0 && entry.path().join(".git").exists())))
        });

    for step in builder.build() {
        let entry = step.map_err(|error| Error::WorkingTree(format!("walk failed: {error}")))?;
        let Some(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if entry.depth() > 0 && entry.path().join(".git").exists() {
                if let Some(path) = relative(workdir, entry.path()) {
                    paths.insert(
                        path.clone(),
                        TreeEntry {
                            path,
                            kind: EntryKind::Submodule,
                            mode: "160000".to_owned(),
                            sha: String::new(),
                            size: None,
                        },
                    );
                }
            }
            continue;
        }
        let Some(path) = relative(workdir, entry.path()) else {
            continue;
        };
        paths.insert(path.clone(), file_entry(path, entry.path(), kind)?);
    }

    // Tracked files that an ignore rule matches are still part of the
    // repository; read them from HEAD's tree listing and observe them on
    // disk like any other file.
    let tracked = tracked_paths(repo);
    let mut deleted = false;
    for path in &tracked {
        if paths.contains_key(path) {
            continue;
        }
        let on_disk = workdir.join(path);
        let Ok(metadata) = std::fs::symlink_metadata(&on_disk) else {
            // Deleted from the tree as it stands: absent is the honest state.
            deleted = true;
            continue;
        };
        paths.insert(
            path.clone(),
            file_entry(path.clone(), &on_disk, metadata.file_type())?,
        );
    }

    let tracked: std::collections::BTreeSet<&String> = tracked.iter().collect();
    let untracked = paths
        .iter()
        .any(|(path, entry)| entry.kind != EntryKind::Submodule && !tracked.contains(path));

    Ok(Walked {
        tree: Tree {
            entries: paths.into_values().collect(),
            truncated: false,
        },
        untracked,
        deleted,
    })
}

fn relative(workdir: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(workdir).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    Some(
        relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn file_entry(path: String, on_disk: &Path, kind: std::fs::FileType) -> Result<TreeEntry> {
    let metadata = std::fs::symlink_metadata(on_disk).map_err(|source| Error::Io {
        path: on_disk.to_path_buf(),
        source,
    })?;
    if kind.is_symlink() {
        return Ok(TreeEntry {
            path,
            kind: EntryKind::Symlink,
            mode: "120000".to_owned(),
            sha: String::new(),
            size: Some(metadata.len()),
        });
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(TreeEntry {
        path,
        kind: if executable {
            EntryKind::ExecutableBlob
        } else {
            EntryKind::Blob
        },
        mode: if executable { "100755" } else { "100644" }.to_owned(),
        sha: String::new(),
        size: Some(metadata.len()),
    })
}

/// Every file path in HEAD's tree.
///
/// An unreadable HEAD tree yields no paths rather than an error: the walk
/// already observed the tree as it stands, and this union only adds
/// tracked-but-ignored files.
fn tracked_paths(repo: &gix::Repository) -> Vec<String> {
    let Ok(head) = repo.head_commit() else {
        return Vec::new();
    };
    let Ok(tree) = head.tree() else {
        return Vec::new();
    };
    let mut recorder = gix::traverse::tree::Recorder::default();
    if tree.traverse().breadthfirst(&mut recorder).is_err() {
        return Vec::new();
    }
    recorder
        .records
        .into_iter()
        .filter(|record| {
            matches!(
                record.mode.kind(),
                gix::object::tree::EntryKind::Blob
                    | gix::object::tree::EntryKind::BlobExecutable
                    | gix::object::tree::EntryKind::Link
            )
        })
        .map(|record| record.filepath.to_string())
        .collect()
}

impl WorkingTreeFacts {
    /// The text of `path` as committed at HEAD, when it exists there.
    ///
    /// This deliberately bypasses the working tree: authorization-bearing
    /// inputs (the suppression request file) are honoured only from
    /// committed content, so an uncommitted edit cannot suppress a finding.
    #[must_use]
    pub fn head_file(&self, path: &str) -> Option<String> {
        let repo = gix::open(&self.root).ok()?;
        let commit = repo.head_commit().ok()?;
        let tree = commit.tree().ok()?;
        let entry = tree.lookup_entry_by_path(path).ok()??;
        let object = entry.object().ok()?;
        String::from_utf8(object.data.to_vec()).ok()
    }
}

/// Read `paths` from the working tree into file states, under the same
/// budgets the API source honours.
///
/// An unreadable local path becomes [`FileState::LocalUnreadable`], which
/// every check reports as inconclusive — never a false pass.
pub fn load_files(
    facts: &WorkingTreeFacts,
    paths: &[String],
    limits: Limits,
    files: &mut BTreeMap<String, FileState>,
    bytes_read: &mut usize,
) {
    for path in paths {
        if files.contains_key(path) {
            continue;
        }
        let state = read_path(facts, path, limits, *bytes_read);
        if let FileState::Content { bytes, .. } = &state {
            *bytes_read += bytes.len();
        }
        files.insert(path.clone(), state);
    }
}

fn read_path(facts: &WorkingTreeFacts, path: &str, limits: Limits, bytes_read: usize) -> FileState {
    let Some(entry) = facts
        .tree
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .cloned()
    else {
        return FileState::Missing;
    };

    let on_disk = facts.root.join(path);
    match entry.kind {
        EntryKind::Tree | EntryKind::Submodule => FileState::NotAFile {
            kind: entry.kind,
            mode: entry.mode,
        },
        EntryKind::Symlink => match std::fs::read_link(&on_disk) {
            Ok(target) => FileState::Symlink {
                target: target.to_string_lossy().into_owned(),
            },
            Err(error) => local_unreadable(path, &error),
        },
        EntryKind::Blob | EntryKind::ExecutableBlob => {
            let size = entry.size.unwrap_or_default();
            if size as usize > limits.max_blob_bytes {
                return FileState::OverBudget {
                    size,
                    limit: limits.max_blob_bytes,
                };
            }
            if bytes_read + size as usize > limits.max_total_bytes {
                return FileState::OverBudget {
                    size,
                    limit: limits.max_total_bytes,
                };
            }
            match std::fs::read(&on_disk) {
                Ok(bytes) => FileState::Content {
                    sha: blob_sha(&bytes),
                    bytes,
                },
                Err(error) => local_unreadable(path, &error),
            }
        }
    }
}

fn local_unreadable(path: &str, error: &std::io::Error) -> FileState {
    FileState::LocalUnreadable {
        detail: format!("{path} could not be read from the working tree: {error}"),
    }
}

/// The git blob sha of `bytes`, so a local read carries the same identity
/// the API would report for identical content.
fn blob_sha(bytes: &[u8]) -> String {
    gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, bytes)
        .map(|id| id.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_names_parse_from_common_remote_urls() {
        for url in [
            "git@github.com:acme/widget.git",
            "https://github.com/acme/widget.git",
            "https://github.com/acme/widget",
            "ssh://git@github.com/acme/widget.git",
        ] {
            assert_eq!(
                full_name_from_url(url).as_deref(),
                Some("acme/widget"),
                "{url}"
            );
        }
        assert_eq!(full_name_from_url("not a url"), None);
    }

    #[test]
    fn blob_shas_match_git() {
        // `git hash-object` of an empty file.
        assert_eq!(blob_sha(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        // `echo hello | git hash-object --stdin`
        assert_eq!(
            blob_sha(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }
}
