use super::*;

/// What is left of the policy bundle's aggregate byte budget.
///
/// A per-file cap alone lets sixteen individually legal references add up to
/// far more than one audit is allowed to hold, so the budget is spent down
/// rather than re-applied.
#[derive(Debug, Clone, Copy)]
pub(super) struct ByteBudget {
    total: usize,
    used: usize,
}

impl ByteBudget {
    pub(super) fn new(total: usize) -> Self {
        Self { total, used: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.total.saturating_sub(self.used)
    }

    /// The most one source may occupy: the smaller of the per-blob cap and
    /// whatever the bundle has left.
    pub(super) fn cap_for(&self, per_source: usize) -> usize {
        per_source.min(self.remaining())
    }

    pub(super) fn spend(&mut self, label: &str, bytes: usize) -> Result<()> {
        if bytes > self.remaining() {
            return Err(Error::Policy(format!(
                "the policy bundle exceeds its {} byte budget at {label}; {} bytes were already \
                 read and this source adds {bytes}",
                self.total, self.used
            )));
        }
        self.used += bytes;
        Ok(())
    }
}

/// One resolved source: its bytes and the identity it was pinned to.
pub(super) struct LoadedSource {
    pub(super) commit: Option<String>,
    pub(super) blob_sha: Option<String>,
    pub(super) bytes: Vec<u8>,
}

pub(super) async fn load_source<G: GitHub>(
    client: &G,
    source: &PolicySource,
    limits: &Limits,
    budget: &mut ByteBudget,
) -> Result<LoadedSource> {
    let cap = budget.cap_for(limits.max_blob_bytes);
    match source {
        PolicySource::Local(path) => {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                Error::Policy(format!("cannot read policy {}: {error}", path.display()))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(Error::Policy(format!(
                    "{} is a symlink; airlock never follows a link to reach a file it will trust",
                    path.display()
                )));
            }
            if metadata.len() as usize > cap {
                return Err(Error::Policy(format!(
                    "{} is {} bytes, over the {cap} bytes the policy bundle has left of its {} \
                     byte budget",
                    path.display(),
                    metadata.len(),
                    limits.max_total_bytes
                )));
            }
            let bytes = std::fs::read(path).map_err(|error| Error::Io {
                path: path.clone(),
                source: error,
            })?;
            budget.spend(&path.display().to_string(), bytes.len())?;
            // A local file has no commit and no blob sha; its content hash is
            // the only immutable identity it has.
            Ok(LoadedSource {
                commit: None,
                blob_sha: None,
                bytes,
            })
        }
        PolicySource::Remote {
            owner,
            repo,
            path,
            reference,
        } => {
            let target = reference.as_deref().unwrap_or("HEAD");
            let commit = client
                .resolve_commit(owner, repo, target)
                .await
                .map_err(|error| {
                    Error::Policy(format!(
                        "cannot resolve `{target}` in {owner}/{repo}: {error}"
                    ))
                })?;
            // `read_file_at` compares the tree entry's declared size against
            // the cap, so an oversized blob is refused before it is fetched.
            let file = read_file_at(client, owner, repo, &commit, path, cap)
                .await
                .map_err(|error| {
                    Error::Policy(format!("cannot read {owner}/{repo}:{path}: {error}"))
                })?;
            let Some((blob_sha, bytes)) = file else {
                return Err(Error::Policy(format!(
                    "no policy at {owner}/{repo}:{path}@{commit}. Airlock ships no built-in \
                     policy, so there is nothing to audit against."
                )));
            };
            budget.spend(&format!("{owner}/{repo}:{path}"), bytes.len())?;
            Ok(LoadedSource {
                commit: Some(commit),
                blob_sha: Some(blob_sha),
                bytes,
            })
        }
    }
}

pub(super) fn to_text(label: &str, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::Policy(format!("{label} is not valid UTF-8")))
}

pub(super) fn content_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
