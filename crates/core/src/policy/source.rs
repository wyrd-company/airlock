use super::*;

impl PolicySource {
    /// The canonical policy location for an owner.
    #[must_use]
    pub fn default_for_owner(owner: &str) -> Self {
        PolicySource::Remote {
            owner: owner.to_owned(),
            repo: ".github".to_owned(),
            path: "airlock/policy.yml".to_owned(),
            reference: None,
        }
    }

    /// Parse a `--policy` value.
    ///
    /// # Errors
    ///
    /// Returns a policy error when the value is neither a local path nor a
    /// well-formed `owner/repo:path[@ref]` reference.
    pub fn parse(value: &str) -> Result<Self> {
        if value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with('/')
            || value.starts_with('~')
        {
            return Ok(PolicySource::Local(PathBuf::from(value)));
        }

        let Some((repository, rest)) = value.split_once(':') else {
            return Err(Error::Policy(format!(
                "`{value}` is neither a local path (starting `./`, `../`, or `/`) nor an \
                 `owner/repo:path[@ref]` reference"
            )));
        };
        let Some((owner, repo)) = repository.split_once('/') else {
            return Err(Error::Policy(format!(
                "`{value}` should name a repository as `owner/repo:path[@ref]`"
            )));
        };
        let (path, reference) = match rest.split_once('@') {
            Some((path, reference)) => (path, Some(reference.to_owned())),
            None => (rest, None),
        };
        if owner.is_empty() || repo.is_empty() || path.is_empty() {
            return Err(Error::Policy(format!(
                "`{value}` has an empty owner, repository, or path"
            )));
        }
        Ok(PolicySource::Remote {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            path: path.to_owned(),
            reference,
        })
    }

    /// A stable label for output.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            PolicySource::Remote {
                owner,
                repo,
                path,
                reference,
            } => match reference {
                Some(reference) => format!("{owner}/{repo}:{path}@{reference}"),
                None => format!("{owner}/{repo}:{path}"),
            },
            PolicySource::Local(path) => path.display().to_string(),
        }
    }
}
