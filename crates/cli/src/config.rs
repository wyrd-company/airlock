//! Credential storage.
//!
//! The file airlock writes here holds a user access token and, when GitHub
//! issues expiring tokens, its refresh token. It is treated as a secret from
//! the first syscall: created `0600` before anything is written to it, replaced
//! by an atomic rename in the same directory, and refused outright if it is a
//! symlink or readable by anyone but its owner. Rotation of expiring grants is
//! serialised by a lock file, because two airlock processes racing to refresh
//! would leave one of them holding a token GitHub has already invalidated.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};

/// The default profile name.
pub const DEFAULT_PROFILE: &str = "default";

/// How long a lock may be waited for before airlock gives up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a lock file may exist before it is treated as abandoned.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(60);

/// One stored credential.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The user access token, while it is still worth trying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// When the access token expires, in seconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<u64>,
    /// The refresh token, when GitHub issued an expiring access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The account the credential was acquired for, for `auth status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
}

impl Profile {
    /// Whether the access token is still usable, with a safety margin.
    #[must_use]
    pub fn access_token_is_fresh(&self, now: u64) -> bool {
        // A token about to expire is treated as expired: an audit takes longer
        // than the margin, and a mid-run expiry is a confusing failure.
        const MARGIN_SECONDS: u64 = 120;
        match (&self.access_token, self.access_token_expires_at) {
            (Some(_), Some(expires_at)) => expires_at > now + MARGIN_SECONDS,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Stored credentials, by profile name.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Config {
    /// The named profile, if it is stored.
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }
}

/// Where the configuration file lives.
///
/// # Errors
///
/// Returns an error when neither `XDG_CONFIG_HOME` nor `HOME` is set, because
/// airlock will not guess at a path it is about to write a secret into.
pub fn config_path() -> Result<PathBuf> {
    config_path_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The configuration path implied by two directory settings.
///
/// Split out from [`config_path`] so the precedence is testable without
/// reaching into the process environment.
///
/// # Errors
///
/// Returns an error when neither setting is usable.
pub fn config_path_from(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    if let Some(base) = xdg_config_home.filter(|base| !base.is_empty()) {
        return Ok(PathBuf::from(base).join("airlock").join("config.toml"));
    }
    let home = home
        .filter(|home| !home.is_empty())
        .context("neither XDG_CONFIG_HOME nor HOME is set, so airlock cannot locate its config")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("airlock")
        .join("config.toml"))
}

/// Read the configuration, refusing a file that is not safe to trust.
///
/// A missing file is an empty configuration, not an error.
///
/// # Errors
///
/// Returns an error when the file is a symlink, is readable by anyone but its
/// owner, or is not valid configuration.
pub fn load(path: &Path) -> Result<Config> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => return Err(error).context(format!("cannot read {}", path.display())),
    };

    if metadata.file_type().is_symlink() {
        bail!(
            "{} is a symlink. Airlock will not read a credential through a link it cannot vouch \
             for; replace it with a regular file.",
            path.display()
        );
    }
    if !metadata.file_type().is_file() {
        bail!("{} is not a regular file.", path.display());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {mode:o}; it holds a credential and must be readable only by its owner. \
             Run `chmod 600 {}`.",
            path.display(),
            path.display()
        );
    }

    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("{} is not valid airlock config", path.display()))
}

/// Write the configuration, atomically, mode `0600` from creation.
///
/// # Errors
///
/// Returns an error when the file cannot be created or replaced.
pub fn store(path: &Path, config: &Config) -> Result<()> {
    let directory = path
        .parent()
        .context("the config path has no parent directory")?;
    std::fs::create_dir_all(directory)
        .with_context(|| format!("cannot create {}", directory.display()))?;
    restrict_directory(directory)?;

    let text = toml::to_string_pretty(config).context("cannot serialise the airlock config")?;

    // The temporary file is in the same directory so the rename is atomic, and
    // is created 0600 so the secret is never briefly world-readable.
    let temporary = directory.join(format!(".config.toml.{}.tmp", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("cannot flush {}", temporary.display()))?;
    }

    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "cannot replace {} with {}",
            path.display(),
            temporary.display()
        )
    })
}

fn restrict_directory(directory: &Path) -> Result<()> {
    let metadata = std::fs::metadata(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(directory, permissions)
            .with_context(|| format!("cannot restrict {}", directory.display()))?;
    }
    Ok(())
}

/// A held lock over one profile's rotation.
///
/// Refreshing invalidates the previous access and refresh tokens immediately,
/// so two processes refreshing at once would leave the loser holding a dead
/// credential. The lock makes rotation one-at-a-time.
#[derive(Debug)]
pub struct RotationLock {
    path: PathBuf,
}

impl RotationLock {
    /// Acquire the lock, waiting for a holder that is still alive.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock is held for longer than the timeout.
    pub fn acquire(config_path: &Path, profile: &str) -> Result<Self> {
        let directory = config_path
            .parent()
            .context("the config path has no parent directory")?;
        std::fs::create_dir_all(directory)
            .with_context(|| format!("cannot create {}", directory.display()))?;
        let path = directory.join(format!(".{profile}.lock"));

        let deadline = SystemTime::now() + LOCK_TIMEOUT;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if is_stale(&path) {
                        // A crash between creating the lock and releasing it
                        // would otherwise wedge every future run.
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if SystemTime::now() > deadline {
                        bail!(
                            "another airlock process has held {} for over {} seconds. If none is \
                             running, delete it.",
                            path.display(),
                            LOCK_TIMEOUT.as_secs()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => {
                    return Err(error).context(format!("cannot create {}", path.display()))
                }
            }
        }
    }
}

fn is_stale(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified
        .elapsed()
        .is_ok_and(|elapsed| elapsed > LOCK_STALE_AFTER)
}

impl Drop for RotationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Seconds since the epoch.
#[must_use]
pub fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Read a token from a file, refusing one anyone else can read.
///
/// # Errors
///
/// Returns an error when the file is a symlink, is group or world readable, or
/// cannot be read.
pub fn read_token_file(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "{} is a symlink. Airlock will not read a credential through a link it cannot vouch \
             for.",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {mode:o}; a token file must be readable only by its owner.",
            path.display()
        );
    }
    let token =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(token.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn profile(refresh: &str) -> Config {
        let mut config = Config::default();
        config.profiles.insert(
            DEFAULT_PROFILE.to_owned(),
            Profile {
                access_token: Some("ghu_example".to_owned()),
                access_token_expires_at: Some(now_epoch_seconds() + 3600),
                refresh_token: Some(refresh.to_owned()),
                login: Some("example-user".to_owned()),
            },
        );
        config
    }

    #[test]
    fn a_stored_config_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("airlock").join("config.toml");
        let config = profile("ghr_example");
        store(&path, &config).unwrap();
        assert_eq!(load(&path).unwrap(), config);
    }

    #[test]
    fn a_stored_config_is_owner_only_from_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("airlock").join("config.toml");
        store(&path, &profile("ghr_example")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "stored as {mode:o}");
    }

    #[test]
    fn storing_twice_replaces_rather_than_appends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("airlock").join("config.toml");
        store(&path, &profile("ghr_first")).unwrap();
        store(&path, &profile("ghr_second")).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(
            loaded
                .profile(DEFAULT_PROFILE)
                .unwrap()
                .refresh_token
                .as_deref(),
            Some("ghr_second")
        );
        // No temporary files are left behind to be read by anyone else.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_missing_config_is_empty_rather_than_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nothing-here.toml");
        assert_eq!(load(&path).unwrap(), Config::default());
    }

    #[test]
    fn a_symlinked_config_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.toml");
        std::fs::write(&real, "").unwrap();
        let link = directory.path().join("config.toml");
        symlink(&real, &link).unwrap();
        let error = load(&link).unwrap_err().to_string();
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn a_group_readable_config_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let error = load(&path).unwrap_err().to_string();
        assert!(error.contains("owner"), "{error}");
    }

    #[test]
    fn a_group_readable_token_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, "ghu_example").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token_file(&path).is_err());
    }

    #[test]
    fn a_private_token_file_is_read_and_trimmed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, "  ghu_example\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token_file(&path).unwrap(), "ghu_example");
    }

    #[test]
    fn a_rotation_lock_excludes_a_second_holder() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("airlock").join("config.toml");
        let held = RotationLock::acquire(&path, DEFAULT_PROFILE).unwrap();
        // The second acquisition would block for the timeout, so this asserts
        // the lock file exists rather than waiting it out.
        assert!(directory
            .path()
            .join("airlock")
            .join(format!(".{DEFAULT_PROFILE}.lock"))
            .exists());
        drop(held);
        assert!(!directory
            .path()
            .join("airlock")
            .join(format!(".{DEFAULT_PROFILE}.lock"))
            .exists());
    }

    #[test]
    fn a_token_expiring_within_the_margin_is_treated_as_expired() {
        let now = now_epoch_seconds();
        let profile = Profile {
            access_token: Some("ghu_example".to_owned()),
            access_token_expires_at: Some(now + 30),
            refresh_token: None,
            login: None,
        };
        assert!(!profile.access_token_is_fresh(now));

        let fresh = Profile {
            access_token_expires_at: Some(now + 3600),
            ..profile
        };
        assert!(fresh.access_token_is_fresh(now));
    }

    #[test]
    fn the_config_path_follows_xdg_then_home() {
        assert_eq!(
            config_path_from(Some("/x".into()), Some("/h".into())).unwrap(),
            PathBuf::from("/x/airlock/config.toml")
        );
        assert_eq!(
            config_path_from(None, Some("/h".into())).unwrap(),
            PathBuf::from("/h/.config/airlock/config.toml")
        );
        assert_eq!(
            config_path_from(Some("".into()), Some("/h".into())).unwrap(),
            PathBuf::from("/h/.config/airlock/config.toml")
        );
        assert!(config_path_from(None, None).is_err());
    }
}
