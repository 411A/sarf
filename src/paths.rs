//! Centralized data-directory layout.
//!
//! SARF keeps *all* persistent state in one directory so a single executable plus
//! one folder is a complete installation:
//!
//! ```text
//! sarf                       # the single executable
//! sarf-data/
//!   sarf.toml                # configuration (written by `sarf init`)
//!   sarf.db                  # SQLite database (WAL mode)
//!   sarf.db-wal, sarf.db-shm # SQLite WAL sidecars
//!   reports/                 # generated self-contained HTML reports
//!   sarf.log                 # SARF's own bounded diagnostic log
//! ```
//!
//! Resolution order (first match wins):
//! 1. `--data-dir <path>`
//! 2. `SARF_DATA_DIR` environment variable
//! 3. `sarf-data/` next to the executable
//! 4. `sarf-data/` in the current working directory (when the executable path is
//!    unavailable, e.g. exotic wrappers)

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Default data directory name, placed next to the executable.
pub const DATA_DIR_NAME: &str = "sarf-data";
/// Configuration file name inside the data directory.
pub const CONFIG_FILE: &str = "sarf.toml";
/// Database file name inside the data directory.
pub const DB_FILE: &str = "sarf.db";
/// Reports subdirectory name.
pub const REPORTS_DIR: &str = "reports";
/// SARF's own diagnostic log file name.
pub const LOG_FILE: &str = "sarf.log";
/// Environment variable overriding the data directory.
pub const ENV_DATA_DIR: &str = "SARF_DATA_DIR";

/// Resolved, centralized data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Resolve the data directory using the documented precedence.
    ///
    /// `explicit` is the CLI argument, `env` is the environment value (pass
    /// `std::env::var(ENV_DATA_DIR).ok()`), and `exe` is the executable path.
    pub fn resolve(explicit: Option<&Path>, env: Option<&Path>, exe: Option<&Path>) -> Self {
        let root = explicit
            .map(Path::to_path_buf)
            .or_else(|| env.map(Path::to_path_buf))
            .or_else(|| {
                exe.and_then(Path::parent)
                    .map(|dir| dir.join(DATA_DIR_NAME))
            })
            .unwrap_or_else(|| PathBuf::from(DATA_DIR_NAME));
        Self { root }
    }

    /// Resolve using the process environment and the current executable.
    pub fn from_environment(explicit: Option<&Path>) -> Self {
        let env = std::env::var_os(ENV_DATA_DIR).map(PathBuf::from);
        let exe = std::env::current_exe().ok();
        Self::resolve(explicit, env.as_deref(), exe.as_deref())
    }

    /// Construct directly from a path (tests and integrations).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Data-directory root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Configuration path.
    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    /// Database path.
    pub fn db_path(&self) -> PathBuf {
        self.root.join(DB_FILE)
    }

    /// WAL sidecar path.
    pub fn wal_path(&self) -> PathBuf {
        self.root.join(format!("{DB_FILE}-wal"))
    }

    /// SHM sidecar path.
    pub fn shm_path(&self) -> PathBuf {
        self.root.join(format!("{DB_FILE}-shm"))
    }

    /// Reports directory.
    pub fn reports_dir(&self) -> PathBuf {
        self.root.join(REPORTS_DIR)
    }

    /// SARF diagnostic log path.
    pub fn log_path(&self) -> PathBuf {
        self.root.join(LOG_FILE)
    }

    /// Whether a database already exists in this directory.
    pub fn has_database(&self) -> bool {
        self.db_path().is_file()
    }

    /// Whether a configuration file already exists.
    pub fn has_config(&self) -> bool {
        self.config_path().is_file()
    }

    /// Create the directory layout and write the default configuration if absent.
    ///
    /// Returns `true` when a new configuration file was written.
    pub fn init(&self, overwrite_config: bool) -> Result<bool> {
        std::fs::create_dir_all(&self.root).map_err(|err| Error::io(&self.root, err))?;
        restrict_dir_permissions(&self.root);
        let reports = self.reports_dir();
        std::fs::create_dir_all(&reports).map_err(|err| Error::io(&reports, err))?;
        restrict_dir_permissions(&reports);

        let config_path = self.config_path();
        if overwrite_config || !config_path.exists() {
            let tmp = config_path.with_extension("toml.tmp");
            std::fs::write(&tmp, crate::config::DEFAULT_CONFIG)
                .map_err(|err| Error::io(&tmp, err))?;
            restrict_file_permissions(&tmp);
            std::fs::rename(&tmp, &config_path).map_err(|err| Error::io(&config_path, err))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Total on-disk bytes used by the data directory (bounded walk, one level of
    /// reports included). Missing files count as zero.
    pub fn usage_bytes(&self) -> UsageBytes {
        let mut usage = UsageBytes::default();
        for (name, size) in [
            (DB_FILE, self.db_path()),
            ("wal", self.wal_path()),
            ("shm", self.shm_path()),
        ] {
            if let Ok(meta) = std::fs::metadata(&size) {
                match name {
                    DB_FILE => usage.database = meta.len(),
                    "wal" => usage.wal = meta.len(),
                    _ => usage.shm = meta.len(),
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(self.reports_dir()) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        usage.reports = usage.reports.saturating_add(meta.len());
                    }
                }
            }
        }
        usage
    }

    /// Paths reported by `sarf status`/`sarf doctor` for transparency.
    pub fn layout(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("data directory", self.root.clone()),
            ("configuration", self.config_path()),
            ("database", self.db_path()),
            ("reports", self.reports_dir()),
            ("diagnostic log", self.log_path()),
        ]
    }
}

/// Disk usage accounting for the data directory (guide §11.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageBytes {
    /// Main database file.
    pub database: u64,
    /// WAL sidecar.
    pub wal: u64,
    /// SHM sidecar.
    pub shm: u64,
    /// Generated reports.
    pub reports: u64,
}

impl UsageBytes {
    /// Total bytes counted against the configured budget.
    pub const fn total(&self) -> u64 {
        self.database
            .saturating_add(self.wal)
            .saturating_add(self.shm)
            .saturating_add(self.reports)
    }
}

/// Restrict a directory to owner-only access (`0750` on Unix; no-op elsewhere).
#[allow(
    clippy::missing_const_for_fn,
    reason = "const fn cannot call std::fs::set_permissions on Unix, and the Windows \
              no-op body must have the same signature"
)]
pub fn restrict_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o750);
        let _ = std::fs::set_permissions(path, mode);
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Restrict a file to owner read/write (`0600` on Unix; no-op elsewhere).
#[allow(
    clippy::missing_const_for_fn,
    reason = "const fn cannot call std::fs::set_permissions on Unix, and the Windows \
              no-op body must have the same signature"
)]
pub fn restrict_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, mode);
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_arg_wins_over_everything() {
        let dir = DataDir::resolve(
            Some(Path::new("/tmp/explicit")),
            Some(Path::new("/tmp/env")),
            Some(Path::new("/opt/bin/sarf")),
        );
        assert_eq!(dir.root(), Path::new("/tmp/explicit"));
    }

    #[test]
    fn env_wins_over_executable_directory() {
        let dir = DataDir::resolve(
            None,
            Some(Path::new("/tmp/env")),
            Some(Path::new("/opt/bin/sarf")),
        );
        assert_eq!(dir.root(), Path::new("/tmp/env"));
    }

    #[test]
    fn default_is_next_to_the_executable() {
        let dir = DataDir::resolve(None, None, Some(Path::new("/opt/sarf/bin/sarf")));
        assert_eq!(dir.root(), Path::new("/opt/sarf/bin/sarf-data"));
    }

    #[test]
    fn layout_is_centralized() {
        let dir = DataDir::new("/srv/sarf-data");
        assert_eq!(dir.db_path(), Path::new("/srv/sarf-data/sarf.db"));
        assert_eq!(dir.config_path(), Path::new("/srv/sarf-data/sarf.toml"));
        assert_eq!(dir.reports_dir(), Path::new("/srv/sarf-data/reports"));
        assert_eq!(dir.wal_path(), Path::new("/srv/sarf-data/sarf.db-wal"));
    }

    #[test]
    fn init_creates_layout_and_writes_default_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("nested/sarf-data");
        let dir = DataDir::new(&root);
        assert!(dir.init(false).expect("init"));
        assert!(dir.config_path().is_file());
        assert!(dir.reports_dir().is_dir());
        let text = std::fs::read_to_string(dir.config_path()).expect("config readable");
        assert!(text.contains("[general]"));
        assert!(text.contains("[logs]"));
        // Second init must not clobber an existing configuration.
        std::fs::write(dir.config_path(), "# user edit\n").expect("write");
        assert!(!dir.init(false).expect("init again"));
        let text = std::fs::read_to_string(dir.config_path()).expect("config readable");
        assert_eq!(text, "# user edit\n");
        // Forced overwrite restores defaults.
        assert!(dir.init(true).expect("force init"));
        assert!(std::fs::read_to_string(dir.config_path())
            .expect("read")
            .contains("[general]"));
    }

    #[test]
    fn usage_accounting_counts_sidecars() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = DataDir::new(temp.path());
        dir.init(false).expect("init");
        std::fs::write(dir.db_path(), vec![0u8; 16]).expect("db");
        std::fs::write(dir.wal_path(), vec![0u8; 8]).expect("wal");
        std::fs::write(dir.reports_dir().join("r.html"), vec![0u8; 4]).expect("report");
        let usage = dir.usage_bytes();
        assert_eq!(usage.database, 16);
        assert_eq!(usage.wal, 8);
        assert_eq!(usage.reports, 4);
        assert_eq!(usage.total(), 28);
    }

    #[cfg(unix)]
    #[test]
    fn unix_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = DataDir::new(temp.path().join("d"));
        dir.init(false).expect("init");
        let dir_mode = std::fs::metadata(dir.root())
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(dir.config_path())
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o750);
        assert_eq!(file_mode, 0o600);
    }
}
