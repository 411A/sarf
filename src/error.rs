//! Typed errors for the pieces of SARF that are reused and unit-tested.
//!
//! Command implementations mostly use [`anyhow::Error`]; parsers and the storage
//! layer expose the typed [`Error`] so tests can assert on the failure kind instead
//! of on message text.

use std::path::PathBuf;

/// Errors produced by SARF's typed building blocks.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A source file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Generic I/O error without a meaningful path (socket, pipe, ...).
    #[error(transparent)]
    PlainIo(#[from] std::io::Error),

    /// A source file did not match the documented kernel format.
    #[error("{source_name}: malformed input: {message}")]
    Parse {
        /// Stable name of the format, e.g. `proc/stat`.
        source_name: &'static str,
        /// What was wrong, including a bounded excerpt where useful.
        message: String,
    },

    /// A required kernel interface, controller or file is absent.
    #[error("{what} is unavailable: {reason}")]
    Unavailable {
        /// Interface name, e.g. `cgroup v2 cpu controller`.
        what: &'static str,
        /// Why it is unavailable (ENOENT, permission, kernel config, ...).
        reason: String,
    },

    /// Access was denied by the kernel, mount options, LSM or user permissions.
    #[error("permission denied reading {path}")]
    PermissionDenied {
        /// The path that was not readable.
        path: PathBuf,
    },

    /// Configuration file content was invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Database schema or query failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// A bounded resource was exhausted and the operation refused to grow.
    #[error("capacity exceeded: {what} (limit {limit})")]
    Capacity {
        /// Which bound was hit.
        what: &'static str,
        /// The configured limit.
        limit: u64,
    },
}

/// Convenient result alias for typed SARF operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Build an [`Error::Parse`] with a bounded message.
    pub fn parse(source_name: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        const MAX: usize = 240;
        if message.len() > MAX {
            // Keep the message bounded so a malicious/corrupt source cannot grow logs.
            message.truncate(MAX);
            message.push('…');
        }
        Self::Parse {
            source_name,
            message,
        }
    }

    /// Build an [`Error::Unavailable`].
    pub fn unavailable(what: &'static str, reason: impl Into<String>) -> Self {
        Self::Unavailable {
            what,
            reason: reason.into(),
        }
    }

    /// Build an [`Error::Io`], mapping permission errors to the distinct variant.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        let path = path.into();
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            return Self::PermissionDenied { path };
        }
        Self::Io { path, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_messages_are_bounded() {
        let err = Error::parse("proc/stat", "x".repeat(10_000));
        let text = err.to_string();
        assert!(
            text.len() < 400,
            "message must stay bounded: {}",
            text.len()
        );
    }

    #[test]
    fn permission_errors_are_distinguished() {
        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err = Error::io("/proc/1/io", io);
        assert!(matches!(err, Error::PermissionDenied { .. }));
    }

    #[test]
    fn io_errors_keep_the_path() {
        let io = std::io::Error::from(std::io::ErrorKind::NotFound);
        let err = Error::io("/proc/stat", io);
        match err {
            Error::Io { path, .. } => assert_eq!(path, PathBuf::from("/proc/stat")),
            other => panic!("unexpected error: {other}"),
        }
    }
}
