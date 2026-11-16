//! Bounded enrichment via optional external CLIs and read-only metadata.
//!
//! v0.1 deliberately uses small CLI queries instead of the Docker Engine API,
//! D-Bus or the Zellij plugin API. Every command is bounded by wall-clock timeout,
//! output bytes and invocation cadence; failures degrade enrichment only and never
//! stop universal process accounting (`docs/DECISIONS.md`).

pub mod docker;
pub mod sessions;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Maximum bytes captured from one enrichment command.
pub const MAX_COMMAND_BYTES: usize = 1024 * 1024;

/// Result of a bounded external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit status code, `None` when killed by a signal/timeout.
    pub status: Option<i32>,
    /// Whether the process reported success.
    pub success: bool,
    /// Captured stdout, lossily decoded and bounded.
    pub stdout: String,
    /// Whether stdout was cut at the byte cap.
    pub truncated: bool,
    /// Whether SARF killed the process at the timeout.
    pub timed_out: bool,
}

/// Run a command with a hard wall-clock and output bound.
///
/// `std` has no portable `wait_timeout`; this helper polls `try_wait` and kills the
/// child at the deadline. stdout is drained on a helper thread so a chatty command
/// cannot deadlock on a full pipe. stderr is discarded. No shell is involved and the
/// caller passes an explicit argument vector, so no untrusted string is interpreted.
pub fn run_bounded(
    program: &str,
    args: &[String],
    timeout: Duration,
    max_bytes: usize,
) -> Result<CommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Error::unavailable("external command", format!("{program} not found"))
            } else {
                Error::io(program, err)
            }
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::unavailable("external command", "stdout pipe unavailable"))?;
    let reader = std::thread::spawn(move || read_bounded(stdout, max_bytes));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                break child.wait().ok();
            }
        }
    };
    let (bytes, truncated) = match reader.join() {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::unavailable(
                "external command",
                "output reader panicked",
            ))
        }
    };
    let success = status.is_some_and(|status| status.success());
    Ok(CommandOutput {
        status: status.and_then(|status| status.code()),
        success,
        stdout: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        timed_out,
    })
}

fn read_bounded(mut reader: impl std::io::Read, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = max_bytes.saturating_sub(output.len());
                if read > remaining {
                    output.extend_from_slice(&buffer[..remaining]);
                    truncated = true;
                    break;
                }
                output.extend_from_slice(&buffer[..read]);
                if output.len() >= max_bytes {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (output, truncated)
}

/// Find an executable in `PATH` without spawning it.
pub fn find_in_path(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn bounded_command_captures_stdout() {
        let output = run_bounded(
            "sh",
            &["-c".to_string(), "printf 'hello\\n'".to_string()],
            Duration::from_secs(2),
            MAX_COMMAND_BYTES,
        )
        .expect("command");
        assert!(output.success);
        assert_eq!(output.stdout, "hello\n");
        assert!(!output.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_truncates_output() {
        let output = run_bounded(
            "sh",
            &["-c".to_string(), "printf 'xxxxxxxxxxxxxxxx'".to_string()],
            Duration::from_secs(2),
            8,
        )
        .expect("command");
        assert_eq!(output.stdout.len(), 8);
        assert!(output.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_kills_at_timeout() {
        let started = Instant::now();
        let output = run_bounded(
            "sh",
            &["-c".to_string(), "sleep 5".to_string()],
            Duration::from_millis(150),
            MAX_COMMAND_BYTES,
        )
        .expect("command");
        assert!(output.timed_out);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn missing_program_is_unavailable() {
        let err = run_bounded(
            "sarf-definitely-not-a-real-program",
            &[],
            Duration::from_millis(100),
            1024,
        )
        .expect_err("missing");
        assert!(matches!(err, Error::Unavailable { .. }));
    }
}
