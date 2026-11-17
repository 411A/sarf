//! tmux and Zellij session discovery (bounded, read-only).
//!
//! tmux exposes stable pane ids and pane PIDs through a format string, so SARF maps
//! pane PIDs and their descendants to a session label. Zellij has no stable
//! machine-readable PID→pane mapping in v0.1, so only session existence is recorded;
//! pane topology stays a documented gap (guide §5.10, §19).

#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

#[cfg(unix)]
use super::run_bounded_as;
use super::{find_in_path, run_bounded};

/// Discovery timeout for one session-manager query.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(2);

/// One tmux pane binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneBinding {
    /// Stable session id (`$0`).
    pub session_id: String,
    /// Session name.
    pub session_name: String,
    /// Stable window id (`@0`).
    pub window_id: String,
    /// Window name.
    pub window_name: String,
    /// Stable pane id (`%0`).
    pub pane_id: String,
    /// PID of the pane's shell/process.
    pub pane_pid: u32,
    /// Current command in the pane, when tmux reports it.
    pub current_command: Option<String>,
}

impl PaneBinding {
    /// Compact label used on processes and in reports.
    pub fn label(&self) -> String {
        if self.window_name.is_empty() {
            format!("tmux {}:{}", self.session_name, self.pane_id)
        } else {
            format!(
                "tmux {}:{}/{}",
                self.session_name, self.window_name, self.pane_id
            )
        }
    }
}

/// Result of a session-manager probe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDiscovery {
    /// Whether the binary answered.
    pub available: bool,
    /// Pane bindings (tmux only).
    pub panes: Vec<PaneBinding>,
    /// Session names (Zellij and tmux sessions).
    pub sessions: Vec<String>,
    /// Bounded error when unavailable.
    pub error: Option<String>,
}

/// Discover tmux panes with one bounded format-string query.
///
/// tmux sockets are per-user. When SARF runs as root with `PrivateTmp=no`, scan
/// `/tmp/tmux-*` and query each socket explicitly with `tmux -S`. The client is
/// executed as the socket owner, not as root, so a malicious socket cannot
/// exercise root privileges. The default current-user query remains the fallback.
pub fn discover_tmux() -> SessionDiscovery {
    let format = "#{session_id}\t#{session_name}\t#{window_id}\t#{window_name}\t#{pane_id}\t#{pane_pid}\t#{pane_current_command}";
    if find_in_path("tmux").is_none() {
        return SessionDiscovery {
            available: false,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some("tmux not installed".to_string()),
        };
    }

    #[cfg(unix)]
    {
        let sockets = tmux_socket_paths();
        if !sockets.is_empty() {
            let count = sockets.len();
            let mut panes = Vec::new();
            let mut succeeded = false;
            let mut last_error = None;
            for socket in sockets {
                let Ok(metadata) = std::fs::metadata(&socket) else {
                    continue;
                };
                let args = tmux_socket_args(&socket, format);
                match run_bounded_as(
                    "tmux",
                    &args,
                    SESSION_TIMEOUT,
                    512 * 1024,
                    metadata.uid(),
                    metadata.gid(),
                ) {
                    Ok(output) if output.success => {
                        succeeded = true;
                        panes.extend(parse_tmux_panes(&output.stdout));
                    }
                    Ok(output) => {
                        last_error = Some(if output.timed_out {
                            format!("{}: tmux list-panes timed out", socket.display())
                        } else {
                            format!("{}: tmux server closed the query", socket.display())
                        });
                    }
                    Err(err) => last_error = Some(format!("{}: {err}", socket.display())),
                }
            }
            if succeeded {
                return discovery_from_panes(panes);
            }
            return SessionDiscovery {
                available: true,
                panes: Vec::new(),
                sessions: Vec::new(),
                error: Some(format!(
                    "no tmux server is visible to the service user (scanned {count} socket(s){})",
                    last_error
                        .map(|error| format!("; last error: {error}"))
                        .unwrap_or_default()
                )),
            };
        }
    }

    let args = vec![
        "list-panes".to_string(),
        "-a".to_string(),
        "-F".to_string(),
        format.to_string(),
    ];
    match run_bounded("tmux", &args, SESSION_TIMEOUT, 512 * 1024) {
        Ok(output) if output.success => discovery_from_panes(parse_tmux_panes(&output.stdout)),
        Ok(output) => SessionDiscovery {
            available: true,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some(if output.timed_out {
                "tmux list-panes timed out".to_string()
            } else {
                "no tmux server is visible to the service user (tmux sessions are per-user)"
                    .to_string()
            }),
        },
        Err(err) => SessionDiscovery {
            available: false,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some(err.to_string()),
        },
    }
}

fn discovery_from_panes(panes: Vec<PaneBinding>) -> SessionDiscovery {
    let mut sessions: Vec<String> = panes.iter().map(|pane| pane.session_name.clone()).collect();
    sessions.sort();
    sessions.dedup();
    SessionDiscovery {
        available: true,
        panes,
        sessions,
        error: None,
    }
}

#[cfg(unix)]
fn tmux_socket_args(socket: &Path, format: &str) -> Vec<String> {
    vec![
        "-S".to_string(),
        socket.to_string_lossy().into_owned(),
        "list-panes".to_string(),
        "-a".to_string(),
        "-F".to_string(),
        format.to_string(),
    ]
}

#[cfg(unix)]
fn tmux_socket_paths() -> Vec<PathBuf> {
    socket_paths_in(Path::new("/tmp"))
}

/// Bounded scan of `/tmp/tmux-<uid>/*` socket files.
#[cfg(unix)]
fn socket_paths_in(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut directories: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("tmux-"))
        .map(|entry| entry.path())
        .collect();
    directories.sort();
    directories.truncate(64);

    let mut sockets = Vec::new();
    for directory in directories {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok).take(32) {
            let is_socket = entry
                .file_type()
                .is_ok_and(|file_type| file_type.is_socket());
            if is_socket {
                sockets.push(entry.path());
                if sockets.len() >= 128 {
                    return sockets;
                }
            }
        }
    }
    sockets
}

/// Parse `tmux list-panes -F` tab-separated output.
pub fn parse_tmux_panes(text: &str) -> Vec<PaneBinding> {
    let mut panes = Vec::new();
    for line in text.lines() {
        if panes.len() >= 4096 {
            break;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 6 {
            continue;
        }
        let Ok(pane_pid) = fields[5].parse::<u32>() else {
            continue;
        };
        panes.push(PaneBinding {
            session_id: fields[0].to_string(),
            session_name: fields[1].to_string(),
            window_id: fields[2].to_string(),
            window_name: fields[3].to_string(),
            pane_id: fields[4].to_string(),
            pane_pid,
            current_command: fields
                .get(6)
                .map(ToString::to_string)
                .filter(|value| !value.is_empty()),
        });
    }
    panes
}

/// Discover Zellij sessions by name (session-level only).
pub fn discover_zellij() -> SessionDiscovery {
    let args = vec!["list-sessions".to_string(), "--short".to_string()];
    match run_bounded("zellij", &args, SESSION_TIMEOUT, 256 * 1024) {
        Ok(output) if output.success => {
            let mut sessions: Vec<String> = output
                .stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| {
                    // `--short` appends status such as ` [Created 2h ago]`.
                    line.split(" [").next().unwrap_or(line).to_string()
                })
                .take(256)
                .collect();
            sessions.sort();
            sessions.dedup();
            SessionDiscovery {
                available: true,
                panes: Vec::new(),
                sessions,
                error: None,
            }
        }
        Ok(output) => SessionDiscovery {
            available: true,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some(if output.timed_out {
                "zellij list-sessions timed out".to_string()
            } else {
                "no Zellij session is running".to_string()
            }),
        },
        Err(err) => SessionDiscovery {
            available: false,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some(err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tmux_panes_and_labels() {
        let output = "$0\tmain\t@1\teditor\t%2\t4242\tvim\n$0\tmain\t@1\teditor\t%3\t4243\tbash\n";
        let panes = parse_tmux_panes(output);
        assert_eq!(panes.len(), 2);
        assert_eq!(panes[0].pane_pid, 4242);
        assert_eq!(panes[0].label(), "tmux main:editor/%2");
        let mut sessions: Vec<String> = panes.iter().map(|p| p.session_name.clone()).collect();
        sessions.dedup();
        assert_eq!(sessions, vec!["main".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn finds_per_user_tmux_sockets() {
        use std::os::unix::net::UnixListener;

        let root = std::env::temp_dir().join(format!(
            "sarf-tmux-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let tmux_dir = root.join("tmux-1000");
        std::fs::create_dir_all(&tmux_dir).expect("tmux dir");
        let _listener = UnixListener::bind(tmux_dir.join("default")).expect("socket");
        let sockets = socket_paths_in(&root);
        assert_eq!(sockets.len(), 1);
        assert!(sockets[0].ends_with("tmux-1000/default"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_tmux_rows_are_skipped() {
        let output = "\n$0\tmain\n$0\tmain\t@1\teditor\t%2\tnotapid\tbash\n";
        assert_eq!(parse_tmux_panes(output).len(), 0);
    }

    #[test]
    fn zellij_output_is_not_parsed_as_panes() {
        // Zellij has no pane PID contract in v0.1; empty pane list is intentional.
        let discovery = SessionDiscovery {
            available: true,
            panes: Vec::new(),
            sessions: vec!["work".to_string()],
            error: None,
        };
        assert_eq!(discovery.panes.len(), 0);
        assert_eq!(discovery.sessions, vec!["work".to_string()]);
    }
}
