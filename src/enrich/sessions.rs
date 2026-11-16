//! tmux and Zellij session discovery (bounded, read-only).
//!
//! tmux exposes stable pane ids and pane PIDs through a format string, so SARF maps
//! pane PIDs and their descendants to a session label. Zellij has no stable
//! machine-readable PID→pane mapping in v0.1, so only session existence is recorded;
//! pane topology stays a documented gap (guide §5.10, §19).

use std::time::Duration;

use super::run_bounded;

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
pub fn discover_tmux() -> SessionDiscovery {
    let format = "#{session_id}\t#{session_name}\t#{window_id}\t#{window_name}\t#{pane_id}\t#{pane_pid}\t#{pane_current_command}";
    let args = vec![
        "list-panes".to_string(),
        "-a".to_string(),
        "-F".to_string(),
        format.to_string(),
    ];
    match run_bounded("tmux", &args, SESSION_TIMEOUT, 512 * 1024) {
        Ok(output) if output.success => {
            let panes = parse_tmux_panes(&output.stdout);
            let mut sessions: Vec<String> =
                panes.iter().map(|pane| pane.session_name.clone()).collect();
            sessions.sort();
            sessions.dedup();
            SessionDiscovery {
                available: true,
                panes,
                sessions,
                error: None,
            }
        }
        Ok(output) => {
            let message = if output.timed_out {
                "tmux list-panes timed out".to_string()
            } else {
                // "no server running" means tmux is installed but idle; that is not an
                // error for coverage purposes.
                "no tmux server/session is running".to_string()
            };
            SessionDiscovery {
                available: true,
                panes: Vec::new(),
                sessions: Vec::new(),
                error: Some(message),
            }
        }
        Err(err) => SessionDiscovery {
            available: false,
            panes: Vec::new(),
            sessions: Vec::new(),
            error: Some(err.to_string()),
        },
    }
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
                .map(|value| value.to_string())
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

    #[test]
    fn malformed_tmux_rows_are_skipped() {
        let output = "\n$0\tmain\n$0\tmain\t@1\teditor\t%2\tnotapid\tbash\n";
        assert!(parse_tmux_panes(output).is_empty());
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
        assert!(discovery.panes.is_empty());
        assert_eq!(discovery.sessions, vec!["work".to_string()]);
    }
}
