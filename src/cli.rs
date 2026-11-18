//! Command-line definition for `sarf`.
//!
//! Parsing and presentation live here and under [`crate::commands`]; collection and
//! storage stay in their own modules. Every command supports global `--data-dir`,
//! `--config` and `--json` so scripting never needs to scrape a table.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// SARF — Service Activity Recorder & Forensics.
#[derive(Debug, Parser)]
#[command(
    name = "sarf",
    version,
    about = "Lightweight Linux process, service and activity forensics",
    long_about = "Records which services and processes consumed which resources, correlates \
                  bounded logs and lifecycle events, and exports one self-contained offline \
                  HTML report. Missing data is shown as unavailable, never as zero."
)]
pub struct Cli {
    /// Centralized data directory (default: `SARF_DATA_DIR` or ./sarf-data).
    #[arg(long, global = true, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
    /// Configuration file (default: <data-dir>/sarf.toml).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Emit machine-readable JSON instead of a table where supported.
    #[arg(long, global = true)]
    pub json: bool,
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the data directory and default configuration.
    Init {
        /// Overwrite an existing configuration with the defaults.
        #[arg(long)]
        force: bool,
    },
    /// Install or update the system-wide service from this binary (Linux, root).
    Install(InstallArgs),
    /// Run the collection daemon.
    Run(RunArgs),
    /// Check kernel, /proc, cgroup, permissions, database and optional tools.
    Doctor,
    /// Show database size, row counts, latest run and collector state.
    Status {
        /// Compact JSON: freshness, storage and gaps only (no collector table).
        #[arg(long)]
        brief: bool,
    },
    /// Show detected kernel/runtime capabilities and known gaps.
    Capabilities,
    /// List open and resolved coverage gaps.
    Gaps,
    /// Rank entities by resource use over a window.
    Top {
        /// Window such as 15m, 1h, 24h, 7d, or RFC3339.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Metric to rank by.
        #[arg(long, value_enum, default_value = "cpu")]
        by: ByMetric,
        /// Only container cgroups and the processes running inside containers.
        #[arg(long)]
        containers: bool,
        /// Maximum rows.
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// List process lifetimes overlapping a window.
    Processes {
        /// Window such as 60m, 24h.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Case-insensitive filter on comm/executable/tool/unit/container.
        #[arg(long)]
        filter: Option<String>,
        /// Maximum rows.
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Print a process tree from observed lifetimes.
    Tree {
        /// Window.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Restrict to one process instance and its ancestors.
        #[arg(long)]
        process: Option<String>,
        /// Restrict to a service/tool/container label.
        #[arg(long)]
        service: Option<String>,
        /// Maximum nodes.
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Explain high and low resource windows with ranked contributors and evidence.
    Why {
        /// Window.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Maximum windows.
        #[arg(long, default_value_t = 12)]
        limit: usize,
        /// Optional metric filter (cpu, memory, `psi_cpu`, `psi_memory`, `psi_io`, load).
        #[arg(long)]
        metric: Option<String>,
    },
    /// Group resource windows with actors, logs, events and process links.
    Story {
        /// Window.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Maximum groups.
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// List incidents in a window.
    Incidents {
        /// Window.
        #[arg(long, default_value = "24h")]
        since: String,
        /// Maximum rows.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one incident with evidence, logs and events.
    Show {
        /// Incident id.
        incident_id: i64,
    },
    /// Query retained log records.
    Logs {
        /// Source id, or `all`.
        source: String,
        /// Window.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Case-insensitive substring filter.
        #[arg(long)]
        grep: Option<String>,
        /// Minimum level (debug, info, warn, error, critical).
        #[arg(long)]
        level: Option<String>,
        /// Maximum rows.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Build one self-contained offline HTML report.
    #[command(alias = "graph")]
    Report {
        /// Window.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Output path (default: <data-dir>/reports/sarf-report-<timestamp>.html).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Restrict the report to one incident.
        #[arg(long)]
        incident: Option<i64>,
        /// Restrict the process tree to one process instance.
        #[arg(long)]
        process: Option<String>,
        /// Restrict ranked entities/tree to a service label.
        #[arg(long)]
        service: Option<String>,
    },
    /// Export entity usage and incidents as bounded JSON or CSV.
    Export {
        /// Window.
        #[arg(long, default_value = "24h")]
        since: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "csv")]
        format: ExportFormat,
        /// Output path (default: stdout).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Run retention, rollups and the disk guard once.
    ///
    /// Run it while the service is stopped: the daemon runs the same pass on
    /// its own cadence and a second writer only makes both wait on locks.
    Prune,
    /// Emit peak dossiers as machine JSON for agent analysis.
    ///
    /// A peak is relative to the entity's own rolling baseline, not an absolute
    /// threshold. The document carries a typed graph of host, cgroups and
    /// processes with their values plus a bounded series around each episode.
    Peaks {
        /// Window to analyse.
        #[arg(long, default_value = "72h")]
        since: String,
        /// Only container cgroups (Docker/containerd/k8s), never host or system units.
        #[arg(long)]
        containers: bool,
        /// Read dossiers stored by the daemon instead of detecting now.
        #[arg(long)]
        stored: bool,
        /// Print one CSV row per peak instead of the JSON graph document.
        #[arg(long)]
        csv: bool,
        /// Write the JSON document to this path instead of stdout.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Profile CPU self time of a container's live processes (Linux).
    ///
    /// Runs external `perf` for a bounded interval and reports the symbols that
    /// consumed CPU. This is deliberate: a BPF loader would need libbpf, kernel
    /// headers and `unsafe`, while `perf` is an ordinary read-only command. The
    /// answer is self time by symbol, never a call graph, and the command says
    /// "unavailable" when the host lacks perf or forbids sampling.
    Profile {
        /// Container name or id as recorded by SARF (`top --containers`).
        #[arg(long, required_unless_present = "pid")]
        container: Option<String>,
        /// Live PID to profile instead of a container.
        #[arg(long, required_unless_present = "container", value_parser = clap::value_parser!(u32).range(1..))]
        pid: Option<u32>,
        /// Sampling duration in seconds.
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        /// Sampling frequency in Hz.
        #[arg(long, default_value_t = 999)]
        hz: u64,
    },
    /// Measure bounded collection and database write throughput.
    Benchmark {
        /// Cycles to measure.
        #[arg(long, default_value_t = 20)]
        cycles: u64,
        /// Fixture tree instead of the live host.
        #[arg(long, value_name = "PATH")]
        fixture_root: Option<PathBuf>,
    },
    /// Inspect the declarative integration catalog.
    Tools {
        /// Catalog operation.
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

/// Arguments for `sarf install`.
#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Install prefix for the binary (default: /usr/local).
    #[arg(long, default_value = "/usr/local", value_name = "PATH")]
    pub prefix: PathBuf,
    /// Service user and group (default: sarf).
    #[arg(long, default_value = "sarf", value_name = "NAME")]
    pub user: String,
    /// Add the service user to the docker group (root-equivalent).
    #[arg(long)]
    pub docker_group: bool,
    /// Run as root with PrivateTmp=no for full /proc, Docker and tmux visibility.
    #[arg(long)]
    pub full_observation: bool,
    /// Enable and start the systemd unit after installing it.
    #[arg(long)]
    pub start: bool,
    /// Do not install or reload a systemd unit.
    #[arg(long)]
    pub no_systemd: bool,
}

/// Daemon arguments.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Stop after N cycles (0 or omitted means run until terminated).
    #[arg(long, default_value_t = 0)]
    pub cycles: u64,
    /// Replay a fixture tree instead of the live host (simulated, no sleeping).
    #[arg(long, value_name = "PATH")]
    pub fixture_root: Option<PathBuf>,
    /// Mark the run simulated without a fixture root.
    #[arg(long)]
    pub simulate: bool,
    /// Override the normal sampling cadence.
    #[arg(long, value_name = "SECONDS")]
    pub interval_secs: Option<u64>,
}

/// Ranking metrics accepted by `top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ByMetric {
    /// CPU percentage of one core.
    Cpu,
    /// Memory bytes.
    Mem,
    /// Network bytes.
    Net,
    /// Storage I/O bytes.
    Io,
}

/// Export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Comma-separated entity usage table.
    Csv,
    /// JSON document with usage, incidents and coverage.
    Json,
}

/// `tools` subcommands.
#[derive(Debug, Subcommand)]
pub enum ToolsCommand {
    /// List all known integrations.
    List,
    /// Show one integration descriptor.
    Show {
        /// Integration id.
        id: String,
    },
    /// Search ids, names, executables and descriptions.
    Search {
        /// Query string.
        query: String,
    },
}
