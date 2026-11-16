//! CLI command implementations and shared presentation helpers.
//!
//! Commands format data and call the read-only query layer; collection logic lives in
//! `collect`, `daemon`, `analysis` and `report`. Tables are compact and bounded;
//! `--json` mirrors the same data for scripts.

pub mod export;
pub mod query;
pub mod system;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone};
use clap::Parser;
use serde::Serialize;

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::paths::DataDir;
use crate::store::query::Window;
use crate::store::Store;
use crate::time::{format_wall_rfc3339, Clock, SystemClock, WallNs};

/// Shared command context.
#[derive(Debug, Clone)]
pub struct Context {
    /// Resolved data directory.
    pub data_dir: DataDir,
    /// Validated configuration.
    pub config: Config,
    /// JSON output requested.
    pub json: bool,
    /// One wall-clock reading for the whole command.
    pub now: WallNs,
}

impl Context {
    /// Build context from global arguments.
    pub fn new(cli: &Cli) -> Result<Self> {
        let data_dir = DataDir::from_environment(cli.data_dir.as_deref());
        let config_path = cli.config.clone().unwrap_or_else(|| data_dir.config_path());
        let config = if config_path.is_file() {
            Config::load(&config_path)?
        } else {
            let config = Config::default();
            config.validate()?;
            config
        };
        Ok(Self {
            data_dir,
            config,
            json: cli.json,
            now: SystemClock::new().wall_ns(),
        })
    }

    /// Open the database read-only.
    pub fn open_read(&self) -> Result<Store> {
        let path = self.data_dir.db_path();
        if !path.is_file() {
            return Err(Error::unavailable(
                "database",
                format!(
                    "{} does not exist; run `sarf init` and `sarf run` first",
                    path.display()
                ),
            ));
        }
        Store::open_read_only(&path)
    }

    /// Open the database for maintenance writes.
    pub fn open_write(&mut self) -> Result<Store> {
        self.data_dir.init(false)?;
        let mut store = Store::open(&self.data_dir.db_path())?;
        store.migrate()?;
        Ok(store)
    }

    /// Resolve a `--since` argument into a window ending now.
    pub fn window(&self, since: &str) -> Result<Window> {
        parse_window(since, self.now)
    }
}

/// Parse a duration/RFC3339 `since` value into `[since, now)`.
pub fn parse_window(text: &str, now: WallNs) -> Result<Window> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Window::new(now.saturating_sub(3_600_000_000_000), now));
    }
    if text.eq_ignore_ascii_case("all") {
        return Ok(Window::new(0, now));
    }
    if let Some(duration) = parse_duration_ns(text) {
        return Ok(Window::new(now.saturating_sub(duration), now));
    }
    if let Ok(stamp) = DateTime::parse_from_rfc3339(text) {
        return Ok(Window::new(stamp.timestamp_nanos_opt().unwrap_or(0), now));
    }
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, format) {
            if let Some(stamp) = local_stamp(naive) {
                return Ok(Window::new(stamp, now));
            }
        }
    }
    Err(Error::Config(format!(
        "invalid --since {text:?}: use 15m, 1h, 24h, 7d, all or RFC3339"
    )))
}

fn parse_duration_ns(text: &str) -> Option<i64> {
    let split = text
        .char_indices()
        .find(|(_, character)| !character.is_ascii_digit() && *character != '.')?;
    let (number, unit) = text.split_at(split.0);
    let value = number.parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let seconds = match unit {
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        "d" => value * 86_400.0,
        "w" => value * 604_800.0,
        _ => return None,
    };
    Some((seconds * 1e9) as i64)
}

fn local_stamp(naive: NaiveDateTime) -> Option<i64> {
    Local
        .from_local_datetime(&naive)
        .earliest()
        .and_then(|stamp| stamp.timestamp_nanos_opt())
}

/// Format a wall-clock value for a table.
pub fn fmt_time(wall_ns: i64) -> String {
    if wall_ns <= 0 {
        return "-".to_string();
    }
    let local = Local
        .timestamp_opt(wall_ns / 1_000_000_000, 0)
        .earliest()
        .map(|stamp| stamp.format("%Y-%m-%d %H:%M:%S").to_string());
    local.unwrap_or_else(|| format_wall_rfc3339(wall_ns))
}

/// Format bytes with IEC units.
pub fn fmt_bytes(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return "-".to_string();
    };
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Format a percentage, preserving unavailable values.
pub fn fmt_pct(value: Option<f64>) -> String {
    value
        .filter(|value| value.is_finite())
        .map_or_else(|| "-".to_string(), |value| format!("{value:.1}%"))
}

/// Format a duration between two wall clocks.
pub fn fmt_span(start: i64, end: Option<i64>, now: i64) -> String {
    let end = end.unwrap_or(now);
    let seconds = ((end.saturating_sub(start)) as f64 / 1e9).max(0.0);
    if seconds < 90.0 {
        format!("{seconds:.0}s")
    } else if seconds < 5400.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds < 172_800.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else {
        format!("{:.1}d", seconds / 86_400.0)
    }
}

/// Print a compact aligned table.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(no rows)");
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index < widths.len() {
                widths[index] = widths[index].max(cell.chars().count());
            }
        }
    }
    let render = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                let width = widths.get(index).copied().unwrap_or(cell.len());
                format!("{cell:<width$}")
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let header: Vec<String> = headers.iter().map(|header| (*header).to_string()).collect();
    println!("{}", render(&header));
    let rule: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
    println!("{}", rule.join("  "));
    for row in rows {
        println!("{}", render(row));
    }
}

/// Print one JSON document with a trailing newline.
pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| Error::Storage(format!("serialize output: {err}")))?;
    println!("{text}");
    Ok(())
}

/// Resolve or create an output path.
pub fn output_path(explicit: Option<&Path>, default: PathBuf) -> PathBuf {
    explicit.map_or(default, Path::to_path_buf)
}

/// Parse an RFC3339-ish timestamp for filters; `None` when absent.
pub fn parse_timestamp(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .and_then(|stamp| stamp.timestamp_nanos_opt())
        .or_else(|| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .ok()
                .and_then(|date| date.and_hms_opt(0, 0, 0))
                .and_then(local_stamp)
        })
}

/// Parse the CLI and run one command.
pub fn main() -> Result<i32> {
    let cli = Cli::parse();
    let mut context = Context::new(&cli)?;
    match &cli.command {
        Command::Init { force } => system::init(&mut context, *force),
        Command::Run(args) => system::run_daemon(&context, args),
        Command::Doctor => system::doctor(&context),
        Command::Status => system::status(&context),
        Command::Capabilities => system::capabilities(&context),
        Command::Gaps => system::gaps(&context),
        Command::Top { since, by, limit } => query::top(&context, since, *by, *limit),
        Command::Processes {
            since,
            filter,
            limit,
        } => query::processes(&context, since, filter.as_deref(), *limit),
        Command::Tree {
            since,
            process,
            service,
            limit,
        } => query::tree(
            &context,
            since,
            process.as_deref(),
            service.as_deref(),
            *limit,
        ),
        Command::Why {
            since,
            limit,
            metric,
        } => query::why(&context, since, *limit, metric.as_deref()),
        Command::Incidents { since, limit } => query::incidents(&context, since, *limit),
        Command::Show { incident_id } => query::show(&context, *incident_id),
        Command::Logs {
            source,
            since,
            grep,
            level,
            limit,
        } => query::logs(
            &context,
            source,
            since,
            grep.as_deref(),
            level.as_deref(),
            *limit,
        ),
        Command::Report {
            since,
            output,
            incident,
            process,
            service,
        } => export::report(
            &context,
            since,
            output.as_deref(),
            *incident,
            process.as_deref(),
            service.as_deref(),
        ),
        Command::Export {
            since,
            format,
            output,
        } => export::export(&context, since, *format, output.as_deref()),
        Command::Prune => system::prune(&mut context),
        Command::Benchmark {
            cycles,
            fixture_root,
        } => system::benchmark(&context, *cycles, fixture_root.as_deref()),
        Command::Tools { command } => export::tools(&context, command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        let now = 10_000_000_000_000;
        assert_eq!(
            parse_window("1h", now).expect("1h").since,
            now - 3_600_000_000_000
        );
        assert_eq!(
            parse_window("30m", now).expect("30m").since,
            now - 1_800_000_000_000
        );
        assert_eq!(parse_window("all", now).expect("all").since, 0);
        assert!(parse_window("nonsense", now).is_err());
    }

    #[test]
    fn bytes_are_compact_and_missing_stays_missing() {
        assert_eq!(fmt_bytes(None), "-");
        assert_eq!(fmt_bytes(Some(0)), "0 B");
        assert_eq!(fmt_bytes(Some(1536)), "1.5 KiB");
        assert_eq!(fmt_bytes(Some(2 * 1024 * 1024)), "2.0 MiB");
    }

    #[test]
    fn percentages_do_not_turn_none_into_zero() {
        assert_eq!(fmt_pct(None), "-");
        assert_eq!(fmt_pct(Some(f64::NAN)), "-");
        assert_eq!(fmt_pct(Some(12.34)), "12.3%");
    }

    #[test]
    fn timestamps_parse_rfc3339_and_dates() {
        assert!(parse_timestamp("2026-11-16T12:00:00Z").is_some());
        assert!(parse_timestamp("2026-11-16").is_some());
        assert!(parse_timestamp("not a time").is_none());
    }
}
