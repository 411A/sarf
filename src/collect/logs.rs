//! Bounded log ingestion (guide §9).
//!
//! Each configured source owns one ring buffer with line, byte and time caps. A file
//! follower handles rename rotation, truncation, partial lines and bounded reads. A
//! Docker source uses a bounded `docker logs` CLI fallback in v0.1 (documented in
//! `docs/DECISIONS.md`); the Engine logs API is the planned upgrade.
//!
//! One flooding source cannot starve another: every source reads at most
//! `read_bytes_per_cycle` bytes and processes at most [`MAX_LINES_PER_POLL`] lines per
//! cycle. Discarded lines are counted, never silently forgotten.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

use crate::config::{Config, LogSource, LogSourceKind};
use crate::enrich::run_bounded;
use crate::model::{Availability, LogRecord, LogStream, Severity};
use crate::time::{format_wall_rfc3339, Stamps};

/// Hard per-source line cap processed in one poll; the remainder is counted as
/// dropped and the read position advances so SARF catches up instead of replaying.
pub const MAX_LINES_PER_POLL: usize = 500;

/// Docker log CLI timeout.
const DOCKER_TIMEOUT: Duration = Duration::from_secs(5);

/// Effective bounded-log policy.
#[derive(Debug, Clone)]
pub struct LogPolicy {
    /// Ring line cap.
    pub ring_lines: usize,
    /// Ring age cap in nanoseconds.
    pub ring_ns: i64,
    /// Ring byte cap.
    pub ring_bytes: u64,
    /// Maximum stored bytes of one line.
    pub max_line_bytes: usize,
    /// Bytes read per source per cycle.
    pub read_bytes_per_cycle: usize,
    /// INFO persistence percentage.
    pub persist_info_sample_percent: u8,
    /// Persist WARN.
    pub persist_warnings: bool,
    /// Persist ERROR and above.
    pub persist_errors: bool,
    /// Always-store patterns, lowercased.
    pub patterns: Vec<String>,
}

impl LogPolicy {
    /// Derive a policy from the validated configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            ring_lines: config.logs.ring_lines,
            ring_ns: (config.logs.ring_minutes as i64).saturating_mul(60_000_000_000),
            ring_bytes: config.logs.ring_bytes_per_source,
            max_line_bytes: config.logs.max_line_bytes,
            read_bytes_per_cycle: config.logs.read_bytes_per_cycle,
            persist_info_sample_percent: config.logs.persist_info_sample_percent,
            persist_warnings: config.logs.persist_warnings,
            persist_errors: config.logs.persist_errors,
            patterns: config
                .logs
                .always_store_patterns
                .iter()
                .map(|pattern| pattern.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Whether a record should be persisted outside an incident evidence window.
    pub fn should_persist(&self, record: &LogRecord) -> bool {
        if record
            .level
            .is_some_and(|level| level >= Severity::Critical)
        {
            return true;
        }
        if self.persist_errors && record.level == Some(Severity::Error) {
            return true;
        }
        if self.persist_warnings && record.level == Some(Severity::Warn) {
            return true;
        }
        let lower = record.message.to_ascii_lowercase();
        if self
            .patterns
            .iter()
            .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
        {
            return true;
        }
        if record.level.unwrap_or(Severity::Info) <= Severity::Info
            && self.persist_info_sample_percent > 0
        {
            let percent = u64::from(self.persist_info_sample_percent.min(100));
            if percent >= 100 {
                return true;
            }
            let hash = fnv1a(record.source_id.as_bytes())
                ^ fnv1a(record.message.as_bytes())
                ^ record.wall_ns as u64;
            return hash % 100 < percent;
        }
        false
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug)]
struct RingEntry {
    record: LogRecord,
    ingested_wall_ns: i64,
}

/// One bounded per-source ring.
#[derive(Debug, Default)]
pub struct LogRing {
    entries: VecDeque<RingEntry>,
    bytes: u64,
    dropped: u64,
    truncated: u64,
}

impl LogRing {
    /// Add a record, evicting oldest entries beyond the line/byte/time caps.
    fn push(&mut self, record: LogRecord, ingested_wall_ns: i64, policy: &LogPolicy) -> u64 {
        self.bytes = self.bytes.saturating_add(entry_size(&record));
        if record.truncated {
            self.truncated = self.truncated.saturating_add(1);
        }
        self.entries.push_back(RingEntry {
            record,
            ingested_wall_ns,
        });
        let mut dropped = 0;
        loop {
            let over_lines = self.entries.len() > policy.ring_lines;
            let over_bytes = self.bytes > policy.ring_bytes;
            let over_time = self.entries.back().is_some_and(|back| {
                ingested_wall_ns.saturating_sub(back.ingested_wall_ns) > policy.ring_ns
            });
            if !(over_lines || over_bytes || over_time) {
                break;
            }
            let Some(entry) = self.entries.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(entry_size(&entry.record));
            dropped += 1;
        }
        self.dropped = self.dropped.saturating_add(dropped);
        dropped
    }

    /// Number of records currently retained.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Retained bytes (bounded estimate).
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Records dropped by the caps.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Records in the ring at or after `since_wall_ns`, oldest first.
    pub fn recent(&self, since_wall_ns: i64, limit: usize) -> Vec<LogRecord> {
        let mut records: Vec<LogRecord> = self
            .entries
            .iter()
            .filter(|entry| entry.record.wall_ns >= since_wall_ns)
            .rev()
            .take(limit)
            .map(|entry| entry.record.clone())
            .collect();
        records.reverse();
        records
    }

    /// All retained records, oldest first.
    pub fn all(&self) -> Vec<LogRecord> {
        self.entries
            .iter()
            .map(|entry| entry.record.clone())
            .collect()
    }
}

const fn entry_size(record: &LogRecord) -> u64 {
    (record.message.len() as u64)
        .saturating_add(record.source_id.len() as u64)
        .saturating_add(32)
}

/// One raw line before normalization.
#[derive(Debug, Clone)]
struct RawLine {
    text: String,
    truncated: bool,
}

#[derive(Debug, Default)]
struct PollBatch {
    lines: Vec<RawLine>,
    error: Option<String>,
    dropped: u64,
}

/// File follower state.
#[derive(Debug)]
struct FileFollower {
    path: PathBuf,
    file: Option<File>,
    identity: Option<u64>,
    position: u64,
    partial: Vec<u8>,
    initialized: bool,
    needs_restart: bool,
    /// Discard the first partial line when a tail read starts mid-line.
    skip_partial: bool,
}

impl FileFollower {
    const fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: None,
            identity: None,
            position: 0,
            partial: Vec::new(),
            initialized: false,
            needs_restart: false,
            skip_partial: false,
        }
    }

    fn poll(&mut self, policy: &LogPolicy) -> PollBatch {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) => {
                self.file = None;
                self.identity = None;
                self.needs_restart = self.initialized;
                self.initialized = false;
                return PollBatch {
                    error: Some(format!("{}: {err}", self.path.display())),
                    ..PollBatch::default()
                };
            }
        };
        let identity = file_identity(&metadata, &self.path);
        let rotated = self.identity.is_some_and(|known| known != identity);
        let truncated = self.initialized && metadata.len() < self.position;
        if rotated || truncated || self.file.is_none() {
            self.file = match File::open(&self.path) {
                Ok(file) => Some(file),
                Err(err) => {
                    return PollBatch {
                        error: Some(format!("{}: {err}", self.path.display())),
                        ..PollBatch::default()
                    };
                }
            };
            self.identity = Some(identity);
            self.partial.clear();
            self.position = if self.needs_restart || (self.initialized && (rotated || truncated)) {
                0
            } else {
                // First open reads a bounded recent tail (ADR-010): enough history to
                // explain a live incident without replaying an entire archive.
                metadata
                    .len()
                    .saturating_sub(policy.read_bytes_per_cycle as u64)
            };
            self.skip_partial = self.position > 0;
            self.needs_restart = false;
            self.initialized = true;
        }
        let Some(file) = self.file.as_mut() else {
            return PollBatch::default();
        };
        if metadata.len() < self.position {
            self.position = 0;
        }
        if file.seek(SeekFrom::Start(self.position)).is_err() {
            return PollBatch {
                error: Some(format!("{}: seek failed", self.path.display())),
                ..PollBatch::default()
            };
        }
        let remaining = (metadata.len().saturating_sub(self.position) as usize)
            .min(policy.read_bytes_per_cycle);
        if remaining == 0 {
            return PollBatch::default();
        }
        let mut buffer = vec![0_u8; remaining];
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(err) => {
                return PollBatch {
                    error: Some(format!("{}: {err}", self.path.display())),
                    ..PollBatch::default()
                };
            }
        };
        buffer.truncate(read);
        self.position = self.position.saturating_add(read as u64);
        let mut batch = PollBatch::default();
        let mut start = 0;
        if self.skip_partial {
            if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
                start = index + 1;
                self.skip_partial = false;
            } else {
                // The whole chunk is the middle of a very long line. Keep skipping
                // on the next poll rather than storing a fragment.
                self.partial.clear();
                return batch;
            }
        }
        for (index, byte) in buffer.iter().enumerate().skip(start) {
            if *byte == b'\n' {
                let mut line = std::mem::take(&mut self.partial);
                line.extend_from_slice(&buffer[start..index]);
                let text = String::from_utf8_lossy(&line)
                    .trim_end_matches('\r')
                    .to_string();
                batch.lines.push(bound_line(&text, policy));
                start = index + 1;
            }
        }
        if start < buffer.len() {
            self.partial.extend_from_slice(&buffer[start..]);
            if self.partial.len() > policy.max_line_bytes {
                let text = String::from_utf8_lossy(&self.partial).into_owned();
                self.partial.clear();
                batch.lines.push(bound_line(&text, policy));
            }
        }
        if batch.lines.len() > MAX_LINES_PER_POLL {
            batch.dropped = (batch.lines.len() - MAX_LINES_PER_POLL) as u64;
            batch.lines.truncate(MAX_LINES_PER_POLL);
        }
        batch
    }
}

fn bound_line(text: &str, policy: &LogPolicy) -> RawLine {
    let (text, truncated) = crate::store::truncate_utf8(text, policy.max_line_bytes);
    RawLine { text, truncated }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata, _path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev().wrapping_mul(1_000_003) ^ metadata.ino()
}

#[cfg(windows)]
fn file_identity(metadata: &std::fs::Metadata, path: &std::path::Path) -> u64 {
    use std::os::windows::fs::MetadataExt;
    // Creation time is stable across appends (unlike last_write_time) and changes on
    // rotation/recreation. Windows is only used for fixture tests; Linux uses dev+ino.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^ metadata.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn file_identity(metadata: &std::fs::Metadata, _path: &std::path::Path) -> u64 {
    metadata.len()
}

/// Docker CLI follower state.
#[derive(Debug)]
struct DockerFollower {
    container: String,
    last_wall_ns: Option<i64>,
}

impl DockerFollower {
    const fn new(container: String) -> Self {
        Self {
            container,
            last_wall_ns: None,
        }
    }

    fn poll(&mut self) -> PollBatch {
        let mut args = vec![
            "logs".to_string(),
            "--timestamps".to_string(),
            "--tail".to_string(),
            "200".to_string(),
        ];
        if let Some(since) = self.last_wall_ns {
            args.push("--since".to_string());
            args.push(format_wall_rfc3339(since));
        }
        args.push(self.container.clone());
        let output = match run_bounded("docker", &args, DOCKER_TIMEOUT, 1024 * 1024) {
            Ok(output) => output,
            Err(err) => {
                return PollBatch {
                    error: Some(err.to_string()),
                    ..PollBatch::default()
                };
            }
        };
        if !output.success {
            return PollBatch {
                error: Some(format!(
                    "docker logs exited with {:?}{}",
                    output.status,
                    if output.timed_out { " (timeout)" } else { "" }
                )),
                ..PollBatch::default()
            };
        }
        let mut batch = PollBatch::default();
        for line in output.stdout.lines() {
            let (stamp, text) = split_docker_timestamp(line);
            if let Some(stamp) = stamp {
                self.last_wall_ns = Some(self.last_wall_ns.map_or(stamp, |known| known.max(stamp)));
            }
            batch.lines.push(RawLine {
                text: text.to_string(),
                truncated: output.truncated,
            });
        }
        if batch.lines.len() > MAX_LINES_PER_POLL {
            batch.dropped = (batch.lines.len() - MAX_LINES_PER_POLL) as u64;
            batch.lines.truncate(MAX_LINES_PER_POLL);
        }
        batch
    }
}

fn split_docker_timestamp(line: &str) -> (Option<i64>, &str) {
    let Some((stamp, rest)) = line.split_once(' ') else {
        return (None, line);
    };
    (parse_rfc3339(stamp), rest)
}

#[derive(Debug)]
enum Tail {
    File(FileFollower),
    Docker(DockerFollower),
}

#[derive(Debug)]
struct ManagedSource {
    id: String,
    kind: String,
    target: String,
    entity_hint: Option<String>,
    max_lines: usize,
    max_bytes: u64,
    tail: Tail,
    ring: LogRing,
    received: u64,
    dropped: u64,
    truncated: u64,
    last_error: Option<String>,
    availability: Availability,
}

/// Per-source health snapshot for collector health and `sarf doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealth {
    /// Source id.
    pub source_id: String,
    /// `file` or `docker`.
    pub kind: String,
    /// Bounded target label.
    pub target: String,
    /// Availability.
    pub availability: Availability,
    /// Last error.
    pub last_error: Option<String>,
    /// Lines read.
    pub received: u64,
    /// Lines dropped by ring/line caps.
    pub dropped: u64,
    /// Truncated lines.
    pub truncated: u64,
    /// Ring occupancy.
    pub ring_lines: usize,
    /// Ring bytes.
    pub ring_bytes: u64,
}

/// One log poll result.
#[derive(Debug, Default)]
pub struct LogPulse {
    /// Persistence-policy-selected records.
    pub records: Vec<LogRecord>,
    /// Lines read across all sources.
    pub received: u64,
    /// Lines dropped by bounds.
    pub dropped: u64,
    /// Truncated lines.
    pub truncated: u64,
    /// Sources that flooded during this poll.
    pub floods: Vec<String>,
    /// Source errors (id, bounded message).
    pub errors: Vec<(String, String)>,
}

/// Bounded log manager.
#[derive(Debug)]
pub struct LogManager {
    sources: Vec<ManagedSource>,
    policy: LogPolicy,
}

impl LogManager {
    /// Create a manager from configured sources.
    pub fn new(config: &Config, policy: LogPolicy) -> Self {
        let sources = config
            .logs
            .sources
            .iter()
            .map(|source| managed_source(source, &policy))
            .collect();
        Self { sources, policy }
    }

    /// Poll every file source once.
    pub fn poll(&mut self, stamps: &Stamps) -> LogPulse {
        let mut pulse = LogPulse::default();
        let policy = &self.policy;
        for source in &mut self.sources {
            if matches!(source.tail, Tail::Docker(_)) {
                continue;
            }
            Self::poll_source(policy, source, stamps, &mut pulse);
        }
        pulse
    }

    /// Poll Docker CLI sources; call on the slower discovery cadence.
    pub fn poll_docker(&mut self, stamps: &Stamps) -> LogPulse {
        let mut pulse = LogPulse::default();
        let policy = &self.policy;
        for source in &mut self.sources {
            if !matches!(source.tail, Tail::Docker(_)) {
                continue;
            }
            Self::poll_source(policy, source, stamps, &mut pulse);
        }
        pulse
    }

    fn poll_source(
        policy: &LogPolicy,
        source: &mut ManagedSource,
        stamps: &Stamps,
        pulse: &mut LogPulse,
    ) {
        let batch = match &mut source.tail {
            Tail::File(follower) => follower.poll(policy),
            Tail::Docker(follower) => follower.poll(),
        };
        if batch.dropped > 0 {
            source.dropped = source.dropped.saturating_add(batch.dropped);
            pulse.dropped = pulse.dropped.saturating_add(batch.dropped);
            pulse.floods.push(source.id.clone());
        }
        if let Some(error) = batch.error {
            let (error, _) = crate::store::truncate_utf8(&error, 512);
            source.last_error = Some(error.clone());
            source.availability = Availability::Partial;
            pulse.errors.push((source.id.clone(), error));
            return;
        }
        source.last_error = None;
        source.availability = Availability::Available;
        let mut source_policy = policy.clone();
        source_policy.ring_lines = source.max_lines;
        source_policy.ring_bytes = source.max_bytes;
        for raw in batch.lines {
            source.received = source.received.saturating_add(1);
            pulse.received = pulse.received.saturating_add(1);
            let wall_ns = parse_log_timestamp(&raw.text).unwrap_or(stamps.wall);
            let level = detect_level(&raw.text);
            let (message, redacted) = redact(&raw.text);
            let (message, truncated) = crate::store::truncate_utf8(&message, policy.max_line_bytes);
            let record = LogRecord {
                wall_ns,
                mono_ns: Some(stamps.mono),
                source_id: source.id.clone(),
                entity_id: None,
                stream: match source.kind.as_str() {
                    "docker" => LogStream::Stdout,
                    _ => LogStream::File,
                },
                level: Some(level),
                message,
                truncated: raw.truncated || truncated,
                incident_id: None,
                redacted,
            };
            if record.truncated {
                source.truncated = source.truncated.saturating_add(1);
                pulse.truncated = pulse.truncated.saturating_add(1);
            }
            let dropped = source
                .ring
                .push(record.clone(), stamps.wall, &source_policy);
            if dropped > 0 {
                source.dropped = source.dropped.saturating_add(dropped);
                pulse.dropped = pulse.dropped.saturating_add(dropped);
                if !pulse.floods.contains(&source.id) {
                    pulse.floods.push(source.id.clone());
                }
            }
            if policy.should_persist(&record) {
                pulse.records.push(record);
            }
        }
    }

    /// Recent records across all sources for an incident evidence window.
    pub fn recent(&self, since_wall_ns: i64, limit: usize) -> Vec<LogRecord> {
        let mut records: Vec<LogRecord> = self
            .sources
            .iter()
            .flat_map(|source| source.ring.recent(since_wall_ns, limit))
            .collect();
        records.sort_by_key(|record| record.wall_ns);
        if records.len() > limit {
            records = records.split_off(records.len() - limit);
        }
        records
    }

    /// Recent records for one source.
    pub fn source_recent(
        &self,
        source_id: &str,
        since_wall_ns: i64,
        limit: usize,
    ) -> Vec<LogRecord> {
        self.sources
            .iter()
            .find(|source| source.id == source_id)
            .map(|source| source.ring.recent(since_wall_ns, limit))
            .unwrap_or_default()
    }

    /// Per-source health.
    pub fn health(&self) -> Vec<SourceHealth> {
        self.sources
            .iter()
            .map(|source| SourceHealth {
                source_id: source.id.clone(),
                kind: source.kind.clone(),
                target: source.target.clone(),
                availability: source.availability,
                last_error: source.last_error.clone(),
                received: source.received,
                dropped: source.dropped,
                truncated: source.truncated,
                ring_lines: source.ring.len(),
                ring_bytes: source.ring.bytes(),
            })
            .collect()
    }

    /// Configured source descriptors for report transparency.
    pub fn descriptors(&self) -> Vec<(String, String, String, Option<String>, usize, u64)> {
        self.sources
            .iter()
            .map(|source| {
                (
                    source.id.clone(),
                    source.kind.clone(),
                    source.target.clone(),
                    source.entity_hint.clone(),
                    source.max_lines,
                    source.max_bytes,
                )
            })
            .collect()
    }

    /// Number of configured sources.
    pub const fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether no sources are configured.
    pub const fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

fn managed_source(source: &LogSource, policy: &LogPolicy) -> ManagedSource {
    let (tail, kind, target) = match source.kind {
        LogSourceKind::File => {
            let path = source.path.clone().unwrap_or_default();
            (
                Tail::File(FileFollower::new(path)),
                "file".to_string(),
                source.target(),
            )
        }
        LogSourceKind::Docker => (
            Tail::Docker(DockerFollower::new(
                source.container.clone().unwrap_or_default(),
            )),
            "docker".to_string(),
            source.target(),
        ),
    };
    ManagedSource {
        id: source.id.clone(),
        kind,
        target,
        entity_hint: source.entity_hint.clone(),
        max_lines: source.max_lines.unwrap_or(policy.ring_lines),
        max_bytes: source.max_bytes.unwrap_or(policy.ring_bytes),
        tail,
        ring: LogRing::default(),
        received: 0,
        dropped: 0,
        truncated: 0,
        last_error: None,
        availability: Availability::Unknown,
    }
}

/// Best-effort severity detection from common log formats.
///
/// Token matching covers `ERROR`, `[error]`, `level=warn`, cloudflared `ERR`/`WRN`
/// and syslog-style `<3>`. It is intentionally deterministic and regex-free.
pub fn detect_level(line: &str) -> Severity {
    let prefix = prefix_chars(line, 200);
    let mut best = Severity::Info;
    for token in prefix
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| !token.is_empty())
    {
        if let Some(level) = Severity::parse(token) {
            best = best.max(level);
        }
    }
    let lower = prefix.to_ascii_lowercase();
    if lower.contains("panic") || lower.contains("traceback") || lower.contains("oomkilled") {
        best = best.max(Severity::Critical);
    }
    best
}

fn prefix_chars(line: &str, max: usize) -> &str {
    match line.char_indices().nth(max) {
        Some((index, _)) => &line[..index],
        None => line,
    }
}

/// Redact common credential shapes before a line is retained or persisted.
///
/// This is a safety net, not a substitute for not logging secrets. It handles
/// `key=value`, `key: value`, `Bearer`/`Basic` credentials and URL userinfo.
pub fn redact(line: &str) -> (String, bool) {
    let (assignments, redacted_assignments) = redact_assignments(line);
    let (auth, redacted_auth) = redact_auth_schemes(&assignments);
    let redacted_url = redact_url_userinfo(&auth);
    let redacted = redacted_assignments || redacted_auth || redacted_url != auth;
    (redacted_url, redacted)
}

fn redact_assignments(line: &str) -> (String, bool) {
    const KEYS: [&str; 8] = [
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "cookie",
        "access_key",
    ];
    let lower = line.to_ascii_lowercase();
    let mut output = String::with_capacity(line.len());
    let mut cursor = 0;
    let mut redacted = false;
    while let Some((position, key)) = next_secret_key(&lower, cursor, &KEYS) {
        let after_key = position + key.len();
        let mut value_start = after_key;
        while value_start < line.len()
            && matches!(line.as_bytes()[value_start], b' ' | b'\t' | b'=' | b':')
        {
            value_start += 1;
        }
        let mut content_start = value_start;
        let mut value_end = value_start;
        if value_start < line.len() && matches!(line.as_bytes()[value_start], b'"' | b'\'') {
            let quote = line.as_bytes()[value_start];
            content_start = value_start + 1;
            value_end = content_start;
            while value_end < line.len() && line.as_bytes()[value_end] != quote {
                value_end += 1;
            }
        } else {
            while value_end < line.len()
                && !matches!(
                    line.as_bytes()[value_end],
                    b' ' | b'\t' | b',' | b';' | b'&' | b'\n'
                )
            {
                value_end += 1;
            }
        }
        if value_end <= content_start {
            cursor = after_key;
            continue;
        }
        output.push_str(&line[cursor..content_start]);
        output.push_str("[REDACTED]");
        cursor = value_end;
        redacted = true;
    }
    output.push_str(&line[cursor..]);
    (output, redacted)
}

fn next_secret_key<'a>(lower: &str, from: usize, keys: &'a [&'a str]) -> Option<(usize, &'a str)> {
    let mut best: Option<(usize, &str)> = None;
    for key in keys {
        let mut search = from;
        while let Some(relative) = lower[search..].find(key) {
            let position = search + relative;
            let after = position + key.len();
            let boundary_before =
                position == 0 || !lower.as_bytes()[position - 1].is_ascii_alphanumeric();
            let boundary_after = after >= lower.len()
                || matches!(
                    lower.as_bytes()[after],
                    b' ' | b'\t' | b'=' | b':' | b'"' | b'\'' | b'&'
                );
            if boundary_before && boundary_after {
                if best.is_none_or(|(best_position, _)| position < best_position) {
                    best = Some((position, key));
                }
                break;
            }
            search = after;
        }
    }
    best
}

fn redact_auth_schemes(line: &str) -> (String, bool) {
    let lower = line.to_ascii_lowercase();
    let mut output = String::with_capacity(line.len());
    let mut cursor = 0;
    let mut redacted = false;
    loop {
        let bearer = lower[cursor..].find("bearer ").map(|at| (cursor + at, 7));
        let basic = lower[cursor..].find("basic ").map(|at| (cursor + at, 6));
        let next = match (bearer, basic) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let Some((position, scheme_len)) = next else {
            break;
        };
        let start = position + scheme_len;
        let mut end = start;
        while end < line.len() && !line.as_bytes()[end].is_ascii_whitespace() {
            end += 1;
        }
        if end <= start {
            cursor = start;
            continue;
        }
        output.push_str(&line[cursor..start]);
        output.push_str("[REDACTED]");
        cursor = end;
        redacted = true;
    }
    output.push_str(&line[cursor..]);
    (output, redacted)
}

fn redact_url_userinfo(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(scheme) = rest.find("://") {
        let after = scheme + 3;
        let Some(relative_at) = rest[after..].find('@') else {
            break;
        };
        let at = after + relative_at;
        if rest[after..at].contains('/') {
            output.push_str(&rest[..after]);
            rest = &rest[after..];
            continue;
        }
        output.push_str(&rest[..after]);
        output.push_str("[REDACTED]@");
        rest = &rest[at + 1..];
    }
    output.push_str(rest);
    output
}

/// Parse common log timestamp prefixes; returns epoch nanoseconds.
pub fn parse_log_timestamp(line: &str) -> Option<i64> {
    let prefix = prefix_chars(line, 96);
    let first = prefix.split_whitespace().next()?;
    if let Some(ns) = parse_rfc3339(first) {
        return Some(ns);
    }
    // nginx error: 2026/11/16 12:34:56 [error]
    if first.len() == 10 && first.as_bytes().get(4) == Some(&b'/') {
        if let Some(rest) = prefix.get(11..19) {
            let combined = format!("{first} {rest}");
            if let Ok(naive) = NaiveDateTime::parse_from_str(&combined, "%Y/%m/%d %H:%M:%S") {
                return local_ns(naive);
            }
        }
    }
    // ISO local: 2026-11-16 12:34:56
    if first.len() == 10 && first.as_bytes().get(4) == Some(&b'-') {
        if let Some(rest) = prefix.get(11..19) {
            let combined = format!("{first} {rest}");
            if let Ok(naive) = NaiveDateTime::parse_from_str(&combined, "%Y-%m-%d %H:%M:%S") {
                return local_ns(naive);
            }
        }
    }
    // nginx access: [16/Nov/2026:12:34:56 +0000]
    if let Some(start) = prefix.find('[') {
        if let Some(end) = prefix[start..].find(']') {
            let inner = &prefix[start + 1..start + end];
            if let Ok(stamp) = DateTime::parse_from_str(inner, "%d/%b/%Y:%H:%M:%S %z") {
                return stamp.timestamp_nanos_opt();
            }
        }
    }
    // syslog: Nov 16 12:34:56 (year assumed current)
    if prefix.len() > 15 && prefix.is_char_boundary(15) {
        let year = Local::now().format("%Y").to_string();
        let candidate = format!("{} {}", year, &prefix[..15]);
        if let Ok(naive) = NaiveDateTime::parse_from_str(&candidate, "%Y %b %e %H:%M:%S") {
            return local_ns(naive);
        }
    }
    None
}

fn parse_rfc3339(text: &str) -> Option<i64> {
    if !text.contains('T') {
        return None;
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .and_then(|stamp| stamp.timestamp_nanos_opt())
}

fn local_ns(naive: NaiveDateTime) -> Option<i64> {
    Local
        .from_local_datetime(&naive)
        .earliest()
        .and_then(|stamp| stamp.timestamp_nanos_opt())
}

/// Map tool/entity hints from configured sources to a compact report label.
pub fn hint_map(manager: &LogManager) -> HashMap<String, String> {
    manager
        .sources
        .iter()
        .filter_map(|source| {
            source
                .entity_hint
                .as_ref()
                .map(|hint| (source.id.clone(), hint.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::time::{ClockDomain, Stamps};
    use std::io::Write;
    use std::path::Path;

    fn stamps(wall: i64) -> Stamps {
        Stamps::new(wall, wall, "boot-logs", ClockDomain::Simulated)
    }

    fn policy() -> LogPolicy {
        LogPolicy::from_config(&Config::default())
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, content).expect("write");
    }

    fn append(path: &Path, content: &[u8]) {
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open")
            .write_all(content)
            .expect("append");
    }

    #[test]
    fn time_ring_evicts_old_records_and_reports_drops() {
        let policy = LogPolicy {
            ring_lines: 2,
            ring_ns: i64::MAX,
            ring_bytes: u64::MAX,
            max_line_bytes: 1024,
            read_bytes_per_cycle: 4096,
            persist_info_sample_percent: 0,
            persist_warnings: true,
            persist_errors: true,
            patterns: Vec::new(),
        };
        let mut ring = LogRing::default();
        for index in 0..5 {
            let record = LogRecord {
                wall_ns: index,
                mono_ns: None,
                source_id: "s".into(),
                entity_id: None,
                stream: LogStream::File,
                level: Some(Severity::Info),
                message: format!("line {index}"),
                truncated: false,
                incident_id: None,
                redacted: false,
            };
            ring.push(record, index, &policy);
        }
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.dropped(), 3);
        let recent = ring.recent(0, 10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[1].message, "line 4");
    }

    #[test]
    fn severity_detection_covers_common_formats() {
        assert_eq!(
            detect_level("2026/11/16 [error] upstream failed"),
            Severity::Error
        );
        assert_eq!(detect_level("level=warn slow request"), Severity::Warn);
        assert_eq!(
            detect_level("PANIC: index out of bounds"),
            Severity::Critical
        );
        assert_eq!(detect_level("INF starting cloudflared"), Severity::Info);
        assert_eq!(detect_level("just a normal line"), Severity::Info);
    }

    #[test]
    fn redaction_covers_assignments_bearer_and_url_userinfo() {
        let (text, redacted) = redact("password=hunter2 token: abc Authorization: Bearer xyz");
        assert!(redacted);
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("abc"));
        assert!(!text.contains("xyz"));
        assert_eq!(text.matches("[REDACTED]").count(), 3);
        let (url, redacted) = redact("proxy https://user:pass@example.invalid/path");
        assert!(redacted);
        assert!(!url.contains("user:pass"));
        assert!(url.contains("https://[REDACTED]@example.invalid/path"));
    }

    #[test]
    fn redaction_leaves_ordinary_lines_unchanged() {
        let (text, redacted) = redact("GET /health HTTP/1.1 200 3ms");
        assert!(!redacted);
        assert_eq!(text, "GET /health HTTP/1.1 200 3ms");
    }

    #[test]
    fn timestamps_cover_rfc3339_nginx_and_iso() {
        assert!(parse_log_timestamp("2026-11-16T12:34:56Z hello").is_some());
        assert!(parse_log_timestamp("2026/11/16 12:34:56 [error] x").is_some());
        assert!(parse_log_timestamp("2026-11-16 12:34:56 info").is_some());
        assert!(parse_log_timestamp(
            r#"1.2.3.4 - - [16/Nov/2026:12:34:56 +0000] "GET / HTTP/1.1" 200"#
        )
        .is_some());
        assert!(parse_log_timestamp("no timestamp here").is_none());
    }

    #[test]
    fn policy_persists_errors_patterns_and_samples_info() {
        let base = LogRecord {
            wall_ns: 1,
            mono_ns: None,
            source_id: "s".into(),
            entity_id: None,
            stream: LogStream::File,
            level: Some(Severity::Info),
            message: "hello".into(),
            truncated: false,
            incident_id: None,
            redacted: false,
        };
        let mut policy = policy();
        policy.persist_info_sample_percent = 0;
        assert!(!policy.should_persist(&base));
        let error = LogRecord {
            level: Some(Severity::Error),
            message: "boom".into(),
            ..base.clone()
        };
        assert!(policy.should_persist(&error));
        let pattern = LogRecord {
            message: "ConnectionRefused by upstream".into(),
            ..base.clone()
        };
        assert!(policy.should_persist(&pattern));
        policy.persist_info_sample_percent = 100;
        assert!(policy.should_persist(&base));
    }

    #[test]
    fn file_follower_handles_append_rotation_and_truncation() {
        let dir = std::env::temp_dir().join(format!("sarf-logs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("app.log");
        write_file(&path, "old line\n");
        let mut follower = FileFollower::new(path.clone());
        let policy = LogPolicy {
            read_bytes_per_cycle: 4096,
            ..policy()
        };
        // First poll reads a bounded recent tail, so the existing line is observed.
        let first = follower.poll(&policy);
        assert_eq!(first.lines.len(), 1, "lines: {:?}", first.lines);
        assert_eq!(first.lines[0].text, "old line");
        assert!(first.error.is_none());
        append(&path, b"first new\nsecond partial");
        let second = follower.poll(&policy);
        assert_eq!(second.lines.len(), 1, "{:?}", second.lines);
        assert_eq!(second.lines[0].text, "first new");
        append(&path, b" continues\n");
        let third = follower.poll(&policy);
        assert_eq!(third.lines.len(), 1, "{:?}", third.lines);
        assert_eq!(third.lines[0].text, "second partial continues");
        std::fs::write(&path, "after truncate\n").expect("truncate");
        let fourth = follower.poll(&policy);
        assert_eq!(fourth.lines.len(), 1);
        assert_eq!(fourth.lines[0].text, "after truncate");
        std::fs::rename(&path, dir.join("app.log.1")).expect("rename");
        write_file(&path, "after rotate\n");
        let fifth = follower.poll(&policy);
        assert_eq!(fifth.lines.len(), 1);
        assert_eq!(fifth.lines[0].text, "after rotate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_follower_bounds_a_partial_line() {
        let dir = std::env::temp_dir().join(format!("sarf-logs-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("app.log");
        write_file(&path, "");
        let mut follower = FileFollower::new(path.clone());
        let policy = LogPolicy {
            max_line_bytes: 32,
            read_bytes_per_cycle: 4096,
            ..policy()
        };
        follower.poll(&policy);
        append(&path, &[b'x'; 128]);
        let batch = follower.poll(&policy);
        assert_eq!(batch.lines.len(), 1);
        assert!(batch.lines[0].truncated);
        assert!(batch.lines[0].text.len() <= 35);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manager_polls_configured_file_and_keeps_ring() {
        let dir = std::env::temp_dir().join(format!("sarf-logs-manager-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nginx-error.log");
        write_file(&path, "");
        let mut config = Config::default();
        config.logs.sources = vec![LogSource {
            id: "nginx-error".into(),
            kind: LogSourceKind::File,
            path: Some(path.clone()),
            container: None,
            entity_hint: Some("nginx".into()),
            max_lines: None,
            max_bytes: None,
        }];
        let mut manager = LogManager::new(&config, policy());
        manager.poll(&stamps(1));
        append(&path, b"2026/11/16 12:00:00 [error] upstream timed out\n");
        let pulse = manager.poll(&stamps(2));
        assert_eq!(pulse.received, 1);
        assert_eq!(pulse.records.len(), 1, "errors are persisted");
        assert_eq!(pulse.records[0].level, Some(Severity::Error));
        assert_eq!(manager.health()[0].ring_lines, 1);
        assert_eq!(manager.recent(0, 10).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
