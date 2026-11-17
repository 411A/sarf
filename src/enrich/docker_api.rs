//! Bounded Docker Engine API client over the local Unix socket.
//!
//! Why this shape:
//! * container CPU/memory/I/O accounting stays on cgroup v2 + `/proc`, avoiding
//!   `docker stats` and the Stats API entirely;
//! * one inventory request plus one inspect per container at the discovery cadence
//!   provides names, labels, Compose identity, health, restart policy, log driver and
//!   log path without reading daemon-managed files;
//! * event polling uses a bounded `since`/`until` window so no permanent stream or
//!   extra thread is required;
//! * logs use the Engine API with `tail`/`since`, bounded response bytes, Docker's
//!   8-byte multiplex framing and timestamp parsing. `json-file`/`local` drivers work;
//!   `none`/remote-only drivers are reported as unavailable per source.
//!
//! The client never reads `/var/lib/docker` directly and never calls `docker stats`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::DateTime;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::model::LogStream;
use crate::time::format_wall_rfc3339;

use super::docker::{ContainerInfo, DockerDiscovery, MAX_CONTAINERS};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_INSPECT_BYTES: usize = 1024 * 1024;
const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOG_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap for API-discovered containers retained in one pass.
pub const API_MAX_CONTAINERS: usize = 256;

/// One parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

/// A connected Engine API client.
#[derive(Debug, Clone)]
pub struct DockerApi {
    socket: PathBuf,
    prefix: String,
    timeout: Duration,
    max_containers: usize,
    server_version: Option<String>,
    api_version: Option<String>,
}

impl DockerApi {
    /// Connect to the default socket (`DOCKER_HOST=unix://...`, rootful or rootless).
    pub fn connect_default() -> Result<Self> {
        let socket = std::env::var("DOCKER_HOST")
            .ok()
            .and_then(|value| value.strip_prefix("unix://").map(PathBuf::from))
            .or_else(|| {
                let root = PathBuf::from("/var/run/docker.sock");
                if root.exists() {
                    return Some(root);
                }
                std::env::var_os("XDG_RUNTIME_DIR")
                    .map(PathBuf::from)
                    .map(|dir| dir.join("docker.sock"))
                    .filter(|path| path.exists())
            })
            .ok_or_else(|| {
                Error::unavailable(
                    "Docker Engine API",
                    "no Unix socket found (set DOCKER_HOST)",
                )
            })?;
        Self::with_socket(&socket)
    }

    /// Connect to an explicit socket and negotiate the API version.
    pub fn with_socket(socket: &Path) -> Result<Self> {
        if !socket.exists() {
            return Err(Error::unavailable(
                "Docker Engine API",
                format!("socket {} does not exist", socket.display()),
            ));
        }
        let mut api = Self {
            socket: socket.to_path_buf(),
            prefix: String::new(),
            timeout: DEFAULT_TIMEOUT,
            max_containers: API_MAX_CONTAINERS,
            server_version: None,
            api_version: None,
        };
        let version = api.get_json("/version", 256 * 1024)?;
        api.server_version = version
            .get("Version")
            .and_then(Value::as_str)
            .map(str::to_string);
        let api_version = std::env::var("DOCKER_API_VERSION")
            .ok()
            .filter(|value| valid_version(value))
            .or_else(|| {
                version
                    .get("ApiVersion")
                    .and_then(Value::as_str)
                    .filter(|value| valid_version(value))
                    .map(str::to_string)
            });
        if let Some(api_version) = api_version {
            api.prefix = format!("/v{api_version}");
            api.api_version = Some(api_version);
        }
        Ok(api)
    }

    /// Socket path in use.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Negotiated API prefix (`/v1.56`) or empty when unversioned.
    pub fn api_prefix(&self) -> &str {
        &self.prefix
    }

    /// Docker server version, when reported.
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// Negotiated API version, when reported.
    pub fn api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }

    /// Set the socket read/write timeout (tests and constrained hosts).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout.max(Duration::from_millis(50));
    }

    /// Discover containers and inspect each one.
    pub fn discover(&self) -> Result<DockerDiscovery> {
        let path = format!("{}/containers/json?all=1", self.prefix);
        let response = self.get(&path, MAX_LIST_BYTES)?;
        let values: Vec<Value> = serde_json::from_slice(&response.body)
            .map_err(|err| Error::parse("docker containers", err.to_string()))?;
        let total = values.len();
        let mut containers = Vec::new();
        let mut inspect_errors = 0_u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        for value in values
            .into_iter()
            .take(self.max_containers.min(MAX_CONTAINERS))
        {
            if std::time::Instant::now() >= deadline {
                inspect_errors = inspect_errors.saturating_add(1);
                break;
            }
            let Some(mut container) = parse_summary(&value) else {
                continue;
            };
            let inspect_path = format!("{}/containers/{}/json", self.prefix, container.id);
            match self.get_json(&inspect_path, MAX_INSPECT_BYTES) {
                Ok(inspect) => apply_inspect(&mut container, &inspect),
                Err(_) => inspect_errors = inspect_errors.saturating_add(1),
            }
            containers.push(container);
        }
        containers.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(DockerDiscovery {
            available: true,
            containers,
            error: (inspect_errors > 0)
                .then(|| format!("{inspect_errors} container inspect request(s) failed")),
            truncated: response.truncated || total > self.max_containers,
        })
    }

    /// Fetch container events in a bounded time window.
    pub fn events(&self, since_ns: Option<i64>, until_ns: i64) -> Result<Vec<DockerEvent>> {
        let filter = url_encode(r#"{"type":["container"]}"#);
        let mut path = format!("{}/events?filters={filter}", self.prefix);
        if let Some(since) = since_ns.filter(|value| *value > 0) {
            // Docker's events endpoint expects Unix seconds for this parameter; using
            // RFC3339 with a fractional part is rejected by some daemon versions.
            path.push_str("&since=");
            path.push_str(&(since / 1_000_000_000).saturating_sub(1).to_string());
        }
        path.push_str("&until=");
        path.push_str(&(until_ns / 1_000_000_000).saturating_add(1).to_string());
        let response = self.get(&path, MAX_EVENT_BYTES)?;
        Ok(parse_events(&response.body))
    }

    /// Read logs since a cursor with bounded bytes and Docker's timestamp framing.
    pub fn logs(
        &self,
        id: &str,
        since_ns: Option<i64>,
        tail: usize,
        max_bytes: usize,
        tty: bool,
    ) -> Result<DockerLogBatch> {
        let tail_value = if since_ns.is_some_and(|value| value > 0) {
            // With a cursor, fetch every line since it (bounded by max_bytes) instead
            // of silently discarding older lines behind a fixed tail.
            "all".to_string()
        } else {
            tail.clamp(1, 2000).to_string()
        };
        let mut path = format!(
            "{}/containers/{id}/logs?stdout=1&stderr=1&timestamps=1&tail={tail_value}",
            self.prefix
        );
        if let Some(since) = since_ns.filter(|value| *value > 0) {
            path.push_str("&since=");
            path.push_str(&url_encode(&format_wall_rfc3339(since)));
        }
        let response = self.get(&path, max_bytes)?;
        Ok(parse_logs(&response.body, tty, response.truncated))
    }

    fn get_json(&self, path: &str, max_bytes: usize) -> Result<Value> {
        let response = self.get(path, max_bytes)?;
        serde_json::from_slice(&response.body).map_err(|err| {
            Error::parse(
                "docker api json",
                format!("{path}: {err} ({} bytes)", response.body.len()),
            )
        })
    }

    fn get(&self, path: &str, max_bytes: usize) -> Result<HttpResponse> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|err| {
            Error::unavailable(
                "Docker Engine API",
                format!("connect {}: {err}", self.socket.display()),
            )
        })?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|err| Error::unavailable("Docker Engine API", format!("write: {err}")))?;
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut truncated = false;
        let limit = max_bytes.saturating_add(MAX_HEADER_BYTES);
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    raw.extend_from_slice(&buffer[..read]);
                    if raw.len() >= limit {
                        truncated = true;
                        break;
                    }
                    if response_complete(&raw) {
                        break;
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    truncated = true;
                    break;
                }
                Err(err) => {
                    return Err(Error::unavailable(
                        "Docker Engine API",
                        format!("read: {err}"),
                    ));
                }
            }
        }
        let mut response = parse_http_response(&raw, max_bytes)?;
        response.truncated |= truncated;
        if !(200..300).contains(&response.status) {
            let snippet = String::from_utf8_lossy(&response.body[..response.body.len().min(512)]);
            return Err(Error::unavailable(
                "Docker Engine API",
                format!("HTTP {}: {}", response.status, snippet.trim()),
            ));
        }
        Ok(response)
    }
}

/// One Docker container event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerEvent {
    /// Action, e.g. `start`, `die`, `oom`, `health_status: unhealthy`.
    pub action: String,
    /// Full container id.
    pub id: String,
    /// Container name (leading slash removed).
    pub name: String,
    /// Image reference when Docker reports it.
    pub image: String,
    /// Event time in Unix nanoseconds.
    pub time_ns: i64,
    /// Bounded attributes (name, image, Compose labels).
    pub attributes: BTreeMap<String, String>,
}

/// One decoded Docker log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerLogLine {
    /// Source timestamp in Unix nanoseconds when Docker supplied one.
    pub timestamp_ns: Option<i64>,
    /// stdout or stderr.
    pub stream: LogStream,
    /// Message without the Docker timestamp prefix.
    pub text: String,
    /// Whether the underlying body/line was truncated.
    pub truncated: bool,
}

/// One bounded Docker log read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerLogBatch {
    /// Decoded lines.
    pub lines: Vec<DockerLogLine>,
    /// Whether the HTTP body/frame was truncated by a bound.
    pub truncated: bool,
    /// Latest timestamp observed (cursor for the next read).
    pub next_cursor: Option<i64>,
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
}

fn parse_summary(value: &Value) -> Option<ContainerInfo> {
    let id = value.get("Id").and_then(Value::as_str)?;
    if id.len() < 12 || !id.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    let labels = value
        .get("Labels")
        .map(parse_label_object)
        .unwrap_or_default();
    let name = value
        .get("Names")
        .and_then(Value::as_array)
        .and_then(|names| names.first())
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    Some(ContainerInfo {
        id: id.to_string(),
        short_id: id.chars().take(12).collect(),
        name,
        image: value
            .get("Image")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        state: value
            .get("State")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        status: value
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        health: None,
        labels,
        log_driver: None,
        log_options: BTreeMap::new(),
        log_path: None,
        tty: false,
        restart_policy: None,
        cgroup_parent: None,
        pid: 0,
        created: value
            .get("Created")
            .and_then(Value::as_i64)
            .map(|seconds| format_wall_rfc3339(seconds.saturating_mul(1_000_000_000))),
        started_at: None,
        finished_at: None,
        networks: value
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .map(|networks| networks.keys().cloned().collect())
            .unwrap_or_default(),
        ports: parse_ports(value.get("Ports")),
        mounts: Vec::new(),
        hostname: None,
        user: None,
        working_dir: None,
        restart_count: 0,
        memory_limit: None,
        nano_cpus: None,
        pids_limit: None,
        network_ips: Vec::new(),
        network_mode: None,
    })
}

fn parse_ports(value: Option<&Value>) -> Vec<String> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    array
        .iter()
        .take(32)
        .filter_map(|port| {
            let private = port.get("PrivatePort").and_then(Value::as_u64)?;
            let kind = port.get("Type").and_then(Value::as_str).unwrap_or("tcp");
            let public = port.get("PublicPort").and_then(Value::as_u64);
            let ip = port.get("IP").and_then(Value::as_str).unwrap_or("");
            Some(match public {
                Some(public) if !ip.is_empty() => {
                    format!("{ip}:{public}->{private}/{kind}")
                }
                Some(public) => format!("{public}->{private}/{kind}"),
                None => format!("{private}/{kind}"),
            })
        })
        .collect()
}

fn apply_inspect(container: &mut ContainerInfo, inspect: &Value) {
    if let Some(name) = inspect.get("Name").and_then(Value::as_str) {
        container.name = name.trim_start_matches('/').to_string();
    }
    if let Some(image) = inspect.pointer("/Config/Image").and_then(Value::as_str) {
        container.image = image.to_string();
    }
    if let Some(labels) = inspect.pointer("/Config/Labels") {
        let inspected = parse_label_object(labels);
        for (key, value) in inspected {
            container.labels.insert(key, value);
        }
    }
    if let Some(status) = inspect.pointer("/State/Status").and_then(Value::as_str) {
        container.state = status.to_string();
    }
    container.health = inspect
        .pointer("/State/Health/Status")
        .and_then(Value::as_str)
        .map(str::to_string);
    container.pid = inspect
        .pointer("/State/Pid")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;
    container.tty = inspect
        .pointer("/Config/Tty")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    container.log_driver = inspect
        .pointer("/HostConfig/LogConfig/Type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.log_options = inspect
        .pointer("/HostConfig/LogConfig/Config")
        .map(parse_label_object)
        .unwrap_or_default();
    container.log_path = inspect
        .get("LogPath")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.restart_policy = inspect
        .pointer("/HostConfig/RestartPolicy/Name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.cgroup_parent = inspect
        .pointer("/HostConfig/CgroupParent")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.created = inspect
        .get("Created")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| container.created.clone());
    container.started_at = inspect
        .pointer("/State/StartedAt")
        .and_then(Value::as_str)
        .map(str::to_string);
    container.finished_at = inspect
        .pointer("/State/FinishedAt")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(networks) = inspect.pointer("/NetworkSettings/Networks") {
        if let Some(object) = networks.as_object() {
            container.networks = object.keys().cloned().collect();
            container.network_ips = object
                .iter()
                .filter_map(|(name, network)| {
                    network
                        .get("IPAddress")
                        .and_then(Value::as_str)
                        .filter(|ip| !ip.is_empty())
                        .map(|ip| format!("{name}={ip}"))
                })
                .take(16)
                .collect();
        }
    }
    container.mounts = inspect
        .get("Mounts")
        .and_then(Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .take(16)
                .filter_map(|mount| {
                    let kind = mount.get("Type").and_then(Value::as_str).unwrap_or("");
                    let source = mount.get("Source").and_then(Value::as_str).unwrap_or("");
                    let destination = mount
                        .get("Destination")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    (!destination.is_empty()).then(|| format!("{kind}:{source}->{destination}"))
                })
                .collect()
        })
        .unwrap_or_default();
    container.hostname = inspect
        .pointer("/Config/Hostname")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.user = inspect
        .pointer("/Config/User")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.working_dir = inspect
        .pointer("/Config/WorkingDir")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    container.restart_count = inspect
        .get("RestartCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;
    container.memory_limit = inspect
        .pointer("/HostConfig/Memory")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    container.nano_cpus = inspect
        .pointer("/HostConfig/NanoCpus")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0);
    container.pids_limit = inspect
        .pointer("/HostConfig/PidsLimit")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0);
    container.network_mode = inspect
        .pointer("/HostConfig/NetworkMode")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if container.status.is_empty() {
        container.status = container.state.clone();
    }
}

fn parse_label_object(value: &Value) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let Some(object) = value.as_object() else {
        return labels;
    };
    for (key, value) in object.iter().take(64) {
        if key.is_empty() || super::docker::sensitive_label(key) {
            continue;
        }
        let text = value.as_str().map_or_else(
            || {
                if value.is_null() {
                    String::new()
                } else {
                    value.to_string()
                }
            },
            str::to_string,
        );
        let (key, _) = crate::store::truncate_utf8(key, 128);
        let (text, _) = crate::store::truncate_utf8(&text, 256);
        labels.insert(key, text);
    }
    labels
}

fn parse_events(body: &[u8]) -> Vec<DockerEvent> {
    let mut events = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() || events.len() >= 1000 {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if value.get("Type").and_then(Value::as_str) != Some("container") {
            continue;
        }
        let action = value
            .get("Action")
            .or_else(|| value.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if action.is_empty() {
            continue;
        }
        let time_ns = value
            .get("timeNano")
            .and_then(Value::as_i64)
            .or_else(|| {
                value
                    .get("time")
                    .and_then(Value::as_i64)
                    .map(|seconds| seconds.saturating_mul(1_000_000_000))
            })
            .unwrap_or(0);
        let actor = value.get("Actor");
        let id = actor
            .and_then(|actor| actor.get("ID"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let attributes = actor
            .and_then(|actor| actor.get("Attributes"))
            .map(parse_label_object)
            .unwrap_or_default();
        events.push(DockerEvent {
            action,
            id,
            name: attributes
                .get("name")
                .cloned()
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_string(),
            image: attributes.get("image").cloned().unwrap_or_default(),
            time_ns,
            attributes,
        });
    }
    events
}

fn parse_logs(body: &[u8], tty: bool, mut truncated: bool) -> DockerLogBatch {
    let mut records: Vec<(LogStream, Vec<u8>)> = Vec::new();
    if tty {
        for line in body.split(|byte| *byte == b'\n') {
            if !line.is_empty() {
                let mut with_newline = line.to_vec();
                with_newline.push(b'\n');
                records.push((LogStream::Stdout, with_newline));
            }
        }
    } else {
        let mut offset = 0;
        while offset + 8 <= body.len() {
            let stream = body[offset];
            let size = u32::from_be_bytes([
                body[offset + 4],
                body[offset + 5],
                body[offset + 6],
                body[offset + 7],
            ]) as usize;
            if stream > 2 {
                // Not a multiplexed body (some proxies/older APIs return raw bytes).
                records.push((LogStream::Stdout, body.to_vec()));
                break;
            }
            let start = offset + 8;
            let end = start.saturating_add(size);
            if end > body.len() {
                records.push((stream_stream(stream), body[start..].to_vec()));
                truncated = true;
                break;
            }
            records.push((stream_stream(stream), body[start..end].to_vec()));
            offset = end;
        }
        if offset == 0 && !body.is_empty() {
            records.push((LogStream::Stdout, body.to_vec()));
        }
    }

    let mut lines = Vec::new();
    let mut line_buffer: Vec<u8> = Vec::new();
    let mut line_stream = LogStream::Stdout;
    for (stream, payload) in records {
        for byte in payload {
            if byte == b'\n' {
                let raw = std::mem::take(&mut line_buffer);
                if let Some(line) = decode_line(&raw, line_stream) {
                    lines.push(line);
                }
                line_stream = stream;
            } else {
                if line_buffer.is_empty() {
                    line_stream = stream;
                }
                line_buffer.push(byte);
            }
        }
    }
    if !line_buffer.is_empty() {
        if let Some(mut line) = decode_line(&line_buffer, line_stream) {
            line.truncated = true;
            lines.push(line);
        }
    }
    if truncated {
        if let Some(line) = lines.last_mut() {
            line.truncated = true;
        }
    }
    if tty && !body.ends_with(b"\n") {
        if let Some(line) = lines.last_mut() {
            line.truncated = true;
        }
    }
    let next_cursor = lines.iter().filter_map(|line| line.timestamp_ns).max();
    DockerLogBatch {
        lines,
        truncated,
        next_cursor,
    }
}

const fn stream_stream(value: u8) -> LogStream {
    if value == 2 {
        LogStream::Stderr
    } else {
        LogStream::Stdout
    }
}

fn decode_line(raw: &[u8], stream: LogStream) -> Option<DockerLogLine> {
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(raw);
    let text = text.strip_suffix('\r').unwrap_or(&text);
    let (timestamp_ns, message) = split_timestamp(text);
    let (message, truncated) = crate::store::truncate_utf8(message, MAX_LOG_LINE_BYTES);
    Some(DockerLogLine {
        timestamp_ns,
        stream,
        text: message,
        truncated,
    })
}

fn split_timestamp(line: &str) -> (Option<i64>, &str) {
    let Some((stamp, rest)) = line.split_once(' ') else {
        return (None, line);
    };
    let timestamp = DateTime::parse_from_rfc3339(stamp)
        .ok()
        .and_then(|stamp| stamp.timestamp_nanos_opt());
    timestamp.map_or((None, line), |timestamp| (Some(timestamp), rest))
}

fn response_complete(raw: &[u8]) -> bool {
    let Some(header_end) = find_bytes(raw, b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
    if let Some(length) = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return raw.len() >= header_end + 4 + length;
    }
    headers
        .lines()
        .any(|line| line.starts_with("transfer-encoding:") && line.contains("chunked"))
        && raw.ends_with(b"0\r\n\r\n")
}

fn parse_http_response(raw: &[u8], max_body: usize) -> Result<HttpResponse> {
    let header_end = find_bytes(raw, b"\r\n\r\n").ok_or_else(|| {
        Error::parse(
            "docker http",
            format!("incomplete response headers ({} bytes)", raw.len()),
        )
    })?;
    if header_end > MAX_HEADER_BYTES {
        return Err(Error::Capacity {
            what: "docker http headers",
            limit: MAX_HEADER_BYTES as u64,
        });
    }
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| Error::parse("docker http", "non-UTF8 headers"))?;
    let mut lines = headers.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::parse("docker http", "missing status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let _http = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::parse("docker http", "invalid status line"))?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key == "content-length" {
            content_length = value.parse::<usize>().ok();
        } else if key == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }
    let body = &raw[header_end + 4..];
    let (body, truncated) = if chunked {
        decode_chunked(body, max_body)
    } else if let Some(length) = content_length {
        if body.len() >= length {
            (body[..length.min(max_body)].to_vec(), length > max_body)
        } else {
            (body.to_vec(), true)
        }
    } else {
        (
            body[..body.len().min(max_body)].to_vec(),
            body.len() > max_body,
        )
    };
    Ok(HttpResponse {
        status,
        body,
        truncated,
    })
}

fn decode_chunked(body: &[u8], max_body: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut offset = 0;
    let mut truncated = false;
    loop {
        let Some(relative_end) = find_bytes(&body[offset..], b"\r\n") else {
            return (output, true);
        };
        let line_end = offset + relative_end;
        let size_text = std::str::from_utf8(&body[offset..line_end]).unwrap_or("");
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return (output, true);
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = start.saturating_add(size);
        if end + 2 > body.len() {
            output.extend_from_slice(
                &body[start
                    ..body
                        .len()
                        .min(start + max_body.saturating_sub(output.len()))],
            );
            return (output, true);
        }
        let remaining = max_body.saturating_sub(output.len());
        if size > remaining {
            output.extend_from_slice(&body[start..start + remaining]);
            return (output, true);
        }
        output.extend_from_slice(&body[start..end]);
        offset = end + 2;
        if output.len() >= max_body {
            truncated = true;
            break;
        }
    }
    (output, truncated)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn url_encode(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![stream, 0, 0, 0];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_content_length_and_chunked_responses() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = parse_http_response(response, 1024).expect("content-length");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"{}");
        assert!(!parsed.truncated);

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        let parsed = parse_http_response(chunked, 1024).expect("chunked");
        assert_eq!(parsed.body, b"{}");

        let truncated = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        let parsed = parse_http_response(truncated, 1024).expect("short");
        assert!(parsed.truncated);
    }

    #[test]
    fn parses_multiplexed_logs_with_timestamps_and_stderr() {
        let mut body = frame(
            1,
            b"2026-11-16T12:00:00.000000001Z hello\n2026-11-16T12:00:01.000000002Z second\n",
        );
        body.extend(frame(2, b"2026-11-16T12:00:02.000000003Z bad thing\n"));
        let batch = parse_logs(&body, false, false);
        assert_eq!(batch.lines.len(), 3);
        assert_eq!(batch.lines[0].text, "hello");
        assert_eq!(batch.lines[1].text, "second");
        assert_eq!(batch.lines[2].stream, LogStream::Stderr);
        assert!(batch.lines[2].text.contains("bad thing"));
        assert!(batch.next_cursor.is_some());
    }

    #[test]
    fn parses_tty_raw_logs_and_partial_last_line() {
        let body = b"2026-11-16T12:00:00Z one\n2026-11-16T12:00:01Z two";
        let batch = parse_logs(body, true, false);
        assert_eq!(batch.lines.len(), 2);
        assert_eq!(batch.lines[1].text, "two");
        assert!(batch.lines[1].truncated);
    }

    #[test]
    fn parses_events_and_compose_metadata() {
        let body = br#"{"Type":"container","Action":"start","Actor":{"ID":"abcdef0123456789abcdef","Attributes":{"name":"/web","image":"nginx:1.27","com.docker.compose.project":"shop"}},"timeNano":1774000000000000000}
{"Type":"network","Action":"connect","Actor":{"ID":"x"},"time":1}
"#;
        let events = parse_events(body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "start");
        assert_eq!(events[0].name, "web");
        assert_eq!(
            events[0]
                .attributes
                .get("com.docker.compose.project")
                .map(String::as_str),
            Some("shop")
        );
    }

    #[test]
    fn inspect_metadata_maps_to_container_info() {
        let summary = serde_json::json!({
            "Id": "e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f",
            "Names": ["/utazbot_fastapi"],
            "Image": "utazbot/fastapi:latest",
            "State": "running",
            "Status": "Up 3 days (healthy)",
            "Labels": {"com.docker.compose.project": "utazbot"},
            "Ports": [{"IP":"127.0.0.1","PrivatePort":6379,"PublicPort":16379,"Type":"tcp"}],
            "NetworkSettings": {"Networks": {"utazbot-network": {}}}
        });
        let inspect = serde_json::json!({
            "Id": "e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f",
            "Name": "/utazbot_fastapi",
            "Created": "2026-11-13T14:38:57.648106032Z",
            "RestartCount": 2,
            "Config": {"Image": "utazbot/fastapi:latest", "Tty": false, "Labels": {"com.docker.compose.service": "fastapi"}, "Hostname": "abc123", "User": "1000", "WorkingDir": "/app"},
            "Mounts": [{"Type":"bind","Source":"/srv/data","Destination":"/data"}],
            "State": {"Status": "running", "Pid": 1_945_667, "Health": {"Status": "healthy"}, "StartedAt": "2026-11-13T14:39:22Z", "FinishedAt": "0001-01-01T00:00:00Z"},
            "HostConfig": {"LogConfig": {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "2"}}, "RestartPolicy": {"Name": "unless-stopped"}, "CgroupParent": "", "Memory": 268_435_456, "NanoCpus": 500_000_000, "PidsLimit": 100},
            "LogPath": "/var/lib/docker/containers/e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f/e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f-json.log",
            "NetworkSettings": {"Networks": {"utazbot-network": {"IPAddress":"172.20.0.5"}}}
        });
        let mut container = parse_summary(&summary).expect("summary");
        apply_inspect(&mut container, &inspect);
        assert_eq!(container.name, "utazbot_fastapi");
        assert_eq!(container.health.as_deref(), Some("healthy"));
        assert_eq!(container.pid, 1_945_667);
        assert_eq!(container.log_driver.as_deref(), Some("json-file"));
        assert_eq!(
            container.log_options.get("max-size").map(String::as_str),
            Some("1m")
        );
        assert_eq!(container.restart_policy.as_deref(), Some("unless-stopped"));
        assert!(container
            .log_path
            .as_deref()
            .is_some_and(|path| path.ends_with("-json.log")));
        assert_eq!(container.networks, vec!["utazbot-network".to_string()]);
        assert_eq!(
            container.network_ips,
            vec!["utazbot-network=172.20.0.5".to_string()]
        );
        assert_eq!(
            container.ports,
            vec!["127.0.0.1:16379->6379/tcp".to_string()]
        );
        assert_eq!(container.mounts, vec!["bind:/srv/data->/data".to_string()]);
        assert_eq!(container.hostname.as_deref(), Some("abc123"));
        assert_eq!(container.user.as_deref(), Some("1000"));
        assert_eq!(container.working_dir.as_deref(), Some("/app"));
        assert_eq!(container.restart_count, 2);
        assert_eq!(container.memory_limit, Some(268_435_456));
        assert_eq!(container.nano_cpus, Some(500_000_000));
        assert_eq!(container.pids_limit, Some(100));
        assert_eq!(
            container.compose(),
            Some(("utazbot".to_string(), "fastapi".to_string()))
        );
    }

    #[test]
    fn url_encoding_is_query_safe() {
        let encoded = url_encode(r#"{"type":["container"]}"#);
        assert_eq!(encoded, "%7B%22type%22%3A%5B%22container%22%5D%7D");
        assert!(!encoded.contains('{'));
    }

    #[test]
    fn mock_socket_discovery_negotiates_version_and_inspects() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let socket = std::env::temp_dir().join(format!(
            "sarf-docker-api-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind mock socket");
        let server = std::thread::spawn(move || {
            let version = r#"{"ApiVersion":"1.56","Version":"29.9.2"}"#;
            let list = r#"[{"Id":"e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f","Names":["/utazbot_fastapi"],"Image":"app:latest","State":"running","Status":"Up","Labels":{"com.docker.compose.project":"utazbot"},"NetworkSettings":{"Networks":{"utazbot-network":{}}}}]"#;
            let inspect = r#"{"Id":"e7e11a124d955a2e00b03ab24c2da396c93511ec9f1fa9bd3d60756b03f24a6f","Name":"/utazbot_fastapi","Created":"2026-11-13T14:38:57Z","Config":{"Image":"app:latest","Tty":false,"Labels":{"com.docker.compose.service":"fastapi"}},"State":{"Status":"running","Pid":42,"Health":{"Status":"healthy"}},"HostConfig":{"LogConfig":{"Type":"json-file","Config":{"max-size":"1m","max-file":"2"}},"RestartPolicy":{"Name":"unless-stopped"}},"LogPath":"/var/lib/docker/containers/x/x-json.log","NetworkSettings":{"Networks":{"utazbot-network":{}}}}"#;
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).expect("read request");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let body = if request.contains("/version") {
                    version
                } else if request.contains("/containers/json") {
                    list
                } else {
                    inspect
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });
        let api = DockerApi::with_socket(&socket).expect("connect mock api");
        assert_eq!(api.server_version(), Some("29.9.2"));
        assert_eq!(api.api_version(), Some("1.56"));
        let discovery = api.discover().expect("discover");
        assert!(discovery.available);
        assert_eq!(discovery.containers.len(), 1);
        assert_eq!(discovery.containers[0].name, "utazbot_fastapi");
        assert_eq!(discovery.containers[0].health.as_deref(), Some("healthy"));
        assert_eq!(
            discovery.containers[0].log_driver.as_deref(),
            Some("json-file")
        );
        server.join().expect("server");
        let _ = std::fs::remove_file(socket);
    }
}
