//! Docker container metadata via a bounded CLI query (v0.1 fallback).
//!
//! The Docker Engine API (`bollard`) is the documented upgrade path. This adapter is
//! enrichment only: container accounting still comes from cgroup v2 and `/proc`.
//! `docker ps` is queried at the discovery cadence, never per sampling cycle, with a
//! timeout and output cap.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use super::run_bounded;

/// Discovery timeout for `docker ps`.
pub const DOCKER_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum containers retained from one discovery pass.
pub const MAX_CONTAINERS: usize = 1000;

/// One container from `docker ps --format {{json .}}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// Full container id.
    pub id: String,
    /// Short id used in cgroup paths and labels.
    pub short_id: String,
    /// Primary name.
    pub name: String,
    /// Image reference.
    pub image: String,
    /// Docker state (`running`, `exited`, ...).
    pub state: String,
    /// Human status (`Up 2 hours`, ...).
    pub status: String,
    /// Bounded labels (never environment variables).
    pub labels: BTreeMap<String, String>,
}

impl ContainerInfo {
    /// Look up the compose project/service labels when present.
    pub fn compose(&self) -> Option<(String, String)> {
        let project = self.labels.get("com.docker.compose.project")?;
        let service = self.labels.get("com.docker.compose.service")?;
        Some((project.clone(), service.clone()))
    }
}

/// Docker discovery result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerDiscovery {
    /// Whether the docker CLI/daemon answered.
    pub available: bool,
    /// Containers found.
    pub containers: Vec<ContainerInfo>,
    /// Bounded error when unavailable.
    pub error: Option<String>,
    /// Whether output was truncated.
    pub truncated: bool,
}

/// Discover containers with one bounded `docker ps` call.
pub fn discover() -> DockerDiscovery {
    let args = vec![
        "ps".to_string(),
        "--no-trunc".to_string(),
        "--format".to_string(),
        "{{json .}}".to_string(),
    ];
    match run_bounded("docker", &args, DOCKER_TIMEOUT, 1024 * 1024) {
        Ok(output) if output.success => DockerDiscovery {
            available: true,
            containers: parse_ps_output(&output.stdout),
            error: None,
            truncated: output.truncated,
        },
        Ok(output) => DockerDiscovery {
            available: false,
            containers: Vec::new(),
            error: Some(format!(
                "docker ps exited with {:?}{}",
                output.status,
                if output.timed_out { " (timeout)" } else { "" }
            )),
            truncated: output.truncated,
        },
        Err(err) => DockerDiscovery {
            available: false,
            containers: Vec::new(),
            error: Some(err.to_string()),
            truncated: false,
        },
    }
}

/// Parse Docker's JSON-lines output. Malformed lines are skipped, not fatal.
pub fn parse_ps_output(text: &str) -> Vec<ContainerInfo> {
    let mut containers = Vec::new();
    for line in text.lines() {
        if containers.len() >= MAX_CONTAINERS {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(id) = value.get("ID").and_then(Value::as_str) else {
            continue;
        };
        if id.len() < 12 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let name = value
            .get("Names")
            .and_then(Value::as_str)
            .and_then(|names| names.split(',').next())
            .unwrap_or("")
            .to_string();
        containers.push(ContainerInfo {
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
            labels: parse_labels(value.get("Labels").and_then(Value::as_str).unwrap_or("")),
        });
    }
    containers
}

fn parse_labels(text: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    for pair in text.split(',') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || labels.len() >= 64 {
            continue;
        }
        let (value, _) = crate::store::truncate_utf8(value.trim(), 256);
        let (key, _) = crate::store::truncate_utf8(key, 128);
        labels.insert(key, value);
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_lines_and_labels() {
        let output = concat!(
            r#"{"ID":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","Names":"web-1,alias","Image":"nginx:1.27","State":"running","Status":"Up 2 hours","Labels":"com.docker.compose.project=shop,com.docker.compose.service=web"}"#,
            "\n",
            r#"{"ID":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210","Names":"worker","Image":"app:2","State":"exited","Status":"Exited (0) 1 hour ago","Labels":""}"#,
            "\n"
        );
        let containers = parse_ps_output(output);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].short_id, "abcdef012345");
        assert_eq!(containers[0].name, "web-1");
        assert_eq!(
            containers[0].compose(),
            Some(("shop".to_string(), "web".to_string()))
        );
        assert_eq!(containers[1].state, "exited");
        assert!(containers[1].labels.is_empty());
    }

    #[test]
    fn skips_malformed_and_non_container_lines() {
        let output = "not json\n{\"ID\":\"short\"}\n{\"ID\":\"zzzzzzzzzzzz\"}\n";
        assert!(parse_ps_output(output).is_empty());
    }

    #[test]
    fn caps_labels_and_containers() {
        let labels = (0..200)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        let line = format!(
            r#"{{"ID":"abcdef0123456789abcdef0123456789","Names":"x","Labels":"{labels}"}}"#
        );
        let containers = parse_ps_output(&line);
        assert_eq!(containers.len(), 1);
        assert!(containers[0].labels.len() <= 64);
    }
}
