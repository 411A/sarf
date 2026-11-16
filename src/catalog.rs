//! Declarative tool catalog and process classification (guide §3–§4).
//!
//! The six embedded descriptors under `config/integrations/` are declarative data:
//! they contain aliases, roles and capabilities, never shell hooks. Classification is
//! a recognition layer only; universal process accounting works with an empty catalog.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::model::{Classification, ToolCategory, ToolSpec};

const DESCRIPTORS: [(&str, &str); 6] = [
    ("docker", include_str!("../config/integrations/docker.toml")),
    ("nginx", include_str!("../config/integrations/nginx.toml")),
    (
        "cloudflared",
        include_str!("../config/integrations/cloudflared.toml"),
    ),
    ("tmux", include_str!("../config/integrations/tmux.toml")),
    ("zellij", include_str!("../config/integrations/zellij.toml")),
    (
        "systemd",
        include_str!("../config/integrations/systemd.toml"),
    ),
];

/// Parsed integration catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    tools: Vec<ToolSpec>,
    by_comm: BTreeMap<String, usize>,
    by_executable: BTreeMap<String, usize>,
}

impl Catalog {
    /// Load and validate the embedded descriptors.
    pub fn embedded() -> Result<Self> {
        let mut tools = Vec::with_capacity(DESCRIPTORS.len());
        for (expected_id, text) in DESCRIPTORS {
            let spec: ToolSpec = toml::from_str(text)
                .map_err(|err| Error::Config(format!("integration {expected_id}: {err}")))?;
            if spec.id != expected_id {
                return Err(Error::Config(format!(
                    "integration file id mismatch: expected {expected_id}, found {}",
                    spec.id
                )));
            }
            if spec.id.is_empty() || spec.name.is_empty() {
                return Err(Error::Config(format!(
                    "integration {expected_id}: empty id or name"
                )));
            }
            tools.push(spec);
        }
        Ok(Self::from_tools(tools))
    }

    /// Build a catalog from explicit descriptors (used by tests).
    pub fn from_tools(tools: Vec<ToolSpec>) -> Self {
        let mut by_comm = BTreeMap::new();
        let mut by_executable = BTreeMap::new();
        for (index, tool) in tools.iter().enumerate() {
            for comm in &tool.comm {
                by_comm.insert(comm.to_ascii_lowercase(), index);
            }
            for executable in &tool.executables {
                by_executable.insert(executable.to_ascii_lowercase(), index);
            }
        }
        Self {
            tools,
            by_comm,
            by_executable,
        }
    }

    /// All descriptors, sorted by id for stable CLI output.
    pub fn tools(&self) -> &[ToolSpec] {
        &self.tools
    }

    /// Look up a descriptor by id.
    pub fn get(&self, id: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|tool| tool.id == id)
    }

    /// Classify one process.
    ///
    /// Matching order: exact `comm` (kernel hash-truncated names included via the
    /// executable basename), executable basename, then role rules. Cgroup-derived
    /// facts (unit/container) are independent of tool recognition so a stopped or
    /// unknown service still maps to its unit.
    pub fn classify(
        &self,
        comm: &str,
        executable: Option<&str>,
        cgroup_path: Option<&str>,
        argv0: Option<&str>,
    ) -> Classification {
        let comm_lower = comm.to_ascii_lowercase();
        let exe_base = executable
            .and_then(|path| Path::new(path).file_name())
            .map(|name| name.to_string_lossy().to_ascii_lowercase());
        let argv_lower = argv0.map(str::to_ascii_lowercase);

        let tool_index = self
            .by_comm
            .get(&comm_lower)
            .copied()
            .or_else(|| {
                exe_base
                    .as_ref()
                    .and_then(|base| self.by_executable.get(base))
                    .copied()
            })
            .or_else(|| {
                // `nginx: worker` and similar kernel comm names start with the binary.
                comm_lower
                    .split_once(':')
                    .and_then(|(prefix, _)| self.by_comm.get(prefix))
                    .copied()
            });

        let (tool, category, role) =
            tool_index
                .and_then(|index| self.tools.get(index))
                .map_or((None, None, None), |spec| {
                    let role = role_label(spec, &comm_lower, argv_lower.as_deref(), cgroup_path);
                    (Some(spec.id.clone()), Some(spec.category), role)
                });

        let unit = cgroup_path.and_then(systemd_unit_from_cgroup);
        let container_id = cgroup_path.and_then(container_from_cgroup);
        Classification {
            tool,
            category,
            role,
            container_id,
            unit,
            session: None,
        }
    }

    /// Tool ids that are configured for an integration toggle.
    pub fn ids(&self) -> Vec<String> {
        self.tools.iter().map(|tool| tool.id.clone()).collect()
    }

    /// Category display string for a tool id.
    pub fn category_of(&self, id: &str) -> Option<ToolCategory> {
        self.get(id).map(|tool| tool.category)
    }
}

/// First matching role rule for a recognized tool.
fn role_label(
    spec: &ToolSpec,
    comm_lower: &str,
    argv_lower: Option<&str>,
    cgroup_path: Option<&str>,
) -> Option<String> {
    spec.roles.iter().find_map(|rule| {
        let equals_match = rule
            .comm_equals
            .iter()
            .any(|needle| comm_lower == needle.to_ascii_lowercase());
        let comm_match = rule
            .comm_contains
            .iter()
            .any(|needle| comm_lower.contains(&needle.to_ascii_lowercase()));
        let argv_match = argv_lower.is_some_and(|argv| {
            rule.argv_contains
                .iter()
                .any(|needle| argv.contains(&needle.to_ascii_lowercase()))
        });
        let cgroup_match = cgroup_path.is_some_and(|path| {
            rule.cgroup_contains
                .iter()
                .any(|needle| path.contains(needle))
        });
        (equals_match || comm_match || argv_match || cgroup_match).then(|| rule.label.clone())
    })
}

/// Infer the systemd unit from a cgroup path.
///
/// The nearest `.service` or `.scope` ancestor is the unit. User session scopes are
/// included because they are legitimate units; slices are not.
pub fn systemd_unit_from_cgroup(path: &str) -> Option<String> {
    path.split('/')
        .rev()
        .find(|segment| {
            segment.strip_suffix(".service").is_some() || segment.strip_suffix(".scope").is_some()
        })
        .map(ToString::to_string)
}

/// Extract a Docker/containerd container id from a cgroup path.
///
/// Handles both cgroupfs (`/docker/<id>`, `/docker-<id>.scope`) and nested systemd
/// layouts (`/system.slice/docker-<id>.scope`). The short 12-character id is stored;
/// the full id remains available from Docker discovery.
pub fn container_from_cgroup(path: &str) -> Option<String> {
    for segment in path.split('/').rev() {
        if let Some(rest) = segment.strip_prefix("docker-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_container_id(id) {
                return Some(short_id(id));
            }
        }
        if let Some(rest) = segment.strip_prefix("cri-containerd-") {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_container_id(id) {
                return Some(short_id(id));
            }
        }
        if segment == "docker" || segment == "containerd" {
            continue;
        }
        if is_container_id(segment) {
            return Some(short_id(segment));
        }
    }
    None
}

fn is_container_id(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_is_valid_and_complete() {
        let catalog = Catalog::embedded().expect("catalog");
        let ids: Vec<&str> = catalog
            .tools()
            .iter()
            .map(|tool| tool.id.as_str())
            .collect();
        for expected in [
            "docker",
            "nginx",
            "cloudflared",
            "tmux",
            "zellij",
            "systemd",
        ] {
            assert!(ids.contains(&expected), "missing {expected}");
        }
        assert!(catalog.get("nginx").is_some());
        assert_eq!(catalog.category_of("nginx"), Some(ToolCategory::WebServer));
    }

    #[test]
    fn classifies_nginx_master_and_worker_roles() {
        let catalog = Catalog::embedded().expect("catalog");
        let master = catalog.classify("nginx", Some("/usr/sbin/nginx"), None, None);
        assert_eq!(master.tool.as_deref(), Some("nginx"));
        assert_eq!(master.category, Some(ToolCategory::WebServer));
        assert_eq!(master.role.as_deref(), Some("nginx master"));
        let worker = catalog.classify("nginx: worker process", Some("/usr/sbin/nginx"), None, None);
        assert_eq!(worker.role.as_deref(), Some("nginx worker"));
    }

    #[test]
    fn classifies_tools_by_executable_with_truncated_comm() {
        let catalog = Catalog::embedded().expect("catalog");
        let docker = catalog.classify(
            "docker-containe",
            Some("/usr/bin/docker-containerd"),
            None,
            None,
        );
        assert_eq!(docker.tool.as_deref(), Some("docker"));
    }

    #[test]
    fn unknown_processes_stay_unclassified_not_hidden() {
        let catalog = Catalog::embedded().expect("catalog");
        let classification = catalog.classify("my-worker", Some("/opt/my-worker"), None, None);
        assert!(classification.tool.is_none());
        assert!(classification.role.is_none());
        assert!(classification.unit.is_none());
    }

    #[test]
    fn systemd_unit_uses_nearest_service_scope() {
        assert_eq!(
            systemd_unit_from_cgroup("/system.slice/nginx.service"),
            Some("nginx.service".to_string())
        );
        assert_eq!(
            systemd_unit_from_cgroup("/user.slice/user-1000.slice/session-2.scope"),
            Some("session-2.scope".to_string())
        );
        assert_eq!(systemd_unit_from_cgroup("/system.slice"), None);
    }

    #[test]
    fn docker_container_id_is_extracted_from_both_layouts() {
        assert_eq!(
            container_from_cgroup("/docker/0123456789abcdef"),
            Some("0123456789ab".to_string())
        );
        assert_eq!(
            container_from_cgroup("/system.slice/docker-0123456789abcdef0123456789abcdef.scope"),
            Some("0123456789ab".to_string())
        );
        assert_eq!(container_from_cgroup("/system.slice/nginx.service"), None);
        assert_eq!(container_from_cgroup("/docker/not-an-id"), None);
    }

    #[test]
    fn systemd_unit_and_container_are_independent_of_recognition() {
        let catalog = Catalog::embedded().expect("catalog");
        let classification = catalog.classify(
            "unknown",
            None,
            Some("/system.slice/docker-abcdef0123456789.scope"),
            None,
        );
        assert_eq!(
            classification.unit.as_deref(),
            Some("docker-abcdef0123456789.scope")
        );
        assert_eq!(classification.container_id.as_deref(), Some("abcdef012345"));
    }
}
