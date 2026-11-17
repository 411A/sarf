# Docker observation and logging design

SARF treats Docker as **one optional enrichment source**, never as the accounting
layer. This document describes the generic path used for any container, on any
project, then the least-overhead behavior selected for the surveyed VPS.

## What comes from where

| Data | Source | Why |
|---|---|---|
| Container CPU, memory, I/O, PIDs | **cgroup v2** under `system.slice/docker-<id>.scope` | kernel accounting; no `docker stats`, one writer, bounded |
| Container network RX/TX bytes, packets, errors, drops | `/proc/<container-pid>/net/dev` in the container network namespace | one tiny read per container; no Stats API request |
| Container identity, name, image, labels, Compose project/service | Engine API `GET /containers/json?all=1` + `GET /containers/{id}/json` | one generic inventory, metadata only |
| Lifecycle (`start`, `die`, `stop`, `kill`, `oom`, `restart`, health) | Engine API `GET /events` in bounded `since`/`until` windows | one request per sampling cycle, no permanent stream thread |
| Container logs | Engine API `GET /containers/{id}/logs` with `since`/`tail` | respects Docker’s framing, rotation and log-driver support |
| Log driver, rotation options, log path, TTY, restart policy, health, PID, cgroup parent, networks | Engine API inspect | visible in reports/coverage without reading daemon-managed files |
| Host process view of container PIDs | `/proc` | parent/child, cgroup membership and process accounting |

SARF **does not**:

- run `docker stats`, `docker ps` or `docker logs` in a loop when the API is
  available;
- read `/var/lib/docker/containers/**/*-json.log` directly (daemon-managed and
  root-only);
- use container names, image names, Compose project names or the surveyed
  `utazbot`/`hidego-tgbot`/`mtprotoxyz` projects in any matching logic;
- read `.Config.Env` or `.Config.Cmd` (no environment/argument persistence by
  default);
- assume one log driver: it records the driver/options per container and reports
  unsupported/no-log drivers as unavailable.

## Generic matching rules

- The inventory is `all=1`, so running, paused, restarting and stopped containers
  are all observed. Metadata is container-agnostic.
- Container → cgroup mapping uses the full container ID embedded in
  `system.slice/docker-<full-id>.scope` or `docker/<full-id>`; the short
  12-character ID is only a display/entity key.
- Compose identity comes from the standard `com.docker.compose.*` labels when
  present. A plain `docker run` container has no Compose identity and is still
  fully represented.
- Logs are keyed by the container ID/name, not by project or image.
- Log driver handling:
  - `json-file`/`local`: Engine API stream works; rotation is Docker’s, SARF’s
    ring adds a second bound.
  - `journald`: API may expose logs when Docker’s journald integration allows
    it; otherwise the source reports unavailable.
  - `none`: no logs by design; metadata/accounting still work.
  - remote drivers (`syslog`, `gelf`, `fluentd`, ...): API availability depends
    on Docker’s local cache/dual logging; failure is per-source, never fatal.
- TTY containers use raw log bytes; non-TTY containers use Docker’s 8-byte
  multiplex framing; both are decoded by the same bounded parser.

## Bounds and cadence

- Inventory/inspect: discovery cadence (default 30 s), up to 256 containers.
- Events: one bounded request per sampling cycle; cursor is advanced to the
  current wall time even when no events arrive, so history is never re-read.
- Logs: one bounded request per container per discovery cadence (default 30 s),
  first read `tail=200`, subsequent reads `since=<latest timestamp>` and
  `tail=all`, response capped at 256 KiB, `logs.max_sources` and per-source ring
  caps enforced. A per-container cursor prevents replay.
- Stopped containers with an established cursor are not polled again until they
  run.
- All HTTP requests use the local Unix socket, a hard timeout and a byte cap.
  Docker returns `Content-Length`/chunked responses; both are parsed, and a
  killed/slow request cannot block the sampler indefinitely.
- The API version is negotiated from `/version` (with `DOCKER_API_VERSION`
  override); the Engine API path is used on Unix when the socket is readable,
  with the bounded `docker ps`/`docker logs` CLI as fallback.

Measured on the surveyed VPS shape (1 vCPU, 10 containers): roughly one events
request per cycle, 10 inspect requests per 30 s and 10 log reads per 30 s —
well below one request per second on average. Container CPU/memory/network
accounting adds **no** Docker API calls: it uses cgroup v2 plus one small
`/proc/<pid>/net/dev` read per container per cycle.

## Permissions

The Docker socket is commonly `0660 root:docker`. Access is **root-equivalent**;
SARF never grants it automatically. Options:

1. Default: no socket access. Baseline host/process/cgroup accounting continues;
   Docker metadata/events/logs are marked unavailable (never zero).
2. Opt in for full Docker observation:
   ```bash
   sudo sarf install --docker-group --start
   ```
   This adds the service user to the `docker` group and adds
   `SupplementaryGroups=docker` to the installed unit. The same idempotent command
   updates an existing install, so the old manual `usermod` + `sed` + `systemctl`
   sequence is no longer needed. Remove the membership if the security trade-off is
   not acceptable.
3. Rootless Docker: run SARF as the owning user and point `DOCKER_HOST` at that
   user’s socket (`unix:///run/user/<uid>/docker.sock`), or grant an equivalent
   read-only proxy. TCP Docker endpoints are intentionally not used.

## Per-container network accounting

SARF reads `/proc/<container-pid>/net/dev` once per sampling cycle for each running
container with a known PID. That file is the container's **network namespace**, so the
counters belong to the container's interfaces (`eth0`, `veth*`, ...), not the host.

- `lo` is excluded; the remaining interfaces are summed.
- Counters are cumulative kernel values. They are stored on the container's cgroup
  sample (`cgroup_samples.net_rx_bytes/net_tx_bytes/...`) and the existing 1-minute
  rollup stores only the **byte deltas** in `rollup_1m.net_rx_bytes/net_tx_bytes`.
- `sarf top --by net`, exports and the report's Network ranking consume those values.
  Network high/low attribution windows use host network rates and rank containers by
  bytes observed in the window.
- The cost is one small procfs read per container per cycle, with no Docker Stats
  request and no extra thread. `docker stats` is still never used.
- Schema version is now 2; migration is additive
  (`ALTER TABLE cgroup_samples ADD COLUMN ...`) and works on an existing v1 database.

Boundaries and caveats:

- `network_mode=host` containers are **skipped**: `/proc/<pid>/net/dev` would show
  host-wide counters and would double-count host traffic. The mode comes from the
  Engine API inspect; the bounded CLI fallback does not expose it, so host-mode
  exclusion needs the Engine API path (the default on Unix).
- Containers that share a network namespace (`network_mode=container:<id>` or a
  Kubernetes pod sandbox) report the same namespace counters. SARF cannot split them
  per process; this is documented rather than guessed.
- A missing/unreadable `/proc/<pid>/net/dev`, a container without a PID, or a stopped
  container leaves the network columns `NULL` ("unavailable"), never `0`.
- This is byte/packet accounting only, not flows. No packet capture, connection
  tracking, payload inspection or HTTP metrics; roadmap phase 8 remains out of scope.

Everything described here is generic and container-agnostic: no project, image,
container name or log driver is ever used to decide whether accounting applies.

## Report evidence

The HTML report has a dedicated **Containers** view with image, state/health,
Compose project/service, log driver/options/path, networks/IPs, ports, mounts,
restart policy/limits, working directory/user and observation times. Container
entities also carry image, state/health, restart policy, log driver/options and
Compose labels. Engine events are stored as container lifecycle events with
provenance `docker_engine_api`; logs carry the container entity ID and source.
Missing drivers, denied sockets and truncated log reads appear in the Coverage
and Gaps views. All wording remains “observed/associated”, never “caused”.
