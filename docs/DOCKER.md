# Docker observation and logging design

SARF treats Docker as **one optional enrichment source**, never as the accounting
layer. This document describes the generic path used for any container, on any
project, then the least-overhead behavior selected for the surveyed VPS.

## What comes from where

| Data | Source | Why |
|---|---|---|
| Container CPU, memory, I/O, PIDs | **cgroup v2** under `system.slice/docker-<id>.scope` | kernel accounting; no `docker stats`, one writer, bounded |
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
well below one request per second on average. Container CPU/memory accounting
adds **no** Docker API calls because it uses cgroup v2.

## Permissions

The Docker socket is commonly `0660 root:docker`. Access is **root-equivalent**;
SARF never grants it automatically. Options:

1. Default: no socket access. Baseline host/process/cgroup accounting continues;
   Docker metadata/events/logs are marked unavailable (never zero).
2. Opt in for full Docker observation:
   ```bash
   ./scripts/install.sh --docker-group
   ```
   This adds the service user to the `docker` group and adds
   `SupplementaryGroups=docker` to the installed unit. Remove the membership if
   the security trade-off is not acceptable.
3. Rootless Docker: run SARF as the owning user and point `DOCKER_HOST` at that
   user’s socket (`unix:///run/user/<uid>/docker.sock`), or grant an equivalent
   read-only proxy. TCP Docker endpoints are intentionally not used.

## Current boundary

Per-container **network byte counters** are not yet a time series. Host interface
counters are collected; container network names/IPs/ports are metadata. If this is
required, the next step is a schema migration for container network samples (or a
bounded Docker Stats API fallback), not scraping `/var/lib/docker`. Everything else
listed above is generic and container-agnostic.

## Report evidence

The HTML report has a dedicated **Containers** view with image, state/health,
Compose project/service, log driver/options/path, networks/IPs, ports, mounts,
restart policy/limits, working directory/user and observation times. Container
entities also carry image, state/health, restart policy, log driver/options and
Compose labels. Engine events are stored as container lifecycle events with
provenance `docker_engine_api`; logs carry the container entity ID and source.
Missing drivers, denied sockets and truncated log reads appear in the Coverage
and Gaps views. All wording remains “observed/associated”, never “caused”.
