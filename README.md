# SARF — Service Activity Recorder & Forensics

SARF is a lightweight, Linux-first recorder for **process, service and activity
forensics**. It answers one practical question:

> What was running at this time, which kernel-accounted resources did it consume, what
> logs and lifecycle events surrounded that period, and what evidence supports the
> likely explanation?

It is one Rust executable, one local SQLite database and one on-demand, self-contained
HTML report. There is no web server, no cloud dependency and no permanent UI process.

## What it records

| Layer | Source | Notes |
|---|---|---|
| Host CPU, memory, load, PSI, network, disk | `/proc` counters | raw cumulative counters; rates derived |
| Service/container totals | cgroup v2 | CPU, memory, I/O, PIDs, pressure, throttling |
| Process inventory and lifetimes | `/proc/PID` | PID-reuse-safe identity, parent/child, exec changes |
| Selected process time series | `/proc/PID` | top-N by CPU plus memory contributors (bounded) |
| Logs | explicit files, Docker Engine API (CLI fallback) | bounded per-source rings, severity, redaction |
| Enrichment | Docker Engine API, tmux, Zellij, nginx, cloudflared, systemd | metadata/events/logs only; never gates baseline accounting |
| Evidence | incidents + high/low windows | correlated logs/events, confidence, coverage gaps |

The universal baseline never depends on an integration. If Docker or tmux is absent,
process and cgroup accounting continues and the report says what was unavailable.

## Install (one binary)

```bash
cargo build --release
sudo ./scripts/install.sh --binary target/release/sarf --start
sarf doctor
```

Add `--docker-group` to the installer only if you want full Docker metadata,
events and logs. Docker group membership is root-equivalent; the default install
keeps baseline accounting without Docker socket access.

The installer creates a system user, `/var/lib/sarf`, a hardened systemd unit and the
default configuration. For a manual install, put the binary anywhere and run:

```bash
sarf init                 # creates ./sarf-data next to the binary/workdir
sarf run                  # daemon in the foreground
```

Data-directory precedence:

1. `--data-dir PATH`
2. `SARF_DATA_DIR`
3. `<directory of the executable>/sarf-data`
4. `./sarf-data`

Everything SARF owns lives there: `sarf.toml`, `sarf.db` (+ WAL/SHM), `reports/` and
`sarf.log`. The directory is `0750` and the database is owner-only on Unix.

## Quickstart

```bash
sarf init
sarf run --cycles 12 --interval-secs 5     # bounded demo run
sarf why --since 1h                        # high/low windows + contributors
sarf top --since 1h --by cpu
sarf processes --since 1h --filter nginx
sarf incidents --since 24h
sarf report --since 1h                     # writes sarf-data/reports/*.html
```

Open the HTML file in any browser with networking disabled. CSS, JavaScript and the
JSON payload are inline; there are no CDNs, fonts, images or network calls.

A deterministic demo artifact can be generated without touching the host:

```bash
cargo run --example demo_report -- sarf-data/reports/sample-report.html
```

A generated demo artifact is at `sarf-data/reports/sample-report.html` (ignored by
git, regenerate with the command above).

## Why it is lightweight

- Two threads: the sampling loop and one SQLite writer.
- Host counters every tick; cgroup and process scans use configured ratios.
- Top-N process persistence instead of storing every field for every PID forever.
- Bounded rings, queues, evidence, JSON fields, report points and log lines.
- Retention rolls raw samples into 1-minute and 1-hour buckets before expiry.
- The report is built only when you ask for it.

Measured numbers from `sarf benchmark` and the release perf test are printed by the
test suite; they are measurements, not guarantees. See `docs/TESTING.md`.

## Commands

```text
sarf init [--force]
sarf run [--config PATH] [--cycles N] [--fixture-root PATH] [--simulate] [--interval-secs N]
sarf doctor | status | capabilities | gaps
sarf top [--since 1h] [--by cpu|mem|net|io] [--limit N]
sarf processes [--since 1h] [--filter TEXT]
sarf tree [--since 1h] [--process ID] [--service NAME]
sarf why [--since 1h] [--metric cpu|memory|psi_cpu|psi_memory|psi_io|load]
sarf incidents [--since 24h]
sarf show <incident-id>
sarf logs <source|all> [--since 1h] [--grep TEXT] [--level warn]
sarf report|graph [--since 1h] [--output PATH] [--incident ID] [--service NAME]
sarf export [--since 24h] [--format csv|json] [--output PATH]
sarf prune
sarf benchmark [--cycles N] [--fixture-root PATH]
sarf tools list|show ID|search QUERY
```

All commands accept global `--data-dir`, `--config` and `--json`.

## Reading the output

- CPU and PSI are **percent of one logical core**. A cgroup using four cores can show
  400%.
- Memory is bytes; reports display IEC units. Per-process RSS sums double-count shared
  pages, so service totals come from cgroup memory.
- Timeline rates are bytes/second; tables show totals in bytes.
- A dash (`—`) means **unavailable**, never zero. Missing permissions, controllers,
  files or kernel features are recorded as coverage gaps.
- Attribution language is deliberately cautious: "observed", "associated", "likely
  contributor", "temporal association only". SARF does not claim causation.

## Privacy and safety defaults

- No environment capture.
- No argv persistence unless `process.store_arguments = true`.
- No request bodies, cookies, authorization headers or TLS interception.
- Log messages are redacted for common credential shapes before storage.
- Read-only collection: SARF never writes to `/proc`, `/sys/fs/cgroup`, journals,
  Docker configuration, tmux/Zellij sessions or monitored services.
- Docker uses the local Engine API for metadata, lifecycle events and bounded logs;
  `docker ps`/`docker logs` CLI calls are only a fallback. Per-container network
  counters come from `/proc/<container-pid>/net/dev` (the container network
  namespace), need no Stats API call, and are rolled up with the cgroup sample.
  Host-mode and shared-netns containers are documented caveats, not silent guesses.
  The Docker socket is root-equivalent, so access is opt-in
  (`scripts/install.sh --docker-group`). The systemd unit never depends on Docker.

## Current limitations (v0.1)

- Linux is the supported runtime. Windows/macOS are supported for fixture replay and
  development tests only.
- No taskstats, kernel process connector, eBPF, systemd D-Bus or journald reader.
  Processes shorter than the scan interval can be missed; coverage says so.
- Docker Engine API is primary on Unix; the CLI is a fallback. No `docker stats`
  loop and no direct reads of `/var/lib/docker` log files.
- Zellij is session-level only (no stable pane PID contract).
- Per-process historical rollups are not implemented; top-N raw samples only.
- User-HZ is assumed to be 100 (the Linux userspace ABI value for supported 64-bit
  architectures).
- SIGINT does not run a graceful shutdown in v0.1; prefer bounded `--cycles` for
  scripted runs. A run row left open is visible in `sarf status`.

## Repository layout

```text
src/collect/     procfs, host, cgroup, process and log readers (fixture seam)
src/catalog.rs   declarative integration descriptors + classification
src/enrich/      Docker Engine API/CLI, tmux/Zellij adapters
src/store/       schema, single writer, queries, rollups/retention
src/analysis/    EWMA, incidents, high/low attribution windows
src/report/      bounded data assembly + self-contained HTML assets
src/daemon.rs    sampling loop, adaptive incidents, discovery cadence
src/commands/    CLI formatting only
tests/           policy, plan, integration, e2e, perf + fixtures
docs/            ADRs, Docker design, testing, spec traceability
deploy/ scripts/ systemd unit, installer, verification scripts
```

Engineering rules are in `AGENTS.md`; the binding architecture specification is
`guide-ChatGPT.md`. Docker Engine API design and permissions are in
`docs/DOCKER.md`; deviations and trade-offs are recorded in `docs/DECISIONS.md`.
