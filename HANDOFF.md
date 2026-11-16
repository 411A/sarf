# HANDOFF — SARF v0.1 (work in progress)

**Status:** foundation + storage layer written, **crate does not compile yet** (58 mechanical
errors). No collectors, CLI, daemon, analysis or HTML report exist yet. Treat this as an
honest mid-build handoff, not a working product.

**Goal (user request):** a lightweight single-executable Rust tool that records which
services/processes (and actual code, e.g. nginx workers, docker containers, cloudflared,
tmux/Zellij sessions) consumed which resource at what time, correlates the logs that were
written around it, explains high **and low** resource usage, and exports one self-contained
offline `.html` forensics report. Linux-first, SQLite local storage, centralized data dir.

---

## 1. Read these first (in order)

1. `guide-ChatGPT.md` — the binding specification (2646 lines). Do **not** modify it.
   Most relevant sections for the current scope: §0–4 (model/catalog), §5 (collectors),
   §7 (timestamps/sampling), §8 (identity/attribution), §9 (bounded logs), §10 (incidents,
   evidence windows), §11 (schema/retention), §12 (runtime/deps/layout), §14 (HTML report),
   §15 (CLI), §19 (coverage/degradation), §21 (test plan), §22 (roadmap), §23 (Ponytail rules).
2. `AGENTS.md` — binding engineering rules: bounded everything, unavailable ≠ zero, privacy
   defaults, read-only collection, no causal overclaiming, no speculative abstraction,
   test pyramid mapping (`tests/policy.rs`, `tests/plan_conformance.rs`, …).
3. Current code:
   - `src/lib.rs` — module map and invariants.
   - `src/model.rs` — all data types (entities, identities, samples, events, logs,
     incidents, `AttributionWindow`, coverage).
   - `src/time.rs` — dual-clock (`Clock` trait, `Stamps { wall, mono, boot_id, domain }`,
     `FakeClock` for deterministic tests), RFC3339 formatting.
   - `src/paths.rs` — centralized `sarf-data/` layout next to the executable.
   - `src/config.rs` + `config/defaults.toml` + `config/integrations/*.toml` — validated,
     documented config (embedded with `include_str!`).
   - `src/store/` — schema (`schema.rs`), single-writer thread (`writer.rs`), queries
     (`query.rs`), rollups/retention/disk guard (`retention.rs`).

## 2. Environment facts (important, verified)

- Rust **1.98.1** on Windows (MSVC). Binary target is Linux; only `cargo check` for Linux is
  possible here (see below). No WSL (access denied, not admin) and Docker daemon is down, so
  **real Linux runtime tests cannot run on this machine**. Deliver fixtures + CI/Dockerfile
  and state this limitation honestly in the final report.
- crates.io is **not reachable by cargo** (Windows schannel TLS is broken host-wide:
  `SEC_E_NO_CREDENTIALS`). A pre-seeded offline registry cache exists; **always build with
  `--offline`**.
- Proxy `127.0.0.1:27910` works for Python HTTPS (used only to verify latest crate versions),
  not for cargo. Versions are pinned in `Cargo.toml`/`Cargo.lock` to the newest **cached**
  versions: clap 4.6.6 (latest is 4.6.7), rusqlite 0.40.2 (0.43.0), toml 1.1.2 (1.2.1).
  These gaps are intentional; upgrading requires a network-enabled environment.
- Linux cross-check (works today):
  ```powershell
  $env:CC_x86_64_unknown_linux_gnu='C:\StrawberryPerl\c\bin\gcc.exe'
  $env:AR_x86_64_unknown_linux_gnu='C:\StrawberryPerl\c\bin\ar.exe'
  cargo check --offline --target x86_64-unknown-linux-gnu
  ```
  (MinGW `cc`/`ar` satisfy `libsqlite3-sys`'s build script for type-checking; nothing links.)
- `_scratch/` contains a throwaway dependency probe and version-check script (gitignored);
  safe to delete.

## 3. What is done

- Git repo initialized, one commit (`Foundation: crate skeleton, model, dual clock, …`).
  Working tree holds the uncommitted storage layer + fixes.
- `src/model.rs`: full model incl. PID-reuse-safe `ProcessIdentity`, `CgroupIdentity`
  (inode+device), `CpuTimes` delta protection, PSI/network/disk counters, process/launch
  rows, events/logs/incidents, `CoverageGap`, `WritePriority`, `Classification`,
  `AttributionWindow`, `Metric`. 35 unit tests for model/time/config/paths pass.
- `src/time.rs`: `Clock`/`SystemClock`/`FakeClock`, `Stamps` with boot id + clock domain,
  single documented `unsafe` block (`clock_gettime(CLOCK_MONOTONIC)`).
- `src/paths.rs`: data-dir precedence (`--data-dir` > `SARF_DATA_DIR` > `<exe dir>/sarf-data`
  > CWD), atomic init, Unix 0750/0600 permissions, usage accounting.
- `src/config.rs`: TOML config with `Toggle` (off/auto/on, accepts bools), strict validation
  of every bound, log-source validation, atomic save. `defaults.toml` parses to
  `Config::default()` (tested).
- `src/store/schema.rs`: **18-table schema v1** (meta, hosts, runs, entities, relationships,
  process_lifetimes, host_samples, cgroup_samples, process_samples, events, logs, incidents,
  rollup_1m, rollup_1h, collector_health, integration_state, log_sources, coverage_gaps).
  No SQL FKs (writer may persist a sample before its entity row); indexes for hot queries.
- `src/store/mod.rs`: `Store` (WAL/NORMAL/busy_timeout, `auto_vacuum=INCREMENTAL`, migrations
  via `user_version`), atomic batch writes for every record type, JSON truncation bounds,
  run begin/end, checkpoint, `RowRead` u64 helpers (rusqlite has no `u64` support).
- `src/store/writer.rs`: bounded queue + dedicated writer thread; degradation order
  low→normal, critical preserved with bounded block; counters for drops/queue high-water.
- `src/store/retention.rs`: incremental complete-bucket rollups (host, cgroup; 1m then 1h),
  expiry windows, disk-size guard escalation, incident/critical-evidence preservation.
- `src/store/query.rs`: windowed `entity_usage` (cgroup from rollups, process from raw),
  host/entity series, **attribution `buckets()`** (process CPU distributed per sample
  interval), incidents, logs/events filters, lifetimes, collectors/integrations/gaps,
  `db_stats`, default window.

## 4. What is needed next (ordered)

### A. Make it compile (immediate, mechanical; 58 errors)

Run `cargo build --offline --message-format short` and fix:
1. `src/store/query.rs`: `fn sql()` helper is shadowed by local `let sql: String` in
   `lifetime_metadata` and `logs`. Rename helper to `db_err` and update all `.map_err(sql)`
   in that file.
2. `u64: FromSql` errors (`query.rs` ~543–572, `retention.rs` ~422–435, ~576–577): use the
   new `store::RowRead` trait (`row.u64_at(i)?`, `row.opt_u64_at(i)?`) instead of
   `row.get(...)`. Add `use super::RowRead;` (query/retention already inside `store`).
3. Shadowed match binding: `match (current.mem_total, current.mem_available) { (total, Some(available)) if total > 0 => ... }` — `total` is `Option<u64>` there; rename to
   `mem_total` (in `query::host_series` and `retention::rollup_host`).
4. `src/store/mod.rs` remaining `u64`/`usize` params (rusqlite has no `ToSql` for them):
   `ProcessLifetimeRow::start_ticks`, all `CgroupSample` counters, all `ProcessSample`
   counters/Options, `LogSourceRow::max_lines`/`max_bytes`. Use `to_sql_i64` /
   `to_sql_opt_i64` (host-sample arm is already converted).
5. `src/store/retention.rs` tests: `prune(...)` returns `Result<PruneReport>` — add
   `.expect("prune")` (7 call sites). Remove unused `value` binding in the disk-guard
   cutoff match and the `crate::config::Config` qualification warning.
6. Move the now-unused `use crate::time::Stamps;` in `store/mod.rs` into the test module.
7. Then: `cargo test --offline --lib` must be green (unit tests incl. new store/rollup/
   query tests), and the Linux check command above must pass.

Commit after A (message: `Storage: schema, writer, queries, rollups/retention`).

### B. Collectors (`src/collect/`)

- `collect/mod.rs`: `SourceRoot { proc, sys, cgroup }` (real `/` or fixture dir), collector
  health/coverage registry, cycle context (clock + host id + boot id + hz).
- `collect/procfs.rs`: parsers for `/proc/stat`, meminfo, loadavg, pressure/*, net/dev,
  diskstats, uptime, `/proc/PID/{stat,status,io,cgroup,exe}`. `comm` parsing must use
  `rfind(')')`; total field = user+nice+system+idle+iowait+irq+softirq+steal (no guest
  double count); counter decreases → anomaly, never a fabricated spike. Fixture-based tests
  incl. spaces/`)` in `comm`, zero elapsed, counter reset.
- `collect/host.rs`, `collect/cgroup.rs` (v2 discovery via mountinfo + `/proc/PID/cgroup`,
  read cpu.stat/memory.*/io.stat/pids.*/`*.pressure`/cpu.max; inode+device identity; never
  write), `collect/process.rs` (inventory diff with start_ticks identity, parent graph,
  top-N sampling, exec generation, PID reuse tests), `collect/logs.rs` (bounded per-source
  rings: lines/bytes/minutes; file follower with rotation/truncation/partial lines; severity
  + always-store patterns; drop counters; docker log fallback via bounded CLI documented in
  DECISIONS).
- Baseline accounting must never depend on an integration; missing data is `None` + flags.

### C. Enrichment (`src/catalog.rs`, `src/enrich/`)

Embed `config/integrations/*.toml` with `include_str!`; classify by comm/exe (nginx
master/worker, cloudflared, tmux server/clients, zellij, docker/containerd, systemd unit from
cgroup path). Docker metadata via bounded `docker ps --format {{json .}}` on the discovery
cadence (Engine API/bollard unavailable offline — record this deviation); tmux via
`tmux list-panes -F …`; Zellij session-level only (no pane plugin). Never gate baseline.
All CLI calls bounded (timeout, max bytes, cadence) and counted in collector health.

### D. Analysis (`src/analysis/`)

EWMA mean/variance with startup/zero-variance/step-change tests; absolute thresholds from
config; incident engine (open/close/hysteresis/dedup/evidence cap/incident ids pre-allocated
from `Store::max_incident_id`); **high/low usage windows** using `query::buckets()` plus
overlapping incidents, logs, lifecycle events → `AttributionWindow` with evidence bullets and
`confidence`; wording must be "observed/associated/likely contributor", never "caused".

### E. HTML report (`src/report/`)

Self-contained single file: inline CSS/JS, no CDN/network/fonts; Canvas for timeseries, SVG
for process tree; embed bounded JSON (downsampled to `report.max_points`, logs ≤
`report.max_logs`, tree ≤ `report.max_process_tree_nodes`); escape everything
(`</script` safe JSON embedding, `textContent` for display); CSP meta for `file://`.
Required views: summary + coverage/gaps; "what happened" high/low windows with top
contributors and correlated logs/events; host timeline (CPU/mem/PSI/load/net/disk);
top contributors ranked tables; process tree/lifetimes with tool/container/session;
incident evidence; collection gaps. Explain units and "percent of one core".

### F. Daemon + CLI

`daemon.rs`: sampling loop (normal cadence, adaptive incident cadence), writer submit/flush,
periodic retention/checkpoint/discovery, coverage/loss accounting, graceful Ctrl-C, bounded
`--cycles` mode and `--fixture-root` simulation for e2e tests (mark reports/DB rows
`simulated`). `cli.rs` + `src/commands/`:
`init, run, doctor, status, capabilities, gaps, top, processes, tree, why, incidents, show,
logs, report (alias graph), export, prune, benchmark, tools list|show`. Default `report`
output into `sarf-data/reports/`. Keep output compact/tabular and responsive.

### G. Test pyramid (required deliverable)

- `tests/policy.rs`: privacy defaults (no argv/env), bounded ring/evidence/queue limits,
  unavailable≠zero, degradation order, HTML external-reference ban, read-only collection,
  redaction, size-guard never deletes incidents.
- `tests/plan_conformance.rs`: traceability — roadmap phases/acceptance criteria ↔
  implemented commands/views/tests (assert CLI help contains commands, report sections exist,
  each integration has a fixture test).
- `tests/integration_*.rs` + `tests/fixtures/`: proc/cgroup trees, nginx logs, docker ps JSON,
  tmux/zellij outputs, rotation/truncation, flood/bounded memory, docker-absent continuity.
- `tests/e2e.rs`: drive the real binary (`CARGO_BIN_EXE_sarf`) through init → run with
  fixture root + FakeClock cycles → `why`/`top`/`incidents` → `report` → assert HTML has
  required sections, no external URLs, contains a known cause/log.
- `tests/perf.rs` (release): scan N=2000 synthetic processes under budget, DB write
  throughput ≥ 5k rows/s, report generation time/size bounds; print measured numbers.
- `scripts/verify.ps1` + `scripts/verify.sh` run compile → fmt → clippy `-D warnings` →
  lib tests → policy/plan/integration → e2e → release perf, and fail on any stage.

### H. Docs / packaging

`README.md` (what it is, install one-binary + data dir, quickstart, privacy/limits,
screenshots via sample report), `docs/DECISIONS.md` (ADRs: no Tokio/std threads; Stamps
fields; boot-scoped PKs; no FKs; CLI-based Docker/tmux fallback; process rollups deferred;
cache-pinned crate versions; no TUI in v0.1), `docs/TESTING.md`, `docs/SPEC-TRACEABILITY.md`,
`deploy/sarf.service`, `scripts/install.sh` (bin + user + /etc + systemd), `Dockerfile`,
`.github/workflows/ci.yml` (ubuntu: fmt/clippy/test/release/musl build/report artifact;
windows: fixture tests). Generate a sample report from e2e fixtures into
`sarf-data/reports/` and link it in the final answer.

## 5. Locked decisions — do not re-litigate without evidence

- No Tokio/async runtime: synchronous sampling loop + one writer thread (2 threads).
- `Stamps` must carry `{ wall, mono, boot_id, domain }`; monotonic values are only compared
  within a boot. Never compare mono to wall time.
- Process identity = `(boot, pid, start_ticks)`; cgroup identity = `(device, inode)`.
- SQLite: one writer connection, WAL, `synchronous=NORMAL`, bounded write queue, no FKs,
  JSON blobs bounded and truncated; `u64` ↔ `i64` at the boundary.
- Process rollups are **not** implemented in v0.1 (raw top-N samples only — document this).
- Data dir is centralized next to the executable; secrets/argv/env never stored by default.
- HTML must stay offline/self-contained; report generation is on demand, never in the
  daemon hot path; failure to parse is typed error, never panic.

## 6. Verification commands (this machine)

```powershell
cargo build --offline --all-targets
cargo test --offline --lib
cargo test --offline
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
# Linux-gated code:
$env:CC_x86_64_unknown_linux_gnu='C:\StrawberryPerl\c\bin\gcc.exe'
$env:AR_x86_64_unknown_linux_gnu='C:\StrawberryPerl\c\bin\ar.exe'
cargo check --offline --target x86_64-unknown-linux-gnu
```

## 7. Known risks / limitations to state in the final report

- No Linux runtime testing on this host (no WSL/Docker); Linux paths verified by
  cross-`cargo check` + fixture-driven tests only.
- Docker/tmux/Zellij enrichment uses bounded CLI calls (no Engine API/D-Bus) in v0.1.
- Taskstats/proc-connector/eBPF/systemd D-Bus/journald are not in v0.1; coverage must say so
  rather than reporting zeros.
- Per-process RSS sums double-count shared pages; report cgroup memory for service totals.
- Percentages are "percent of one logical core" unless explicitly stated otherwise.
