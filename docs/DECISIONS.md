# Architecture decision records

Each record states context, decision, consequences and the upgrade path. Revisit only
with evidence. These records implement `guide-ChatGPT.md` §23/§26 and the rules in
`AGENTS.md`.

## ADR-001 — Two threads, no async runtime

**Context.** The daemon reads cheap kernel counters and must not compete with the
workload. Tokio would add a scheduler, feature surface and a second concurrency model
for no measured benefit.

**Decision.** One synchronous sampling loop plus one dedicated SQLite writer thread.
The report is generated only by a separate command invocation.

**Consequences.** Two persistent threads, deterministic tests via `FakeClock`, no
async cancellation complexity. A slow writer blocks only at the bounded queue / flush
points, where loss is counted.

**Upgrade path.** Add an async event source (Docker/systemd streams) only if profiling
or a concrete adapter requires it; keep the writer thread.

## ADR-002 — Dual clocks with an explicit domain

**Context.** Wall time is needed for humans and log matching; monotonic time is needed
for intervals and ordering. They must never be compared directly.

**Decision.** `Stamps { wall, mono, boot_id, domain }`. `CLOCK_MONOTONIC` is
boot-relative on Linux; the fallback is `std::time::Instant` with domain
`std_instant`; tests use `simulated`. Monotonic values are only compared within a boot.

**Consequences.** Persisted rows carry enough context to reject cross-boot deltas.
Reports format wall time; analysis uses monotonic values.

## ADR-003 — Process and cgroup identity

**Decision.** Process identity is `(boot_id, pid, start_ticks)`. Cgroup identity is
`(device, inode)` with the path kept for display.

**Consequences.** PID reuse creates a new lifetime instead of corrupting history; a
removed/recreated cgroup with the same path is a new entity. Namespace PID views are
not yet resolved (documented gap).

**Upgrade path.** Add PID-namespace identity and nested-container views when the
collector reads `NSpid`.

## ADR-004 — SQLite: one writer, WAL, no foreign keys, u64 at the boundary

**Decision.** WAL + `synchronous=NORMAL`, `busy_timeout`, `auto_vacuum=INCREMENTAL`,
one writer connection, one transaction per bounded batch. No SQL foreign keys: a batch
may persist a sample before its entity row. `u64` counters are converted to `i64` with
saturation at the storage boundary; reads clamp negatives to zero and never silently
turn a malformed value into zero activity.

**Consequences.** Writer isolation, predictable batching and no FK-order coupling.
Referential integrity is an application/query responsibility and is tested.

**Upgrade path.** Add prepared-statement reuse/partitioning only if measured row volume
warrants it; migrations use `PRAGMA user_version`.

## ADR-005 — Process rollups deferred

**Context.** Per-process 1-minute rollups multiply storage by process count and churn.

**Decision.** Persist raw samples only for selected processes (top-N CPU, memory
contributors, new processes). Host and cgroup samples roll up. `sarf capabilities`
and coverage gaps state this explicitly.

**Consequences.** Cheap storage and bounded reports; a process that was never selected
has no historical series. Cgroup/service totals remain the authoritative service view.

**Upgrade path.** Add per-entity rollups for pinned processes when a real query needs
them.

## ADR-006 — Docker Engine API primary; bounded CLI fallback; session/systemd metadata

**Context.** The target VPS runs Docker 29.9.2 with API 1.56 over a Unix socket,
cgroup v2 + systemd driver, and ten `json-file` containers. The socket is
`root:docker` and therefore root-equivalent. The previous v0.1 prototype used only
bounded `docker ps`/`docker logs` calls, which misses lifecycle events and is slower.

**Decision.**
- Docker metadata, lifecycle and logs use the **local Engine API over the Unix
  socket**: version negotiation, `containers/json?all=1`, one inspect per container,
  bounded `events?since/until` windows, and bounded `containers/{id}/logs` reads with
  Docker’s multiplex/TTY framing.
- Container CPU/memory/I/O/PID accounting remains cgroup v2 + `/proc`; the Stats API
  and `docker stats` are intentionally not used.
- The client is generic: all containers are enumerated; names, images, labels,
  Compose labels, health, restart policy, log driver/options/path, TTY, PID, cgroup
  parent and networks are data, never matching rules. No project/image/name is
  hardcoded.
- The bounded CLI (`docker ps`/`docker logs`) remains a fallback when the socket is
  absent/denied or on non-Unix development hosts.
- `/var/lib/docker/**/*-json.log` is never read directly (daemon-managed, root-only).
- Socket access is opt-in: `scripts/install.sh --docker-group` adds the service user
  to the `docker` group and `SupplementaryGroups=docker` to the unit, with a
  root-equivalent warning. Default deployment keeps baseline accounting without it.
- tmux: `list-panes -a -F` with stable pane ids and pane PIDs.
- Zellij: `list-sessions --short` for session-level detection only.
- systemd units: inferred from cgroup path; no D-Bus.
- nginx/cloudflared: process recognition and explicitly configured log files.

Every failure is enrichment-only; baseline accounting continues and the report marks
Docker data unavailable rather than zero.

**Consequences.** Low overhead on the surveyed host: ~1 event request/cycle, 10
inspects/30 s, 10 log reads/30 s, and no Stats API calls. Log drivers `none`/remote
are reported per source; TTY and multiplexed streams are both handled. The cost is
that full Docker observation requires a root-equivalent socket permission, which is
explicitly not the default. Inventory is capped (256 containers) and every response,
frame and log line is bounded.

**Upgrade path.** Add a persistent events/log stream or `bollard` if request latency
becomes material; add zbus/systemd, journald cursors and a Zellij plugin when their
build/permission costs are acceptable.

## ADR-007 — Pinned crate versions reflect the offline Windows cache

**Context.** On the Windows development host, cargo cannot reach crates.io
(schannel `SEC_E_NO_CREDENTIALS`), so builds use a pre-seeded offline registry. Linux/
WSL and CI can resolve newer versions.

**Decision.** Pin the newest **cached** versions:
`clap 4.6.6` (latest known 4.6.7), `rusqlite 0.40.2` (0.43.0), `toml 1.1.2` (1.2.1).
`Cargo.lock` is committed. No dependency is added without recording why the standard
library or an existing dependency is insufficient.

**Consequences.** Deliberate, documented version gaps; `--offline` builds are
reproducible on the development host. Linux CI may test upgrades independently.

**Upgrade path.** Run `cargo update`/review breaking changes in a network-enabled
environment, then re-run the full pyramid and refresh this record.

## ADR-008 — USER_HZ is assumed to be 100

**Context.** Converting `/proc/PID/stat` ticks to microseconds needs `USER_HZ`. Reading
`sysconf` would require a second `unsafe` block; the crate denies `unsafe` except the
documented `clock_gettime` wrapper.

**Decision.** Use `CLOCK_TICKS_PER_SECOND = 100`, the Linux userspace ABI value for
supported 64-bit architectures. Persist it in `meta` (`clock_ticks_per_second`). Raw
ticks are stored; percentages are ratios and do not depend on the constant.

**Consequences.** Alpha's historical 1024 value and unusual out-of-tree ABIs are not
supported. Documented in `sarf capabilities`/source comments.

**Upgrade path.** Extend the single documented time wrapper to read `sysconf` if a
supported target requires it.

## ADR-009 — Windows identity fallback is fixture-only

**Context.** Stable Rust does not expose Windows `FILE_ID_INFO`
(`windows_by_handle` is unstable). Windows is not a supported runtime, but fixture
replay and CI need deterministic identities.

**Decision.** On Windows, cgroup identity is a path+creation-time hash and file
identity is path+creation-time. On Linux use `(dev, inode)`. Reports from Windows
fixture runs are marked simulated.

**Consequences.** Identity is stable for fixture trees but is not a claim of Windows
production support.

## ADR-010 — Bounded recent-tail log start

**Context.** Replaying an entire historical file would violate bounded reads and could
flood the ring at startup. Starting exactly at EOF would miss the error lines a user
opens SARF to investigate.

**Decision.** On first open, read at most `read_bytes_per_cycle` bytes from the **end**
of the file, discard the first partial line, then follow from EOF. Rotation and
truncation restart from byte zero. Every source is additionally limited to
`MAX_LINES_PER_POLL` lines per poll and its ring caps.

**Consequences.** Recent history is available immediately; older history is not
duplicated. Drops are counted and visible.

**Upgrade path.** Add an explicit `from_beginning` per-source option with its own
byte/time budget.

## ADR-011 — CPU unit is "percent of one logical core"

**Context.** `/proc/stat` aggregates all CPUs; cgroup `usage_usec` and process ticks are
per-task. Mixing units would overstate or understate usage.

**Decision.** Divide aggregate host busy/total by total CPU ticks and multiply by the
recorded `cpu_count`, producing percent of one core. Cgroup and process percentages use
the same unit. Reports label the unit and note that values can exceed 100%.

**Consequences.** A saturated 8-core host reports ~800%, matching the documented unit.

## ADR-012 — Fixture replay uses cycle snapshots

**Decision.** `sarf run --fixture-root ROOT` uses `ROOT/proc` unless `ROOT/cycle-NNNN/`
directories exist, in which case each sampling cycle reads the next snapshot with a
`FakeClock`. Cycles are marked simulated and the run row records it.

**Consequences.** Parsers and collectors are exercised end-to-end without sleeping or
touching the host; counter deltas, process lifetimes and reports are deterministic.

**Upgrade path.** Add a recorder mode that writes cycle snapshots from a live host for
reproducible bug reports.

## ADR-013 — Unavailability, degradation and evidence preservation

**Decision.** Missing values are `None`/`NULL` plus a coverage gap; unavailable is never
zero. Under queue/disk pressure the order is: preserve lifecycle/OOM/incident/critical
evidence, then errors, then cgroup/host samples, then selected process samples, then
INFO logs. The disk guard may delete raw low-value data but never incidents.

**Consequences.** Reports can explain their blind spots; loss counters are part of the
artifact.

## ADR-014 — Self-contained HTML with a strict CSP

**Decision.** One HTML file with inline CSS/JS, Canvas charts and SVG/CSS process
trees. JSON is embedded with `<`, `>`, `&`, U+2028/U+2029 escaped; all data-derived
DOM text uses `textContent`. CSP is `default-src 'none'` with inline style/script only.
No remote fonts, images, scripts or fetch calls.

**Consequences.** The artifact opens from `file://` offline and cannot exfiltrate data.
Report generation is on demand and bounded by `report.*` settings plus a 64 MiB hard
cap.

## ADR-015 — Strict lint policy

**Decision.** `cargo fmt` is mandatory; clippy runs with `pedantic` and `nursery` and
`-D warnings`. Purely stylistic lints that conflict with the domain are allowed
crate-wide with written reasons in `Cargo.toml` (numeric casts, repeated domain names,
long linear formatters). Test code may use `expect`/`unwrap` and exact float
comparisons. Any new allow must be narrow and justified in review.

**Consequences.** Production changes are lint-clean and warning-free; test intent stays
readable.

## ADR-016 — v0.1 has no graceful SIGINT shutdown

**Context.** Installing a signal handler requires either a new dependency or a second
`unsafe` block.

**Decision.** Bounded `--cycles` is the supported scripted mode. A real daemon killed
with SIGINT leaves its run row open; `sarf status` shows it. No data corruption occurs
because SQLite commits whole batches and WAL recovery is automatic.

**Upgrade path.** Add a reviewed `ctrlc`/`signal-hook` dependency (or extend the single
audited time/FFI wrapper) and close the run row on SIGINT/SIGTERM.

## ADR-017 — A closed stdout pipe is a clean exit

**Context.** Rust's `println!` panics with `Broken pipe` when a downstream consumer
closes early (`sarf status | head`). That is normal Unix CLI behavior, not an error
worth a panic message or a non-zero status.

**Decision.** The binary installs a panic hook that detects the standard `Broken pipe`
panic, exits `0`, and defers every other panic to the default hook. This is safe,
portable standard-library code and does not reset `SIGPIPE` via `unsafe`.

**Consequences.** Piped output terminates quietly and the daemon/collection logic is
unaffected (it does not write tables). A real panic still prints normally and exits
non-zero.
