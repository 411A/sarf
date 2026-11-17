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
- Socket access is opt-in: `sarf install --docker-group --start` adds the service
  user to the `docker` group and `SupplementaryGroups=docker` to the unit, with a
  root-equivalent warning. The command is idempotent and reuses the embedded
  installer, so upgrades do not need manual `usermod`/`sed` steps. Default
  deployment keeps baseline accounting without it.
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

## ADR-018 — Per-container network from the container network namespace

**Context.** Docker container CPU/memory/I/O/PID accounting already comes from cgroup
v2. Network byte counters were still only available host-wide. The Docker Stats API can
return per-container counters, but `stream=false` costs roughly one second per
container (measured), which is unacceptable for a 30-second cadence with many
containers. Reading `/var/lib/docker` is root-only and daemon-managed.

**Decision.**
- Read `/proc/<container-pid>/net/dev` for every running container with a PID. That
  file is the container's network namespace, so its cumulative counters are
  container-scoped. Exclude `lo` and sum the remaining interfaces.
- Store the raw counters (bytes, packets, errors, drops for RX/TX) on the container's
  existing `cgroup_samples` row. Additive schema migration v2 adds the columns; the
  existing 1-minute cgroup rollup persists RX/TX byte deltas in
  `rollup_1m.net_rx_bytes/net_tx_bytes`.
- Do not call the Docker Stats API and do not poll per-container stats. One procfs read
  per container per cycle is the whole cost.
- Skip `network_mode=host` containers: their namespace counters are host-wide. Report
  containers sharing a network namespace as shared counters; do not attempt to split
  them.
- Missing PID, stopped container, unreadable procfs or a container without a network
  namespace leaves counters `NULL` ("unavailable"), never `0`.
- Network high/low attribution windows use host network rates and rank containers by
  accumulated bytes in the run; wording stays observational.

**Consequences.** Bounded overhead and no new dependency. Network is available with
the same permissions as the rest of `/proc`; if another user's `/proc/<pid>` tree is
hidden, counters are unavailable while baseline accounting continues. Shared
namespaces and host-mode containers are explicit boundaries in reports and docs. The
schema change is additive and forward-only; older SARF builds refuse a v2 database
with an upgrade message.

**Upgrade path.** Add per-interface detail, per-container rates at sample resolution,
or flow-level data only if a real query needs them; any such change requires a new
additive migration and bounded storage review.

## ADR-019 — Static release binaries with a self-installing command

**Context.** Installing from source required a checkout, a Rust toolchain, a release
build, `scripts/install.sh`, and manual `usermod`/`sed`/`systemctl` steps to enable
Docker metadata on an existing install. CI built artifacts but did not publish a
portable release, so the VPS workflow was much larger than "download one binary".

**Decision.**
- Add a `dist` Cargo profile (`opt-level = "z"`, fat LTO, stripped, aborting panics)
  for the published artifact; the normal `release` profile stays tuned for the
  test/perf pyramid.
- `.github/workflows/release.yml` runs on `v*` tags (and manual dispatch), builds
  static musl binaries for `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`, verifies static linkage and `--version`, enforces a
  20 MiB ceiling, and publishes the binaries plus `SHA256SUMS` to the GitHub
  Release. Public repositories also get a build-provenance attestation. The tag must
  match `Cargo.toml`.
- Embed `scripts/install.sh` and `deploy/sarf.service` in the binary and expose
  `sarf install` as an idempotent root command. It installs/updates the binary,
  service user, data directory, configuration, unit and optional Docker group in one
  invocation. `--start` enables and starts the unit.
- Keep `scripts/install.sh` as the source of truth for installer logic (the binary
  feeds it through stdin) instead of duplicating the account/unit/bash rules in Rust.
  Add a `--unit` argument so the embedded unit can be passed without a repository.

**Consequences.** A release install is download + `sudo ./sarf install
--docker-group --start`; upgrades use the same command and preserve `/var/lib/sarf`.
No glibc/libsqlite3 dependency is required on the VPS. `sarf install` remains
Linux-only and root-only; the docker group is still explicitly root-equivalent.
Embedding the installer adds a small amount of binary size, and the ARM release
depends on a GitHub-hosted ARM runner.

**Upgrade path.** Add signed artifacts (`cosign`/minisign) and `.deb`/RPM packaging if
operators need repository-managed updates; keep the self-install path as the
zero-dependency fallback.

## ADR-020 — Opt-in full-observation mode runs as root

**Context.** The default `sarf` service user is isolated and cannot read every
`/proc/<pid>` entry or another user's tmux server. tmux sockets are per-user under
`/tmp/tmux-<uid>`, and the unit's `PrivateTmp=yes` hides the host `/tmp` entirely.
Operators who need complete observation asked for a root/current-user mode without
turning SARF into a writable system agent.

**Decision.** Add `sarf install --full-observation`. It sets the service user/group to
`root`, sets `PrivateTmp=no` so host tmux sockets are visible, and keeps the generated
unit's existing read-only hardening:

- `ProtectSystem=strict`
- `ReadWritePaths=<data-dir>` only
- `ProtectHome=read-only`
- `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`
- `NoNewPrivileges=yes`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`

The default remains the isolated `sarf` user. `--full-observation` is explicit because
it is root-equivalent and weakens the `/tmp` isolation boundary.

**Consequences.** Root mode sees all process and tmux data, and Docker socket access
no longer needs the docker group. It also means a compromised SARF process runs as
root, mitigated but not eliminated by the read-only mount namespace. The data
directory is chowned to root; existing history is preserved.

**Upgrade path.** A future read-only helper or narrowly scoped capabilities can
replace full root if the required observation set is proven sufficient.

## ADR-021 - Story documents merge episodes and fold repeated lines

**Context.** The first `sarf story` document emitted one group per detected window.
`CPU` and `CPU pressure` covering the same interval produced two groups with an
identical actor table, actor evidence, process-link list and log/event list, and every
identical log or lifecycle event appeared once per occurrence. The document claimed
no data was lost but spent most of its output repeating it.

**Decision.** The story document is schema version 2:

- Windows are merged into one *episode* per interval and kind before any query runs.
  Only same-kind windows that contain each other or share a boundary are merged; a
  partial overlap stays separate so evidence is never attributed to the wrong range.
  The group keeps every metric with its own observed span, plus the union interval.
- Contributors of all merged metrics become one actor list keyed by entity id, with
  per-metric `contributors` retained inside each `StoryMetric`.
- Identical log/event records (same source, level, message, entity or kind, entity,
  payload) fold into one `StoryLogLine`/`StoryEventLine` with `repeats` and a
  first/last timestamp.
- Parent/child links keep a `relevant` flag: the child started inside the episode or
  one side is an actor. The human view prints only relevant links and states how many
  long-lived links existed; JSON keeps all of them up to the per-group bound.
- `story` always reports the pre-merge `window_count`, the post-merge `group_count`,
  and `process_lifetimes_truncated`, so a reduced view is never presented as complete.

The human renderer prints one line per episode, a single host summary, one metric
summary line, one actor table (idle entities summarized in one line), relevant links
and one interleaved timeline. Log/event lines already printed for an earlier group are
referenced by count instead of reprinted; `--json` remains the complete document.
Timestamps drop the date when it equals the document range date.

**Consequences.** Console output for a busy hour shrinks by roughly 4-6x while the JSON
keeps every metric and every distinct line with its repeat count. Merged episodes take
the union interval, so a metric may be reported over a wider span than the buckets that
triggered it; each `StoryMetric` carries its own `start_wall_ns`/`end_wall_ns` to keep
that explicit. Consumers of `schema_version: 1` must read `metrics[]` instead of the
top-level `metric`/`value` fields.

**Upgrade path.** If consumers need strict per-window output, add a
`--no-merge` flag that keeps the v1 shape instead of changing the default.

## ADR-022 - Docker log cursors resume from the database

**Context.** `docker_log_cursors` lived only in memory. Every service restart (including
each `sarf install` upgrade) re-read the last 500 lines per container and stored them
again, so the same log line appeared two or three times with identical timestamps.

**Decision.** At daemon start, read `MAX(wall_ts_ns)` per stored `docker:<container>`
source and seed the cursor map before the first poll. The existing rule still drops
lines at or before the cursor, and a live cursor still wins over the seed. Logs are
additionally folded by identity in the story document, so historic duplicates remain
readable as `repeats` instead of being rewritten.

**Consequences.** Restarts no longer duplicate container logs, and the stored line count
stops growing by `tail × containers` per restart. Existing duplicates stay in the
database until retention removes them; the story view reports them as repeats.
Detection assumes the docker log source name (`docker:<container name>`) is stable
across restarts, which it already is for the collector's source ids.

**Upgrade path.** Persist cursors per container id in `integration_state` if container
renames need to preserve the exact cursor.

## ADR-023 - Reclaim space instead of deleting history forever

**Context.** A production database sat at 120 MiB against `general.max_db_mb = 100`
and never came back inside budget. Its own prune output showed the reason:

```
expire process samples older than 1h: deleted 3073 rows, now 135025344 bytes
expire non-critical logs older than 1 day: deleted 162 rows, now 135025344 bytes
```

Deleting 3 073 rows freed zero bytes. The database was created before
`PRAGMA auto_vacuum = INCREMENTAL` was applied, so it stayed at `auto_vacuum =
NONE`: SQLite marks pages free for reuse but never returns them to the filesystem.
The guard therefore escalated on every 5-minute pass from the configured policy
(`process_raw_hours = 24`, `log_days = 7`, `raw_hours = 48`) down to 1 h / 1 d /
6 h, deleting history the policy said to keep, and still reported the same size.
Separately, `sarf prune` against a live service spent 110 s waiting on the daemon's
write lock, because both processes ran the same maintenance pass.

**Decision.** In the disk guard:

- if the file is over budget and `auto_vacuum` is not INCREMENTAL, run
  `PRAGMA auto_vacuum = INCREMENTAL; VACUUM;` once, report
  `vacuumed`/`reclaimed_bytes`, and re-measure. A converted database is never
  vacuumed again, so this costs one pass, not one per five minutes.
- the escalation steps carry their own explicit cutoff (1 h process, 1 day logs,
  6 h raw, 2 days minute rollups) instead of a shared mutable cutoff.
- if a step deletes rows and the file does not shrink, the guard sets
  `guard_stalled`, stops escalating, and tells the operator to raise `max_db_mb`
  or reduce `retention.raw_hours`. Deleting more history for no gain is not a fix.
- `sarf prune --help` states that the service must be stopped first.

**Consequences.** A legacy database is reclaimed once (a few seconds of CPU and
roughly its own size in free disk during `VACUUM`); later deletes actually shrink
the file, so the guard converges and stops running heavy passes every five
minutes. If a database genuinely does not fit its budget, the operator sees the
stall instead of silently losing the retention window they configured.

**Upgrade path.** Batch the deletes (`LIMIT n` loops) and cap `incremental_vacuum`
pages per pass if large databases make a single pass too long.

## ADR-024 - A stopped collector must be visible

**Context.** A full-observation deployment showed a live run, 338 000 stored
cgroup rows and a service that looked healthy, but `range` ended one hour before
`now`: nothing had been persisted for 68 minutes. `sarf story` then printed
"no correlated groups" and the report showed `host CPU avg -`, which reads like an
idle host rather than a stopped recorder. `Restart=on-failure` also means an exit
with code 0 leaves the unit dead: the host looks monitored and records nothing.

**Decision.** `sarf status` prints the age of the newest stored sample and marks it
`STALE (expected every Ns)` when it is older than three sampling intervals; the
same value is exposed as `latest_age_ns` and `stale` in `--json`. The unit uses
`Restart=always` so a clean exit still comes back, with `StartLimitIntervalSec=300`
and `StartLimitBurst=10` so a real crash loop stops instead of restarting forever.

**Consequences.** A stalled or dead collector is visible in the first command an
operator runs, and a crash loop cannot silently consume CPU indefinitely. The
status line needs no new database state: it derives freshness from the newest
sample timestamp that retention already preserves.

## ADR-025 - Peaks are relative to a rolling baseline, not thresholds

**Context.** Operators and coding agents asked for "why was the host slow at 14:03"
in a form a program can reason about: which entity peaked, what carried the cost,
and what was happening around it. Absolute thresholds fail this: 10 % CPU is a real
peak on an idle host and irrelevant on a busy one, and 10.5 % is only a peak until
11 % becomes normal. A flame graph built from sampling stacks is not available in a
read-only binary without eBPF/perf.

**Decision.** Add `sarf peaks` and a stored dossier per peak:

- candidate = a 1-minute bucket that is `>=` the rolling p99 of the *same* entity
  and metric over `[peaks].baseline_mins` (60) **and** at least `mad_k` (3) median
  absolute deviations above the rolling median, with a small per-metric floor. The
  p99 comparison is `>=` so a sustained plateau keeps extending a run instead of
  ending after one bucket; the MAD floor stops floating-point jitter from becoming
  a peak. History is per entity/metric, so a level that becomes the norm stops
  qualifying and the *transition* is the reported peak.
- consecutive qualifying buckets form one episode (`spike` when one bucket,
  `sustained` otherwise), capped by `[peaks].max_peaks`.
- each dossier is self-contained compact JSON: peak values, a typed graph
  (`nodes` with host at index 0, cgroups, processes; `edges` labelled `on`/`in`),
  `share`/`own`, a 1-minute series aligned to a shared grid, and event/log counts.
  Missing values are omitted (`null` in the series), never zero.
- `graph` edges do not claim stack attribution: `on` means the child runs on that
  host/cgroup and does not assert an additive partition (nested cgroups overlap);
  `in` comes from the stored cgroup membership of a process and is additive, so
  `own = value - sum(contained children)` is only computed there.
- the daemon runs detection on its existing retention cadence over
  `[peaks].detect_mins` (30) and upserts dossiers into `peak_dossiers`; retention
  deletes them after `[peaks].retain_hours` (72). Dossiers survive raw-sample
  expiry, so a peak is still explainable after `raw_hours` has passed.

**Consequences.** The artifact is compact (no repeated labels, no indentation, no
pretty printing), deterministic for the same window contents, and cheap: detection
reads 1-minute rollups only and runs on the prune cadence. It cannot say which
function burned CPU; it says which host, cgroup and process did, with the series and
the surrounding events. When a stack source exists, adding `frames` to a node is
additive and does not change the document.

**Upgrade path.** Feed `sarf peaks -o peaks.json` to an agent unchanged; add an
`--explain` mode or eBPF frames later without changing `schema`/`v`.

### Amendment - correlated evidence around the peak (schema v2)

The first dossier carried only counts. An agent asked to diagnose a peak needs the
*evidence* around it, so schema v2 adds a context window whose margin is **derived,
not configured**:

- `win = [start - h, end + h]` where `h` comes from the metric's coupling class and
  the PSI pressure measured at the peak: `fast` (CPU, memory, PSI, load) 1 s idle →
  2 s fully stalled; `disk` 3 s → 8 s; `network` 10 s → 30 s. `win` exposes `h`,
  `base`, `class` and `stretch` (0..1) so a consumer can audit the derivation. A
  fixed `context_mins` was rejected: five minutes pulls in unrelated work, and a
  fixed two seconds ignores that a stalled host defers work for longer.
- `context_scale` (0.25..4.0, default 1.0) multiplies the derived margin for very
  slow hosts; the per-class clamp still applies (a CPU margin can never exceed 8 s
  even at scale 4, and any margin is capped at 60 s).
- `logs`: distinct lines from all sources in `win`, folded by (source, level,
  message) with `n` and `last_t`, errors/criticals first then chronological, capped
  at 40. `node` is the graph index when the line's entity or `docker:<container>`
  source maps to a node, so container logs land on the container that produced them.
- `events`: lifecycle events folded by (kind, entity, payload) with node index, PID
  and short label, capped at 40.
- `near`: other peaks (any entity/metric) whose interval overlaps `win`, capped at 8,
  so a CPU peak and a coincident I/O or network peak read as one story.
- `activity` counts cover `win`, so counters and listed lines agree.

`h` is the *margin around the episode*, not the episode itself: a one-minute peak
still includes everything inside that minute; the margin only decides how far outside
it something may sit and still be called correlated. Everything stays bounded and
deterministic, and missing data is still omitted rather than zeroed. The payload is
capped at 128 KiB by the writer.



