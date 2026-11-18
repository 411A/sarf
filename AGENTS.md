# AGENTS.md — SARF engineering rules

SARF (Service Activity Recorder & Forensics) is a lightweight, Linux-first process,
service and activity recorder written in Rust. These rules are binding for every
contribution (human or agent). They implement the "Ponytail" discipline described in
`guide-ChatGPT.md` §23: the smallest complete change, no speculative abstraction, no
unnecessary dependency — but never at the cost of correctness, security, error
handling or tests.

## Non-negotiable invariants

1. **Universal baseline first.** Process visibility and accounting must never depend on
   a tool-specific integration. Disabling an enrichment may lose metadata, never
   sightings or resource accounting.
2. **One executable.** `sarf` is a single binary. No daemon-side web server, no
   permanent UI process. HTML reports and TUI are generated on demand.
3. **Bounded everything.** Every queue, ring buffer, log line, evidence blob, report
   and DB write batch has a byte/line/time limit. Overflow is counted and reported.
4. **Unavailable is not zero.** Missing permissions, controllers, files or sources are
   represented as `None`/status values, never as `0` activity.
5. **Privacy by default.** No environment capture, no argv persistence unless
   explicitly enabled, no request bodies, no cookie/authorization storage, no secret
   patterns kept unredacted.
6. **Read-only collection.** SARF never writes to `/proc`, `/sys/fs/cgroup`, journals,
   Docker configuration, tmux/Zellij sessions or monitored services.
7. **No causal overclaiming.** Reports say "observed", "associated", "likely
   contributor", "unknown". Never "caused" without direct evidence.
8. **Measure, don't promise.** Resource targets in the guide are benchmarks, not
   guarantees. Performance tests record numbers.

## Working rules

- Before coding: read the touched modules, their callers and tests; state the smallest
  scope that finishes the job.
- No abstraction without a real second implementation or a stated boundary. Fixture
  and system implementations justify the `SourceRoot`, `Clock`, and `CommandRunner`
  seams; nothing else is speculative.
- No new dependency without a note in `docs/DECISIONS.md` explaining why the standard
  library or an existing dependency is insufficient.
- Every parser, state machine, data-loss path and security boundary gets a targeted
  test (unit, or fixture integration test when it crosses modules).
- Parsers are total: malformed input yields a typed error, never a panic. Fuzz-ish
  property tests are expected for parsers that read untrusted kernel/user data.
- `unsafe` is denied crate-wide. The single documented exception is the Unix
  `clock_gettime(CLOCK_MONOTONIC)` syscall wrapper in `src/time.rs`.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`,
  and (for Linux-relevant changes) `cargo check --target x86_64-unknown-linux-gnu`
  using the helper scripts under `scripts/`.
- State what was *not* tested and the remaining risks in the PR/commit description.

## Test pyramid (required)

| Stage | Where | Command |
|---|---|---|
| Compiler | whole workspace | `cargo build --all-targets` |
| Static analysis / lint | rustfmt + clippy policy | `cargo fmt --check && cargo clippy --all-targets -- -D warnings` |
| Policy | `tests/policy.rs` | `cargo test --test policy` |
| Plan / spec conformance | `tests/plan_conformance.rs` | `cargo test --test plan_conformance` |
| Unit | `#[cfg(test)]` in `src/**` | `cargo test --lib` |
| Integration | `tests/integration_*.rs` + fixtures | `cargo test --test integration_*` |
| End-to-end | real binary via `CARGO_BIN_EXE_sarf` | `cargo test --test e2e` |
| Performance | `tests/perf.rs` (release) | `cargo test --release --test perf -- --nocapture` |

`scripts/verify.sh` (Linux/macOS) and `scripts/verify.ps1` (Windows) run the whole
pyramid in order.

## Layout

- `src/collect` — source readers and parsers (`procfs`, `host`, `cgroup`, `process`,
  `logs`). Pure functions where possible; a `SourceRoot` selects real `/proc` or a
  fixture tree.
- `src/enrich` — bounded integrations (docker, tmux, zellij, nginx, cloudflared,
  systemd mapping). They enrich; they never gate baseline accounting.
- `src/store` — SQLite schema, single writer thread, queries, retention/size guard.
- `src/analysis` — EWMA baselines, incident engine, high/low usage windows and
  attribution.
- `src/report` — report data assembly and the self-contained offline HTML renderer.
- `src/commands` — one module per CLI surface; formatting only, no collection logic.

## Documentation of deviations

Any deviation from `guide-ChatGPT.md` must be recorded in `docs/DECISIONS.md` with
context, decision, consequences and the upgrade path (for example: Docker CLI metadata
fallback instead of the Engine API until `bollard` is available in the build
environment).

---

# Part B — For agents using SARF to diagnose deployed services

`SKILL.md` at the repository root is the operational playbook: freshness checks,
peak reading, per-container logs, restart/polling/leak rules and the verification
loop. Load it before running diagnosis commands. This part is the short version for
agents that *change* SARF, and the list of things that are currently wrong or missing.

## Trust rules

1. **Freshness first.** `sarf status --brief` must report `stale: false`. Otherwise
   `top`, `peaks` and `story` describe old data. Check the service, the journal and
   free disk before interpreting anything.
2. **Peak values are scoped; activity counters are not.** `peak`, `base`, `p99`,
   `score`, `share`, `nodes`, `edges`, `series`, `period_s`, `work`, and the
   `logs[]`/`events[]` arrays are per graph node. `activity.starts`, `activity.exits`,
   `activity.logs`, `activity.errors` and the CSV `starts/exits/logs/errors` columns
   are counted over the whole context window. Never attribute them to the row's
   container.
3. **Unavailable is not zero.** `-`, `null`, an omitted field, or an empty document
   with `note` means unavailable. This is invariant 4 above.
4. **Association, not causation.** A restart, a quota and a polling loop are
   hypotheses; verify them with scoped logs and process lifetimes.
5. **No secret capture.** Never add environment, `.env`, argv-by-default, request
   bodies, cookies or authorization headers to make a diagnosis "easier".
   `store_arguments` stays off; redaction stays mandatory.

## Known defects (fix these before trusting the affected output)

Ranked by the damage they do to a diagnosis.

1. **`PeakActivity` is unscoped — P0.**
   `src/analysis/peaks.rs` calls `query::window_activity(conn, context)`, and
   `src/store/query.rs::window_activity` counts every event and log in the window.
   The doc comment on `activity` already claims "scoped to this peak's entities";
   the code does not do it. This produced a live misdiagnosis: a container row
   reported `errors: 39` that belonged to other containers, and `sarf logs` for that
   container correctly returned nothing.
   *Fix:* filter events by the dossier's node entity ids and logs by node entity ids
   or `docker:<container>` sources (the sets `context_logs`/`context_events` already
   build). Add a regression test with two containers in one window: only the scope's
   error may be counted. Do not release a "fix" that merely renames the columns.

2. **Rollup accumulation is quadratic — P1.**
   `rollup_host`, `rollup_cgroups` and `rollup_hours` use
   `accumulators.iter().position(...)` for every sample. After downtime the window
   can hold hundreds of thousands of samples, and the scan dominates the prune.
   *Fix:* `HashMap<(bucket, entity_id), usize>`. Keep deterministic output order.

3. **`status` hides the storage budget — P2.**
   `status --brief` reports `database_bytes` but not `max_db_mb`, whether the guard
   is trimming, or the last pressure steps. Operators only discover data loss after
   rollups vanish.
   *Fix:* include the budget, `over_budget`, and the latest retention report
   (pressure steps, deleted rollups/peaks) in the brief payload.

4. **Runs stay open across restarts — P2.**
   `runs.stopped_wall_ns` is only written on a graceful loop end. A service restart
   leaves a dangling open run forever, so the run list looks like many live
   collectors. *Fix:* on startup, close runs for this host that are still open with a
   `restarted` reason before inserting the new run.

5. **`logs --level` hides unparsed lines — P2 (documentation or flag).**
   The filter is a minimum on parsed severity. Docker lines whose level could not be
   parsed have `level = NULL` and disappear when `--level` is passed. Agents
   reasonably conclude "no errors" when the lines exist without a level.
   *Fix:* either add `--level raw`/`--include-unparsed`, or print a one-line hint when
   `--level` is set and unparsed rows are excluded.

6. **CSV lacks the payload version — P3.**
   `sarf peaks --csv` has no `v` column, so a stored CSV cannot be tied to the
   detector policy that produced it. *Fix:* prepend `v` (and keep column order
   documented in README).

7. **`profile` has no live test — P3.**
   The parser and the unavailable path are tested; a real `perf record`/`perf report`
   run has not been exercised on Linux. Keep the limitation (self time, native
   symbols) in README/ADR-026.

8. **Stale rows in `top` look like deletions — P3.**
   `top --since 15m` drops a short-lived process when its last sample leaves the
   window. This is correct but surprises operators. *Fix:* document in the command
   help, or add a `(window)` note to the table footer.

## Improvement backlog (not defects)

- A `sarf containers --since` view that joins, per container: peak summary, restart
  count, scoped error count, `period_s`, `work` and image/service. This is the one
  command an optimization agent actually wants; today it has to join four.
- Scope `work` to more than one container source (nginx/systemd file logs) and label
  which source produced it.
- Expose `rollup_1h` per container for multi-day shape (leak vs sawtooth) without
  reading 1-minute rollups.
- Add sub-minute burst detection from raw cgroup samples; 60 s buckets average away a
  5 s poll.
- Show the effective budget and guard state in `doctor` as well as `status`.
- Make `sarf logs` accept a container name (`utazbot_tgbot`) instead of requiring the
  `docker:` prefix, while keeping the source id in the output.
- Add a golden end-to-end test with a real container restart: assert that the peak
  dossier's activity counters match only that container's events.

## Diagnosis hygiene for agents

- Always pass `--data-dir /var/lib/sarf` on the server. The default resolves next to
  the binary or in the current directory and will find an empty database.
- Full-observation installs run as **root** and the data directory is `root:root
  0750`. Do not "fix" ownership to a non-root user; root needs it. Read commands
  need `sudo` only because of the directory mode.
- Do not run a second daemon against the same database, and do not `VACUUM` while the
  daemon is running.
- Version matters: 0.1.20 added the time-leading indexes and the post-prune stamp;
  older builds can stall collection on a large database. Always check
  `sarf --version` before blaming the data.
- Prefer `peaks --containers` for container work; host peaks mix system units and
  containers and make attribution harder.
- Use `--since` windows that start after a deploy when measuring the effect of a fix;
  a restart inside the window is not an optimization result.
- Keep evidence: capture the JSON + CSV before and after, and the exact command and
  version in the report.

## Verification for changes in this area

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
`cargo check --target x86_64-unknown-linux-gnu` via `scripts/verify.sh` or
`scripts/verify.ps1`. A fix to counter scoping must add a two-container regression
test; a fix to retention must add a query-plan or timing test, not just an assertion
that the SQL text changed.

