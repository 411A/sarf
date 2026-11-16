# Testing and validation

The required pyramid is enforced by `scripts/verify.ps1` (Windows, offline) and
`scripts/verify.sh` (Linux/macOS/CI, online), plus `.github/workflows/ci.yml`.

| Stage | Command | What it proves |
|---|---|---|
| Format | `cargo fmt --all -- --check` | canonical formatting |
| Lint | `cargo clippy --all-targets -- -D warnings` | pedantic + nursery, zero warnings |
| Compiler | `cargo build --all-targets` | every target builds |
| Unit | `cargo test --lib` | parsers, identity, time, storage, retention, EWMA, incidents, correlation, report escaping |
| Policy | `cargo test --test policy` | privacy, bounds, read-only collection, unavailable≠zero, offline HTML, incident preservation |
| Plan conformance | `cargo test --test plan_conformance` | CLI surfaces, report views, catalog coverage, required artifacts |
| Collector integration | `cargo test --test integration_collectors` | `/proc`, cgroup, process lifecycle, Docker/tmux parsers, log rotation/flood |
| Report integration | `cargo test --test integration_report` | seeded DB → rollups → windows → contributors → HTML |
| End-to-end | `cargo test --test e2e` | real `sarf` binary: init → fixture replay → why/top/incidents/logs → report |
| Performance | `cargo test --release --test perf -- --nocapture` | process scan, DB throughput, report time/size |

## Fixtures, not the host

`tests/common/mod.rs` builds Linux-shaped trees under a temporary directory:

```text
fixture/
  proc/{stat,meminfo,loadavg,pressure/*,net/dev,diskstats,uptime,sys/kernel/*}
  proc/<pid>/{stat,status,io,cgroup,cmdline}
  sys/fs/cgroup/<node>/{cpu.stat,cpu.max,cpu.pressure,memory.*,io.stat,pids.current}
  logs/…
```

`full_cycle()` creates a complete snapshot. `sarf run --fixture-root fixture` uses
`fixture/proc` repeatedly, or `fixture/cycle-NNNN/proc` once per simulated cycle. The
daemon uses `FakeClock` in replay mode, so tests are fast and deterministic.

Integration tests never require Docker, systemd, tmux or Zellij to be installed:
parsers are tested against captured output shapes, and absent tools are tested as a
normal degradation path.

## Windows notes

- `tempfile` fails against the profile temporary directory in the constrained
  development shell. Set a repo-local temp before running tests:
  `$env:TEMP=(Resolve-Path 'target\tmp').Path; $env:TMP=$env:TEMP`.
  `scripts/verify.ps1` does this and cleans up `target/tmp`.
- Builds use `--offline` on Windows (see ADR-007).
- `tests/e2e.rs` and `tests/perf.rs` are Linux-oriented but the fixture-driven e2e is
  platform-neutral; CI runs the full suite on Ubuntu and the platform-neutral subset on
  Windows.
- The Linux cross-check on Windows uses the Strawberry Perl `gcc`/`ar` only for
  type-checking `libsqlite3-sys`; nothing links.

## Linux/WSL runtime validation

The development host has WSL2 Ubuntu with a real kernel, `/proc`, cgroup v2 and PSI.
The suite is run there with a normal (online) cargo invocation, including the e2e
fixture path and a live short collection run when the environment permits. Do not
assume a Docker daemon is present: the Docker adapter is explicitly tested for absence.

## What the performance test measures

- 2,000 synthetic processes: full inventory scan (stat + cgroup + executable readlink),
  top-N selection, bounded samples.
- 20,000 host rows through the single writer in 512-row transactions.
- Report build + render for 600 host points with the default bounds.

The test prints measured milliseconds and rows/second. Thresholds are guardrails
against unbounded behavior (for example, a scan must stay under 15 s and writes above
1,000 rows/s in the test environment), **not** product guarantees. Real numbers depend
on the kernel, storage, process churn and configuration. The guide's `<0.5%` average
CPU / `<2%` burst / `10–20 MiB` RSS targets remain benchmarks to publish per reference
host, not claims.

## Known untested / environment-limited areas

- No real Docker daemon, systemd D-Bus, journald, taskstats, process connector, eBPF or
  Zellij pane topology in v0.1.
- No multi-day soak test is part of CI; run `sarf run` against a reference host and
  compare with `sar`/`docker stats` before production rollout.
- Log-driver edge cases (`none`, remote drivers, dual logging) are documented and
  degrade; only explicit file and bounded Docker CLI sources are implemented.
- Filesystem permissions are unit-tested on Unix; Windows fixture runs do not assert
  Unix modes.
- A killed daemon (SIGINT) leaves an open run row (ADR-016); bounded `--cycles` is the
  supported scripted shutdown.

## Docker validation

- Unit tests decode Content-Length/chunked HTTP, Docker's multiplex stream, TTY raw
  streams, event JSON, inspect metadata and URL encoding.
- A mock Unix-socket test exercises version negotiation, inventory and one inspect
  without a Docker daemon (runs in Linux CI).
- Live validation on WSL2 Docker created an arbitrary `alpine` container with
  non-survey labels, then confirmed the Engine API discovered its entity metadata
  (Compose project/service, image, log driver/path, network/IP, PID, restart policy),
  captured its `create`/`start` events, and persisted its ERROR log lines through the
  bounded log ring. The probe container and temporary data were removed afterward.
- The fixture e2e config disables Docker so replay is deterministic and never reads
  the host daemon; Docker is validated by the dedicated API/live tests instead.

## Recorded measurements (2026-11-16, development host)

Windows 11, Rust 1.98.1, release profile, fixture-driven perf test:

| Measurement | Result |
|---|---|
| 2,000-process inventory scan | 566 ms (≈3,532 processes/s); bounded samples |
| 20,000 host rows through the writer | 50.6 ms (≈394,980 rows/s) |
| Report build + render, 599 points | 5.0 ms, 286,165 bytes |

WSL2 Ubuntu 22.04, Linux 6.6.87, debug profile: 173 unit tests, all integration/e2e/
policy/plan tests pass; a live 4-cycle run read host/cgroup/PSI counters, discovered 81
processes, wrote 54 cgroup samples, and produced a 271 KiB report with zero writer
drops. These numbers are environment-specific measurements, not guarantees.

## Reproducing failures

Capture the fixture tree (or cycle snapshots) and run:

```bash
cargo test --lib <module>::tests::<name> -- --nocapture
cargo test --test integration_collectors -- --nocapture
cargo test --test integration_report -- --nocapture
cargo test --test e2e -- --nocapture
```

Reports are deterministic given the same DB window: `sarf report --since 1h --output
out.html` embeds the bounded JSON payload; compare the `sarf-data` block or open the
Coverage tab to see drops and gaps.
