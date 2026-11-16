# SARF — Lightweight Universal Linux Process, Service & Activity Forensics

**Document type:** Research-backed architecture specification and implementation roadmap  
**Research baseline:** 16 November 2026  
**Primary implementation language:** Rust  
**Initial platform:** Linux, with Ubuntu 24.04 as the first deployment target  
**Deployment shape:** One installable executable, one optional systemd daemon, one local SQLite database  
**Project status:** Proposed design; performance figures are targets to measure, not proven guarantees

---

## 0. Executive summary

SARF ( **S**ervice **A**ctivity **R**ecorder & **F**orensics ) should evolve from a lightweight Docker/container monitor into a **universal, Linux-native process, service, resource and activity recorder**.

Its central promise should be:

> Identify what is running, account for where resources are being consumed, preserve relevant activity around important changes, and make the evidence easy to explore—without installing a full observability stack.

The design combines:

1. **Universal process discovery** — recognize all observable Linux processes, including tools SARF has never heard of.
2. **Kernel-native resource accounting** — prefer cgroup v2 and `/proc` counters; use Docker as a lifecycle/metadata source and a fallback/validation source.
3. **Lifecycle event capture** — observe process fork/exec/exit through supported kernel interfaces when available, and reconcile event streams against `/proc`.
4. **Short-lived process accounting** — optionally use Linux taskstats so commands that finish between scans can still leave useful exit-time accounting records.
5. **Service and tool integrations** — add narrowly scoped enrichment for systemd, Docker, tmux, Zellij, cron, web servers, proxies, networking utilities, build tools and cloud CLIs.
6. **Bounded log and event ingestion** — retain important evidence without unbounded RAM queues or a second full log archive.
7. **Local analysis** — correlate metrics, process trees, logs, network observations and lifecycle events into incidents and timelines.
8. **On-demand TUI and HTML reports** — configure monitored integrations in a small terminal UI and export interactive, offline HTML reports.
9. **Small, extensible codebase** — statically compiled adapters, declarative manifests, explicit capability contracts and no dynamic plugin framework in v1.

The most important architectural rule is:

**Universal baseline process accounting must not depend on a tool-specific integration being enabled.**

Disabling the Cargo integration, for example, must not make `cargo` or `rustc` invisible. It should only disable Cargo-specific enrichment. The same rule applies to `curl`, `nginx`, `tmux`, `sing-box`, `arvan`, `gapcode`, and future tools.

### The architecture in one view

```text
                   ┌──────────────────────────────┐
                   │           Linux host         │
                   │                              │
                   │ /proc  /sys/fs/cgroup  PSI    │
                   │ taskstats  proc connector     │
                   │ journald  sockets  netns      │
                   └──────────────┬───────────────┘
                                  │
                     ┌────────────▼────────────┐
                     │    SARF collector core  │
                     │                          │
                     │ process inventory        │
                     │ cgroup / host metrics    │
                     │ event ingestion          │
                     │ bounded log ingestion    │
                     │ optional network sources │
                     └────────────┬────────────┘
                                  │
                     ┌────────────▼────────────┐
                     │ Normalized entity/event  │
                     │ and metric model         │
                     └────────────┬────────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
   ┌─────────▼─────────┐ ┌────────▼────────┐ ┌────────▼─────────┐
   │ Integration       │ │ Bounded queues  │ │ Incident and     │
   │ adapters          │ │ + SQLite writer │ │ correlation      │
   │ systemd/docker/...│ │                 │ │ engine           │
   └───────────────────┘ └────────┬────────┘ └────────┬─────────┘
                                  │                    │
                         ┌────────▼────────────────────▼──────┐
                         │         Local SQLite database       │
                         └──────────────────┬─────────────────┘
                                            │
                   ┌────────────────────────┼────────────────────┐
                   │                        │                    │
          ┌────────▼────────┐     ┌─────────▼────────┐  ┌────────▼────────┐
          │ CLI             │     │ `sarf configure` │  │ HTML export     │
          │ top/tree/show   │     │ on-demand TUI    │  │ standalone file │
          └─────────────────┘     └──────────────────┘  └─────────────────┘
```

---

## 1. Product goals

### 1.1 Core goals

- Run continuously with a very small and predictable resource footprint.
- Install as one Rust executable, with a single systemd service for the daemon.
- Keep the daemon offline-first: no external telemetry service, no cloud dependency, no network listener by default.
- Discover and track all observable user-space processes, not just Docker containers or a fixed list of applications.
- Attribute resource consumption at the finest reliable level exposed by the host: host, cgroup/service/container, process, thread/task, and optionally request/flow.
- Recognize tools and services by executable identity, cgroup, systemd unit, container metadata, session metadata and integration descriptors.
- Capture process starts, execs, exits, restarts, OOMs, health changes, resource-pressure changes and other useful events.
- Ingest configured logs continuously but with bounded memory, backpressure and explicit loss accounting.
- Correlate activity with peaks and dips in CPU, memory, disk I/O, network activity and resource pressure.
- Keep a local SQLite history with compact raw samples, rollups, incidents and retention limits.
- Provide a compact CLI, an on-demand configuration TUI and interactive, self-contained HTML forensic reports.
- Make adding an integration small and predictable without destabilizing the collector core.
- Preserve collection-coverage information so SARF can say what it could not observe.

### 1.2 Desired outcomes

A user should be able to ask questions such as:

- Which service, process or container consumed CPU during this interval?
- Which child process was responsible for a build-time CPU spike?
- Did `cargo` create a large `rustc` process tree, and which compiler child used most CPU?
- Did a short-lived `curl`/`wget`/`jq`/`rg` execution occur even though it finished between normal process samples?
- Which systemd unit, cron job, tmux pane or Zellij session owns a process?
- Did a service hit its cgroup CPU quota or experience memory/I/O pressure?
- Which logs and application events surrounded a peak?
- Which HTTP route, request ID or upstream call coincided with an expensive operation?
- Which process/container generated network traffic, and what remote endpoint was involved?
- Was the resource spike likely caused by a process, a service restart, a build, an incoming request, a scheduled job, or an external contention event?
- What information is missing because of permissions, unsupported kernel features, logging configuration, event drops or disabled integrations?

### 1.3 Non-goals for v1

- Replacing Prometheus, Grafana, Loki, OpenTelemetry Collector or a full APM suite.
- Running a web server or permanent browser dashboard.
- Capturing every packet or decrypting TLS traffic.
- Capturing HTTP request bodies, cookies, authorization headers, passwords, API keys or process environments by default.
- Building a general-purpose AI agent or running machine-learning models in the daemon.
- Automatically changing system configuration, killing processes, restarting services or applying firewall rules.
- Running arbitrary shell commands defined by an integration manifest.
- Supporting every operating system in v1. The initial design is Linux-first.
- Guaranteeing nanosecond event detection or perfect attribution for every kernel activity.
- Making eBPF mandatory.
- Shipping a dynamic third-party Rust plugin loader in v1.

---

## 2. Resource targets and measurement reality

The desired `<0.1% CPU and RAM` objective is a useful optimization ambition, but it must not be advertised as a universal guarantee.

### 2.1 Why 0.1% CPU and RAM are not equivalent

- 0.1% of one logical CPU corresponds to about **1 ms of CPU time per second**.
- 0.1% of 1 GiB of RAM is about **1 MiB**.
- 0.1% of 256 MiB is about **0.256 MiB**, or roughly 262 KiB.
- A continuously running Rust process using SQLite, buffering events and handling local sockets cannot realistically be promised to remain below a 1 MiB RSS limit.
- Scanning hundreds of processes, collecting every process's metrics at high frequency, reading logs and writing to disk will cost more than collecting a few cgroup counters every several seconds.

The project should optimize for **the smallest useful observation cost**, not a percentage slogan detached from a defined test workload.

### 2.2 Initial performance objectives

These are engineering targets to benchmark and revise—not measured results.

| Profile | CPU objective | RSS objective | Collection behavior |
|---|---:|---:|---|
| Core / idle | Stretch target below 0.1% of one core on a defined small-host test | Aim for 10–20 MiB or less after measurement | Low-frequency host/cgroup counters; no optional deep collectors |
| Normal | Aim below 0.5% average on the reference workload | Aim below 20 MiB | 5-second resource sampling; events and configured bounded logs |
| Incident burst | Short, bounded bursts; target below 2% on reference workload | Must remain under configured memory limit | Higher-frequency sampling only for selected entities and a bounded period |
| Stress / overload | Degrade safely rather than compete with workloads | Hard bounded queues and memory | Drop or summarize low-priority observations with explicit counters |

The original proposal's targets—`<0.5%` average CPU, `<2%` bursts, `10–20 MB` RSS, and `<200 MB` database—are reasonable initial benchmarks for a small reference deployment, but not proven guarantees. The universal process layer adds more work and needs its own load tests.

For a 256 MiB VPS, even a 10–20 MiB daemon consumes a meaningful share of memory. Provide an ultra-light profile that disables per-process time-series persistence, detailed log ingestion, flow tracking and optional integrations while retaining host/cgroup totals, lifecycle summaries and incidents.

### 2.3 Resource costs must be measured independently

Track:

- daemon user/system CPU time;
- average and peak RSS;
- peak virtual memory as a diagnostic, not as a substitute for RSS;
- number of threads;
- allocations or queue high-water marks in development benchmarks;
- SQLite bytes, WAL bytes and SHM bytes;
- bytes written per hour/day;
- CPU time per collector and per collection cycle where practical;
- sample scheduling lateness/jitter;
- event queue depth and event drops;
- log bytes read, parsed, retained and dropped;
- report generation duration and peak memory.

Never use a systemd CPU quota as proof that the daemon is lightweight. A quota limits consumption; it does not measure expected consumption, and hitting it can delay event processing.

---

## 3. The fundamental model: universal process observation plus optional enrichment

SARF should distinguish three concepts:

1. **Process visibility:** recognize that a process exists and account for baseline resources.
2. **Integration selection:** enable deeper, tool-specific enrichment.
3. **Collection depth:** choose how frequently and how deeply a selected entity is observed.

The TUI controls integrations and collection depth; it must not switch off the universal baseline process inventory.

### 3.1 Three integration levels

| Level | Name | Description | Requires tool-specific Rust code? |
|---|---|---|---|
| 0 | Universal recognition | Executable identity, process lifetime, parent, cgroup, CPU/memory/I/O where readable | No |
| 1 | Declarative enrichment | Executable aliases, category, labels, capability declaration, safe command/metadata rules | Usually no |
| 2 | Specialized adapter | D-Bus, Docker API, control socket, official API, log source or application-specific metrics | Yes, when needed |

Example: SARF always sees `cargo` as a process. The Cargo integration may additionally identify build jobs, map `rustc` children to a build invocation, and annotate the process tree. Disabling Cargo enrichment must not remove process accounting for `cargo` or `rustc`.

### 3.2 Capability-based integrations

Do not build a giant `Integration` trait with dozens of mandatory methods. Use small capability-specific interfaces only where multiple real implementations exist.

Candidate capabilities:

- `ProcessEnrichment`
- `ServiceManagerEvents`
- `ContainerLifecycle`
- `LogSource`
- `SessionTopology`
- `RequestMetrics`
- `NetworkFlowSource`
- `ProviderEvents`
- `ApplicationMetrics`

A manifest advertises supported capabilities. It does not claim data that the adapter cannot actually collect.

### 3.3 Declarative integration descriptor example

```toml
id = "arvancloud-cli"
name = "ArvanCloud CLI"
category = "cloud"
executables = ["arvan"]
default_mode = "basic"

[capabilities]
process = true
lifecycle = true
network_flows = false
provider_events = false

[privacy]
store_arguments = false
store_environment = false
```

A declarative descriptor may include aliases, category, default monitoring level, a safe metadata strategy and a list of capabilities. It must not contain arbitrary shell scripts, command templates with untrusted substitutions, or executable hooks.

---

## 4. What SARF should recognize

SARF should recognize executable files and service identities, not merely a curated list of display names. The following catalog is an initial enrichment backlog. Baseline process observation works even when a specific adapter is absent.

| Group | Examples supplied for SARF | Universal observations | Possible specialized enrichment |
|---|---|---|---|
| Terminal/session managers | `tmux`, `zellij`, `screen` | Process trees, lifetime, resource use | Sessions, windows, tabs, panes, attached clients |
| Init/service management | `systemd`, `systemctl` | PID 1, command executions, unit process cgroups | D-Bus unit state, jobs, service properties |
| Scheduling | `cron`, `crond`, `crontab`, systemd timers | Daemon and job process trees, exit events | Scheduled-job identity, journal records, timer metadata |
| Text/data utilities | `ripgrep`/`rg` (user wrote `rigrep`), `jq`, `yq`, `watch`, `fuser` | Process lifetime, CPU, memory, I/O, exit code | Command category and safe operation labels |
| System monitors | `ps`, `top`, `htop`, `btop`, `sar` | Executions and resource usage | Identify self-observation and prevent SARF's own reports from creating noisy incidents |
| Nix/toolchains | `nix`, `nix-daemon`, Nix commands | Process tree and I/O | Build/store operation metadata where available |
| Network diagnostics | `ip`, iproute2 suite, `traceroute`, `tcpdump`, `wget`, `curl`, `arp-scan` (user wrote `arpscan`), `arping` | Process and socket/resource observations | Request/flow metadata, capture status, interface and route changes |
| Firewall/network policy | `nft`, `iptables`, `ufw` | Command executions and service state | Rule-set change events; read-only state summaries |
| VPN/overlay | `tailscale`, `wireguard`, `wg`, `wg-quick` | Daemon, interfaces, network counters | Peer/tunnel state, local status metadata |
| Proxies/tunnels | `cloudflared`, `sing-box`, `xray`, `ngrok`, `socat` | Process, cgroup, sockets and resource use | Inbound/outbound counters, proxy stats API, tunnel state |
| Web servers/reverse proxies | `nginx`, `caddy`, `traefik` | Process tree, cgroup, logs, connections | Native status/metrics endpoints and request counters |
| Crypto/network tools | `openssl` | Short-lived execution, CPU and exit status | Operation classification only; never capture secret input or key material |
| Serverless/deployment CLIs | `vercel` | Execution, child processes, network activity | Deployment/job metadata if an official/local interface exposes it |
| Containers | `docker`, `containerd`, CRI implementations | Daemon processes and cgroups | Containers, images, runtime events, container logs |
| Orchestration | Kubernetes components such as `kubelet`, `kubectl`, control-plane services; OpenStack components/CLI | Processes, cgroups, service logs | Pods, jobs, nodes, API/resource metadata through configured local interfaces |
| Automation/IaC | `ansible`, `ansible-playbook`, `tofu`/OpenTofu, Terraform-compatible tools | Execution trees, process time, I/O, exit status | Play/task/plan/apply operation metadata when available |
| Source control/CI | `git`, `jenkins` and its agents | Processes, build trees, logs | Job/build identity, repository/workspace and pipeline events |
| Language/package builds | `pip`, `python`, `rustc`, `cargo`, compilers and linkers | Process tree, CPU, RSS, disk I/O, runtime | Build invocation grouping and compiler job attribution |
| Cloud provider tools | ArvanCLI (`arvan`), GapCode (`gapcode`) and future provider CLIs | Universal command and subprocess accounting | Provider-specific command/job/API activity if publicly documented and safely accessible |

### 4.1 Important distinctions in the catalog

- `systemd` is the service manager; `systemctl` is its command-line client.
- `cron`/`crond` is a daemon; `crontab` is a management command and a schedule file format.
- `iproute2` is a suite; `ip`, `ss`, `tc` and related binaries are individual tools.
- “Kubernetes” is not one process; the adapter must identify relevant binaries, units, containers, pods and runtime components.
- “OpenStack” is not one process; it is a family of services and command-line tools.
- `ripgrep` normally uses the executable `rg`; map the user-supplied spelling `rigrep` as a search alias only if desired, but do not assume a binary literally named `rigrep` exists.
- `arpscan` is commonly distributed as `arp-scan`; recognize both aliases when installed.
- Shell built-ins such as `cd`, `export`, `alias`, `read` or shell functions do not create separate processes. SARF cannot report them as independent processes unless there is explicit shell-level instrumentation. This is a boundary, not a missing integration.
- A CLI can exec another binary without creating a new PID. Record an `exec` transition on the existing process identity rather than inventing a new process.

### 4.2 Cloud CLI examples: ArvanCLI and GapCode

**ArvanCLI:** its official documentation describes a command structure equivalent to `arvan [command] [subcommand] [arguments] [flags]`, with the main command/category followed by a specific action. This supports an initial low-cost integration that recognizes the `arvan` executable and, when privacy settings allow, labels a command by a safely parsed command/subcommand. The baseline process record must never require a network API call. [ArvanCloud CLI documentation](https://docs.arvancloud.ir/en/developer-tools/cli) and [official CLI repository](https://github.com/arvancloud/cli).

**GapCode:** its public product page describes both CLI and desktop operation and says it works with files, applications, browsers and coding tasks. SARF can monitor its CLI process, descendants, resource consumption, process lifetime, and observable network activity. Do not claim that SARF can see every internal agent action unless GapCode exposes a documented, supported telemetry interface. A first integration should remain process-tree based. [GapCode product and CLI page](https://gapgpt.app/gapcode).

---

## 5. Data sources and collectors

## 5.1 Host metrics through `/proc` and `/sys`

Sample inexpensive kernel-maintained counters rather than repeatedly spawning `ps`, `top`, `sar`, `docker stats` or other external commands.

| Source | Data | Notes |
|---|---|---|
| `/proc/stat` | Host CPU time categories, context switches, process counts, interrupts | Calculate interval deltas; account for all relevant CPU fields |
| `/proc/meminfo` | Total, available, free, buffers/cache, swap | Prefer `MemAvailable` over simplistic used-memory arithmetic |
| `/proc/loadavg` | Load averages and runnable/total processes | Load average is not CPU percentage |
| `/proc/pressure/cpu` | CPU PSI | `some`/`full` stall trends and cumulative totals |
| `/proc/pressure/memory` | Memory PSI | Useful for reclaim/contention diagnosis |
| `/proc/pressure/io` | I/O PSI | Useful for storage stall diagnosis |
| `/proc/net/dev` | Interface byte/packet/error/drop counters | Aggregate host interfaces; account for namespaces separately |
| `/proc/diskstats` | Device I/O counters | Map device major/minor; do not assume only `sd*`, `vd*` or `nvme*` |
| `/proc/vmstat` | Page faults, swap activity and VM counters | Optional or sampled less frequently |
| `/proc/uptime` | Host uptime | Useful for reset/correlation context |
| `/proc/sys/kernel/random/boot_id` | Boot identity | Part of stable process identity |

The `/proc/stat` CPU parser must include all relevant fields: user, nice, system, idle, iowait, irq, softirq, steal, guest and guest_nice. Guest time is included in user/nice accounting, so avoid double-counting it. iowait has known accounting caveats; use guarded deltas and mark counter anomalies rather than assuming every counter always increases.

For host CPU, store raw cumulative counters and derive rates. Do not store only percentages.

## 5.2 Per-process collection through `/proc/PID`

For each tracked process (and optionally each task/thread), collect on a configurable schedule:

| File/interface | Useful fields |
|---|---|
| `/proc/PID/stat` | PID, state, PPID, process start time, user/system CPU ticks, thread count, faults, priority |
| `/proc/PID/status` | Name, state, IDs, VmRSS, VmSize, threads, context-switch counters |
| `/proc/PID/statm` | Page-count memory indicators |
| `/proc/PID/io` | `rchar`, `wchar`, `read_bytes`, `write_bytes`, syscall counts and cancelled writes |
| `/proc/PID/exe` | Executable target, subject to access permissions and process lifetime |
| `/proc/PID/cmdline` | Argument vector, sensitive; disabled/redacted by default |
| `/proc/PID/cgroup` | Cgroup membership |
| `/proc/PID/fd` | Open descriptors; expensive/sensitive; on-demand only |

Important semantics:

- `/proc/PID/io` `rchar`/`wchar` are bytes passed through read/write-like system calls; they are not necessarily physical storage bytes. `read_bytes`/`write_bytes` are closer to storage I/O accounting but also have defined kernel semantics. Keep field names and units explicit.
- Summing per-process RSS can double-count shared pages. Do not present the sum of RSS as exact physical memory use. Use cgroup memory accounting for service/container totals.
- `/proc` access may be restricted by `hidepid`, UID, namespaces, ptrace access rules, LSM policy or systemd sandboxing. A denied field must be marked unavailable, not silently reported as zero.
- Parse `/proc/PID/stat` carefully: the `comm` field is in parentheses and may contain spaces or `)` characters. Do not naïvely split the entire line on whitespace before isolating the command field.
- PID values are reused. A PID alone is never a durable identity.
- Distinguish process IDs (TGID) from task/thread IDs (TID/PID in kernel task terminology).

### Process sampling strategy

A full `/proc` scan costs approximately in proportion to the number of processes and files read. Therefore:

- discover new processes through events when available;
- reconcile the complete process inventory periodically;
- maintain a compact in-memory set of active identities;
- sample cgroup totals more often than every process;
- sample individual processes at a lower cadence or only when selected/active/expensive;
- persist process-level samples for selected entities, top-N contributors, incident windows and short-lived taskstats records;
- avoid storing every field for every PID every 100 ms.

## 5.3 cgroup v2: primary service/container resource accounting

On modern Linux systems using the unified cgroup hierarchy, cgroup v2 should be SARF's primary source for service/container totals. It avoids a full Docker stats JSON payload for every interval and exposes counters already accumulated by the kernel.

Useful cgroup v2 interfaces include:

| File | Metric |
|---|---|
| `cpu.stat` | `usage_usec`, `user_usec`, `system_usec`; throttling counters when CPU bandwidth control is enabled |
| `cpu.stat.local` | Local throttling information when supported by the kernel |
| `cpu.max` | Configured CPU quota and period |
| `cpu.weight` | Relative CPU weight |
| `cpu.pressure` | Cgroup CPU PSI when available/enabled |
| `memory.current` | Current cgroup memory |
| `memory.peak` | Peak memory where supported |
| `memory.stat` | Anonymous, file-cache, kernel and other memory breakdowns |
| `memory.events` / `memory.events.local` | Memory high/max/OOM event counters |
| `memory.swap.current` / related files | Swap accounting where available |
| `memory.pressure` | Cgroup memory PSI where available/enabled |
| `io.stat` | Per-device read/write bytes and I/O operation counters when controller enabled |
| `io.pressure` | Cgroup I/O PSI where available/enabled |
| `pids.current` | Process/task count in the cgroup |
| `pids.events` | PID-limit event counters |
| `cgroup.procs` / `cgroup.threads` | Process/thread membership; read only |
| `cgroup.events` | Cgroup populated/frozen state and other events |

Implementation rules:

1. Detect cgroup v2 from mount information and the actual hierarchy; do not hardcode a Docker-specific path.
2. Discover process cgroup membership from `/proc/PID/cgroup` and resolve it against `/proc/self/mountinfo` or a reliable mount discovery routine.
3. Handle systemd slices/scopes, Docker cgroups, containerd/CRI runtimes, delegated subtrees and nonstandard cgroup drivers.
4. Track cgroup inode/device identity or another robust generation identity, not only its path; cgroups can be deleted and recreated.
5. Reconcile process membership after migration, restart and PID reuse.
6. Support cgroup v1 as a compatibility fallback only if it is in scope for the target hosts. cgroup v2 remains the priority.
7. Read only; never write to cgroup control files.
8. Detect unavailable controllers and missing files. A missing `io.stat` or disabled controller is not a zero value.

Cgroup v2 does **not** provide a standard network accounting controller equivalent to CPU/memory/I/O accounting. SARF needs a separate network collector for per-container/per-process network attribution.

### CPU percentage semantics

For cgroup `cpu.stat`:

```text
cpu_delta_usec = usage_usec_now - usage_usec_previous
elapsed_usec   = monotonic_now - monotonic_previous

cpu_percent_one_core = 100 * cpu_delta_usec / elapsed_usec
```

This definition is percentage of one logical CPU. On a multi-core system, it can exceed 100% if a process group uses multiple cores. If presenting percentage of total machine capacity, divide by the number of effective CPUs and label the metric accordingly.

Record `cpu.max`, ancestor quotas and `cpu.weight` as context. A cgroup can be limited by an ancestor even when its own `cpu.max` says `max`.

### Throttling and provider contention

Record `nr_periods`, `nr_throttled`, and `throttled_usec` when exposed. Distinguish a local cgroup quota from inherited ancestor throttling; the kernel documents `cpu.stat.local` separately for local throttling accounting on supported versions.

Host `%steal` is a useful virtualization signal, but it is not proof on its own that a particular service was throttled. Correlate host steal, CPU PSI, cgroup throttle counters, runnable tasks and observed latency.

## 5.4 Process lifecycle events: proc connector

Linux's process connector (`CN_PROC`) can deliver process lifecycle events such as fork, exec, UID/GID changes, session changes, coredumps and exit. This can reduce dependence on repeated full `/proc` scans.

Use it as an optional event source, not as the sole source of truth.

Important considerations:

- Kernel configuration, connector availability and host permissions vary.
- The process connector's event structures are versioned/kernel ABI details; isolate parsing and validate message lengths/types.
- Event messages are delivered over Netlink; receiver buffer exhaustion or send failure can lose observations.
- Kernel source maintains event sequence numbers per CPU; do not pretend that one global sequence guarantees completeness.
- Track receive errors, overrun/drop indicators where available, sequence anomalies and reconnection periods.
- Reconcile against `/proc` regularly to discover missed starts or exits.
- An exec event does not necessarily carry the full executable path. Read `/proc/PID/exe`/`cmdline` promptly, or use an eBPF exec tracepoint if reliable executable-name capture is required.

## 5.5 Taskstats: short-lived process accounting

This is an important optional collector for commands that can start and exit between ordinary `/proc` samples.

The Linux taskstats interface is Netlink-based and can provide per-task/per-process accounting during a task's lifetime and on exit. Exit notifications can include per-task statistics and, when the final thread exits, a process/thread-group aggregate.

Potentially useful fields include:

- PID/PPID and command name;
- exit code and elapsed time;
- user/system CPU time;
- page-fault information;
- high-water RSS/virtual-memory values when extended accounting is enabled;
- character I/O counters and context switches;
- delay-accounting fields when the kernel is built/configured for them.

Kernel configuration matters:

- `CONFIG_TASKSTATS` enables the taskstats interface and basic fields.
- `CONFIG_TASK_XACCT` controls extended accounting fields.
- `CONFIG_TASK_DELAY_ACCT` controls delay accounting fields.
- Delay accounting may need boot-time or runtime enablement; only tasks started after it is enabled have delay-accounting data.
- High event rates can overflow Netlink receive buffers. Size buffers appropriately, use CPU masks/listeners as documented, monitor `ENOBUFS`, and reconcile where possible.

Taskstats is **not** a magic exact per-instruction profiler. It is useful exit-time task accounting. It can add meaningful visibility for short-lived `curl`, `jq`, `rg`, `openssl`, `systemctl`, `git`, `pip`, `cargo` helper processes and compiler jobs.

Suggested process-event pipeline:

```text
fork/exec event ──> create/update process lifetime
                         │
                         ├── read executable + cgroup promptly
                         ├── establish parent relationship
                         ├── register active identity
                         └── sample selected long-running process

exit event/taskstats ──> finalize lifetime and record exit accounting

periodic /proc scan ──> reconcile missing/changed process identities
```

## 5.6 eBPF: optional advanced collection

eBPF should be an advanced opt-in collector after the baseline is benchmarked. It can enrich process lifecycle, selected syscall/network events, socket-to-process attribution and other kernel-level observations.

Potential tracepoints include:

- `sched_process_fork`
- `sched_process_exec`
- `sched_process_exit`

Use eBPF for a specific demonstrated requirement, not as an automatic default. It adds kernel compatibility, privileges, verifier, buffer sizing, BTF/CO-RE and deployment concerns.

Aya is a Rust eBPF option, but the current state of Rust eBPF CO-RE support should be rechecked at implementation time. A practical design may use an embedded precompiled BPF object or a minimal C eBPF object with Rust userspace loading/processing. That can still be packaged into one main SARF executable, but it is not equivalent to having no kernel-specific payload at all.

No eBPF feature may be required for basic process, host or cgroup accounting.

## 5.7 PSI: event-oriented pressure monitoring

Pressure Stall Information exposes CPU, memory and I/O stall time in `/proc/pressure/*`, and cgroup PSI where enabled.

Record:

- `some` and `full` averages where available;
- `avg10`, `avg60`, `avg300`;
- cumulative `total` stall time;
- sample timestamps and deltas.

PSI can also register threshold triggers and notify userspace through poll/select/epoll. This is potentially more efficient than repeatedly polling aggressive thresholds. The kernel documentation describes supported tracking windows and notification behavior; it does not provide nanosecond detection.

Suggested use:

- Always sample low-cost PSI totals/averages at the baseline interval.
- Optionally register PSI triggers for configured resource pressure.
- On notification, raise detail for the affected host/cgroup, not every process on the machine.

## 5.8 Docker integration

Docker is one integration, not the core accounting layer.

Use Docker Engine API for:

- initial container discovery;
- container name, image, labels, project/service metadata;
- lifecycle events (`start`, `die`, `oom`, `health_status`, `restart`, `destroy` and relevant events supported by the daemon/API version);
- health and restart metadata;
- logs through the supported logs API;
- optional Stats API fallback/validation.

Recommended schedule:

- discover/reconcile containers at startup;
- consume Docker events continuously;
- refresh the inventory periodically (e.g. every 30 seconds) and after reconnects/event gaps;
- inspect details on discovery, lifecycle changes and configured periodic refreshes;
- use cgroup v2 as the primary resource data source when reliable;
- use `GET /containers/{id}/stats?stream=false&one-shot=true` as fallback or validation. Docker documents that `one-shot=true` must be used with `stream=false`, and publishes the formulas for CPU and memory values.

When using Docker Stats API, handle cgroup v1/v2 differences. On cgroup v2, Docker's API stats omit or alter some fields; for memory working-set calculations the API documentation uses `usage - inactive_file` for cgroup v2 and `usage - cache` for cgroup v1.

Docker network counters can be retained as one source of per-container traffic accounting. Do not assume every runtime exposes identical fields.

### Docker logs

- Use the Docker Engine logs API/stream, not repeated `docker logs` subprocesses.
- Handle Docker's multiplexed stdout/stderr framing correctly when TTY is disabled; the Docker stream format uses an 8-byte header per frame.
- Parse timestamps only when the API requests timestamped output; retain the source timestamp separately from SARF ingestion time.
- Reconnect with a bounded backoff and a `since`/cursor strategy that avoids unnecessary replay where supported.
- Do not read or manipulate Docker's internal `local` log-driver files directly; Docker documents those files as daemon-managed.
- Docker's `none` logging driver provides no container logs. Remote logging drivers may make local `docker logs` unavailable when dual logging is disabled. Applications may also write logs to files instead of stdout/stderr.
- Surface these conditions in collector coverage rather than presenting missing logs as an empty log stream.

### Docker security

Access to the Docker daemon socket is highly privileged. The Docker group grants root-level control; a process that promises to issue only GET requests is not thereby sandboxed to GET-only access.

Preferred options, in order:

1. Use cgroup v2 and `/proc` for baseline accounting without Docker socket access.
2. Use a carefully restricted read-only API intermediary if Docker metadata/events/logs are required and the extra component is acceptable.
3. If direct socket access is required, document that it is root-equivalent, restrict who can access SARF and its socket, keep the daemon API local, and never expose it over an unauthenticated TCP listener.

Do not add the `sarf` service account to the `docker` group while describing the result as least privilege.

## 5.9 systemd integration

Prefer systemd's D-Bus API for unit discovery, state changes, jobs and service metadata instead of spawning `systemctl` periodically.

Possible enrichment:

- map a PID/cgroup to its systemd unit;
- track unit start/stop/restart/failure and job changes;
- collect active/substate, invocation identity, main PID, control group and configured resource limits where permitted;
- correlate a service process tree with its service unit and slice;
- access journald entries through an appropriate read-only journal API/path where permissions allow.

`systemctl` itself remains a process that SARF observes like any other CLI command. The systemd adapter is distinct from observing `systemctl` command executions.

## 5.10 tmux and Zellij integration

Baseline process monitoring always works without these adapters.

For tmux:

- use tmux control mode or structured `list-sessions`, `list-windows`, `list-panes` output;
- prefer stable session/window/pane IDs over names/indexes;
- use format strings rather than parsing human-oriented terminal output;
- avoid spawning a new `tmux` command every second; connect on demand or use a persistent control-mode client where appropriate;
- link the pane's shell/process group and descendants where safely discoverable.

For Zellij:

- use its documented plugin/session API when available or a supported, bounded introspection mechanism;
- Zellij's plugin API exposes session and pane structures, but requiring a custom user-installed plugin for simple process accounting would be excessive;
- keep the adapter optional and avoid modifying user sessions.

For `screen`, begin with process/session/process-group recognition. A deep window/session adapter is lower priority unless there is a stable machine-readable interface.

## 5.11 Cron and scheduled jobs

- Monitor `cron`/`crond` as daemons and `crontab` as a CLI execution.
- Attribute jobs through process ancestry, cgroup/unit where available, journal messages and known scheduler metadata.
- Support systemd timers separately; many modern systems use both cron and systemd timers.
- Do not indiscriminately read and store all crontab contents. They can contain credentials, URLs, internal paths and user-specific operational data.
- Add schedule-file parsing only as an explicit opt-in feature with permission checks and redaction.

## 5.12 Log-source architecture

A general Linux host needs more than Docker logs.

Possible sources:

1. Docker Engine logs.
2. journald via a supported journal API or read-only journal access.
3. Explicitly configured application log files.
4. Application structured event streams/instrumentation.
5. Optional integration-specific logs.

Do not scrape arbitrary filesystems or open every process's descriptors by default. File tailing must handle inode rotation, rename, truncate, permissions and bounded reads. Journal access must use cursors/monotonic and realtime timestamps where available.

---

## 6. Network observability

Network visibility has three levels with different costs and guarantees.

### Level 1 — Always-on accounting

- host interface bytes/packets/errors/drops from `/proc/net/dev`;
- per-container network counters from Docker/runtime APIs or namespace-aware collectors where available;
- deltas and rates rather than repeated cumulative storage;
- interface identity and network namespace identity.

This identifies which host interface or container generated traffic, but not necessarily which PID or URL.

### Level 2 — Optional connection/flow accounting

Possible data:

- source/destination IP;
- source/destination port;
- protocol;
- network namespace;
- process/cgroup attribution where reliable;
- connection start/end/duration;
- bytes/packets when an accounting source provides them.

Potential mechanisms:

- conntrack (`/proc/net/nf_conntrack` or netlink) where enabled and permitted;
- socket diagnostics (`NETLINK_SOCK_DIAG`/inet_diag);
- eBPF cgroup/socket hooks for richer process-to-flow association;
- application proxy APIs where available.

Limitations:

- conntrack may be unavailable, disabled or costly at high flow counts;
- `/proc/PID/fd` socket mapping is racy and may require permissions;
- basic socket diagnostics do not automatically provide every payload byte or application request;
- flow records are not URLs and do not reveal encrypted HTTPS paths/bodies.

Do not poll a large conntrack table every 5 seconds by default. Make it opt-in, rate-limited and bounded.

### Level 3 — Request-level application instrumentation

For services under the user's control, this is the preferred source for per-request observability.

Recommended structured request record:

```json
{
  "request_id": "01J...",
  "service": "fastapi",
  "method": "POST",
  "route": "/search",
  "status": 200,
  "duration_us": 18420,
  "response_bytes": 1536,
  "client_class": "internal",
  "upstream": "search-provider"
}
```

Use normalized route templates (`/users/{id}`) rather than raw paths where possible. Measure duration with a monotonic clock. Emit a correlation/request ID into logs and downstream calls. Instrument outbound HTTP clients when practical.

When structured instrumentation is unavailable, SARF may parse existing access logs as a best-effort fallback. For example, a Uvicorn access line such as `INFO: 172.32.0.10:53250 - "POST /search HTTP/1.1" 200 OK` can provide client, method, path and status. It does not inherently include request duration; do not fabricate latency from it. Application-specific timing logs can be correlated separately.

Do not collect request/response bodies, cookies, authorization headers, bearer tokens, API keys or secrets by default. Provide field allowlists, redaction and sampling.

### Correlation example

```text
CPU increase in cgroup: fastapi
  ├─ Process: uvicorn worker PID 412
  ├─ Request: POST /search, request_id=abc123
  ├─ Duration: 18.42 ms
  ├─ Outbound call: configured upstream service
  ├─ Application log: matching request_id
  └─ Host context: CPU PSI, steal, memory and I/O pressure
```

This is evidence of temporal and entity correlation, not automatic proof of causation.

---

## 7. Timestamps, sampling and the nanosecond question

### 7.1 Four distinct concepts

Do not conflate:

1. **Timestamp representation precision** — how many decimal places or integer units can be stored.
2. **Source clock resolution** — the actual resolution of the kernel/application clock.
3. **Measurement resolution** — what a counter reports (ticks, microseconds, bytes, event counts).
4. **Observation frequency/latency** — how often SARF samples or receives an event.

Storing an event as Unix nanoseconds does not mean the resource data is nanosecond-accurate. `/proc` CPU counters commonly use `USER_HZ` units; cgroup CPU usage is reported in microseconds; taskstats uses defined accounting units; and a periodic sampler cannot reconstruct a spike that begins and ends between samples.

### 7.2 Dual-clock model

Store both:

- wall-clock UTC timestamp for human reports and matching application logs;
- monotonic/boot-relative time for interval calculations, ordering and durations.

In Rust:

- `std::time::Instant` is appropriate for local elapsed-duration measurement.
- For persisted cross-source correlation on Linux, use a documented boot-relative monotonic clock source (e.g. `clock_gettime(CLOCK_MONOTONIC)`) and record the clock domain.
- Do not compare a monotonic timestamp directly with Unix wall time.
- Periodically estimate a wall/monotonic offset for report conversion, and tolerate wall-clock corrections.

Suggested timestamp columns:

```text
wall_ts_ns       INTEGER
mono_ts_ns       INTEGER
clock_domain     TEXT
source_ts_ns     INTEGER NULL
source_clock     TEXT NULL
```

Nanosecond storage is convenient for event alignment where sources have that precision; use microsecond units for actual counters when that is the source's resolution. Preserve the source unit and precision in metadata.

### 7.3 Sampling defaults

Use different cadences for different sources. Suggested starting defaults—not universal performance claims:

| Collector | Normal interval | Incident mode | Notes |
|---|---:|---:|---|
| Host `/proc` counters | 5 s | 250–1000 ms | Low-cost counters |
| cgroup v2 counters | 5 s | 250–1000 ms | Per selected service/container |
| Individual process samples | 5–10 s or selected/top-N | 250–1000 ms for selected targets | Avoid full high-rate scans |
| Process lifecycle source | Event driven | Event driven | Reconcile periodically |
| Docker events | Continuous stream | Continuous stream | Reconnect and reconcile |
| Docker inventory | 30 s / after events | Same | Do not inspect everything every tick |
| Logs | Continuous bounded streams | Continuous bounded streams | Backpressure and drop accounting |
| Interface counters | 5 s | 250–1000 ms | Per interface/namespace where supported |
| Conntrack/flow scans | Off by default | Explicit opt-in | High-flow hosts can be expensive |
| Application requests | Per request | Per request | Instrumented apps only |
| PSI | 5 s sample plus optional triggers | Event notification | Use kernel PSI monitors where available |

The initial Docker-only design used 5-second host/container stats, 30-second container discovery and inspection every 30 seconds or on health events. Retain these as fallback settings if direct cgroup discovery is unavailable.

### 7.4 Adaptive sampling

The normal mode should be intentionally quiet:

```text
NORMAL (e.g. 5 s)
   │
   ├─ absolute threshold crossed
   ├─ EWMA anomaly detected
   ├─ PSI trigger received
   ├─ process restart/OOM/unhealthy event
   └─ log flood / slow request event
            │
            ▼
INCIDENT MODE (e.g. 250–1000 ms for selected entities)
            │
            ├─ capture pre-event ring buffer
            ├─ sample affected cgroup/processes at higher cadence
            ├─ retain event/log/request context
            └─ stop after bounded timeout and recovery hysteresis
            │
            ▼
NORMAL MODE
```

Do not switch every collector on the entire host into 100 ms mode after one service spikes. Increase resolution only for the affected cgroup, relevant host context and related processes. Enforce a maximum incident duration, sample budget and database budget.

Adaptive mode cannot guarantee detection of every sub-sampling-interval spike. Event sources and kernel counters improve coverage, but nanosecond-wide observation is not a realistic promise for this architecture.

---

## 8. Process identity, entity graph and attribution

### 8.1 Stable process identity

Never use PID alone as a key. A recommended process key is:

```text
(host_boot_id, pid_namespace_identity, host_pid, start_time_ticks)
```

For tasks/threads, also retain TID and TGID. Track exec transitions separately:

```text
process_instance_id
exec_generation
exec_timestamp
executable_identity
```

A process may execute a new binary without changing PID. A PID may be reused after exit. Container PID namespaces mean the same process can have different PIDs from different namespace views; retain host PID and namespace PID when observable.

### 8.2 Entity types

- host;
- cgroup;
- systemd unit/slice/scope;
- container/runtime object;
- process;
- task/thread;
- terminal session/window/tab/pane;
- scheduled job/invocation;
- network namespace/interface;
- socket/flow;
- HTTP request;
- log source;
- incident.

### 8.3 Typed relationships

Use time-bounded relationships rather than assuming one permanent tree:

```text
SPAWNED_BY
MEMBER_OF_CGROUP
MANAGED_BY_SYSTEMD
RUNNING_IN_CONTAINER
ATTACHED_TO_SESSION
BELONGS_TO_JOB
USES_NETWORK_NAMESPACE
CONNECTED_TO
HANDLED_REQUEST
EMITTED_LOG
TRIGGERED_EVENT
```

Some relationships are direct and some are inferred. Store provenance and confidence for inferred edges.

A process may move between cgroups. Parent processes may exit and children may be reparented. A container may restart and receive a new process identity. A request may be handled by a worker process but not have a causal edge to every process active at the same time.

### 8.4 Attribution limits

The process graph is an evidence graph, not a complete causal graph.

- Shared page cache and shared memory complicate per-process memory attribution.
- Kernel threads, interrupts, softirqs and deferred kernel work do not always map cleanly to one user process.
- Host-wide storage or network work may be asynchronous and outlive the process that initiated it.
- A request and CPU spike occurring together do not prove causation.
- Request-level and function-level details need application instrumentation/profiling.

Reports must use wording such as **observed**, **associated**, **correlated**, **likely contributor** and **unknown** rather than claiming certainty without evidence.

---

## 9. Logging architecture

The logging system should be continuous where configured, but bounded and selective.

### 9.1 Per-source rolling buffers

Maintain a rolling buffer per container, service, process group or configured log source.

A starting default for a small system:

- maximum 1,000 lines per source;
- maximum 10 minutes of history;
- maximum 512 KiB per source;
- maximum per-line storage length, initially 512 characters for summaries (retain an optional bounded original line if policy allows);
- total global memory budget across all rings;
- configurable limits by source importance.

Use byte-based accounting as well as line count. A single very long line must not defeat a line-count limit.

### 9.2 Normalize each log record

Possible fields:

```text
source_id
entity_id
wall_ts_ns
mono_ts_ns
stream                 # stdout / stderr / journal / file / app
level
message
request_id
trace_id
sequence
source_cursor
truncated
redaction_flags
```

### 9.3 Persist selectively

Initial rules:

- persist ERROR/FATAL/PANIC/exception/traceback and configured critical patterns;
- persist selected WARN records based on policy;
- persist all bounded log records inside an incident evidence window;
- store log-rate anomaly summaries;
- store configured slow-request summaries;
- store only sampled INFO logs when explicitly configured;
- keep raw full logs in their original logging system where possible rather than duplicating all of them in SARF.

Useful patterns from the original proposal include `ENOSPC`, `OOM`, `Timeout`, `ConnectionRefused`, `unhealthy`, `Traceback`, `panic`, `FATAL`, `ERROR` and `WARN`. Pattern matching must be configurable and should use small deterministic matchers. Do not add a heavy regular-expression engine solely for a few fixed patterns.

### 9.4 Backpressure and fairness

This is mandatory.

- bounded queue per collector or bounded shared queue with per-source quotas;
- prioritize lifecycle, OOM, panic and incident markers above ordinary INFO logs;
- cap parsing work per event/line;
- cap line bytes and total retained bytes;
- use rate limits and token buckets for noisy sources;
- count dropped, truncated, sampled and delayed records;
- prevent one log-flooding container from starving all other sources;
- degrade by dropping/summarizing low-priority records rather than growing memory indefinitely;
- report evidence loss as part of incident metadata.

### 9.5 Docker log edge cases

- `none` driver means there is no Docker log stream to read.
- Remote logging drivers may not expose local logs if dual logging/cache is disabled.
- Applications may write directly to files instead of stdout/stderr.
- Docker's local log-driver files are daemon-managed; do not read or modify them directly.
- Rotated log reads can cause temporary disk and CPU costs; avoid scanning large archived logs during normal collection.

### 9.6 Application file logs

Support explicitly configured paths only. Use a robust file follower that handles rename rotation, inode replacement, truncation and partial lines. Never traverse the entire filesystem looking for `*.log` files.

---

## 10. Incident detection and correlation

### 10.1 Detection inputs

- host CPU/memory/load/PSI/steal;
- cgroup CPU, memory, I/O, throttling and pressure;
- process CPU/RSS/I/O and lifetime;
- process start/exec/exit events;
- Docker/systemd/session/scheduler events;
- log levels and rate anomalies;
- HTTP request latency/status/volume (when instrumented);
- network byte/flow observations;
- storage free space and database-health events.

### 10.2 Baselines

Use lightweight statistics, not an ML runtime.

For each entity/metric, maintain an EWMA mean and variance:

```text
mean = alpha * x + (1 - alpha) * mean
var  = alpha * (x - old_mean)^2 + (1 - alpha) * var
z    = (x - mean) / sqrt(var + epsilon)
```

Implementation detail: use the prior mean for the deviation update or choose a numerically stable equivalent; explicitly test startup, zero-variance and step-change cases.

- warm up a new service/metric before relying on relative anomalies;
- suppress relative alerts for near-zero baselines where percentage ratios become noisy;
- combine absolute thresholds with relative anomaly detection;
- require multiple samples for noisy metrics;
- use hysteresis to close incidents;
- maintain per-metric cooldowns and deduplication windows;
- separate real state transitions (OOM/exit) from statistical anomalies.

### 10.3 Starting absolute thresholds

These are configurable initial examples, not universal operating limits.

| Signal | Initial example |
|---|---|
| Host CPU (user + system + steal) | Above 10% for 3 samples |
| Container/service CPU | Above a configured service-specific threshold; 20% was an example in the original proposal |
| Memory | Above 80% of effective cgroup limit |
| CPU/memory/I/O PSI | Above configured percentage/stall-time threshold; calibrate per workload |
| Disk free | Below 15% |
| Restart/OOM/unhealthy | Immediate event |
| Error log rate | Baseline + 3 standard deviations and at least 5/minute |
| Critical log pattern | Immediate or high-priority event depending on pattern |
| CPU throttling | Increased throttled periods/time relative to baseline or quota context |

The earlier example used PSI `some avg10 > 10`. Since PSI averages are percentages, this should be a configurable starting threshold, not an unexamined universal rule. Consider cumulative total deltas and pressure triggers as well.

### 10.4 Incident evidence window

At incident opening:

- preserve approximately 60 seconds before the trigger from in-memory log/event rings;
- preserve host and relevant cgroup/process samples covering the same period;
- include process lifecycle changes and service/container events;
- include matching HTTP request IDs and network events if collected;
- include collector health and dropped-event counts.

At incident close:

- collect approximately 30 seconds after the trigger/recovery by default;
- retain a compact incident summary and references to underlying rows;
- cap individual evidence output, e.g. 256 KiB by default;
- deduplicate repeated incidents for the same entity/metric within a configurable window (five minutes was the original example);
- mark likely contributors with evidence and confidence rather than claiming proof.

### 10.5 Correlation output

A `sarf show <incident>` report should show:

1. incident trigger and time range;
2. host pressure and capacity context;
3. service/cgroup resource counters and quota/throttling;
4. top contributing processes and child process tree;
5. process/service/container lifecycle events;
6. matching application logs and request IDs;
7. network flows/requests if available;
8. collector gaps, permissions and dropped records;
9. likely contributors ranked by evidence;
10. facts SARF cannot determine.

Example wording:

```text
Likely contributor: cargo build process tree
Evidence:
- cgroup CPU rose from 2% to 68% of one core
- rustc children account for most observed process CPU
- build job began 2.1s before the spike
- host CPU steal remained low
- no memory PSI increase detected
Confidence: high temporal/resource association; causal proof not available
```

---

## 11. SQLite storage and retention

SQLite remains the recommended local database for one host, one writer and CLI/report queries.

### 11.1 Writer architecture

Do not run synchronous SQLite writes directly inside the current-thread Tokio event loop.

Recommended layout:

```text
Tokio current-thread runtime
  ├─ host/cgroup sampler
  ├─ process event source
  ├─ Docker/systemd event consumers
  ├─ bounded log streams
  └─ optional network/request collectors
             │
             ▼
       bounded typed channel
             │
             ▼
       one SQLite writer thread
             │
             ▼
         sarf.db (WAL)
```

A single dedicated writer thread is sufficient initially. Keep read queries short and separate from the writer connection. Avoid a general thread pool. If later profiling proves the architecture needs a different runtime, change it based on evidence.

### 11.2 Suggested logical tables

| Table | Purpose |
|---|---|
| `hosts` | Host identity, boot ID, kernel and architecture metadata |
| `entities` | Host, cgroup, unit, container, process, thread, session, job, interface, request and log-source identities |
| `relationships` | Typed, time-bounded entity relationships and provenance |
| `process_lifetimes` | Process creation, exec generations, exit, parent and executable identity |
| `process_samples` | Selected process/task CPU, RSS, I/O and state samples |
| `host_samples` | Host CPU, memory, swap, load, PSI, network and disk counters |
| `cgroup_samples` | cgroup CPU, memory, I/O, PIDs, pressure and throttling counters |
| `events` | Kernel, process, Docker, systemd, session, scheduler and integration events |
| `logs` | Selective important log entries with source/cursor and correlation IDs |
| `http_requests` | Optional structured request metadata and duration |
| `network_flows` | Optional connection/flow observations with source and confidence |
| `incidents` | Trigger, interval, summary, evidence references and acknowledgement |
| `rollup_1m` | Minute aggregates |
| `rollup_1h` | Hour aggregates |
| `collector_health` | Collector availability, errors, permissions, gaps and dropped records |
| `integration_state` | Installed/enabled integration versions, capabilities and last status |

### 11.3 Example SQL structure

This is a starter schema sketch, not a final immutable migration. Add indexes based on actual query plans and measurements.

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA page_size = 4096;
PRAGMA cache_size = -2000; -- about 2 MiB page cache

CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    boot_id TEXT NOT NULL,
    hostname TEXT,
    kernel_release TEXT,
    architecture TEXT,
    first_seen_wall_ns INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    labels_json TEXT,
    first_seen_wall_ns INTEGER NOT NULL,
    last_seen_wall_ns INTEGER NOT NULL,
    UNIQUE(kind, stable_key)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id INTEGER PRIMARY KEY,
    from_entity_id TEXT NOT NULL,
    to_entity_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    valid_from_mono_ns INTEGER NOT NULL,
    valid_to_mono_ns INTEGER,
    provenance TEXT NOT NULL,
    confidence REAL
);
CREATE INDEX IF NOT EXISTS relationships_from_time
    ON relationships(from_entity_id, valid_from_mono_ns);
CREATE INDEX IF NOT EXISTS relationships_to_time
    ON relationships(to_entity_id, valid_from_mono_ns);

CREATE TABLE IF NOT EXISTS process_lifetimes (
    process_instance_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    pid_namespace_id TEXT,
    host_pid INTEGER NOT NULL,
    namespace_pid INTEGER,
    tgid INTEGER,
    parent_instance_id TEXT,
    start_ticks INTEGER NOT NULL,
    exec_generation INTEGER NOT NULL DEFAULT 0,
    executable TEXT,
    comm TEXT,
    cgroup_entity_id TEXT,
    systemd_unit_entity_id TEXT,
    container_entity_id TEXT,
    start_wall_ns INTEGER NOT NULL,
    start_mono_ns INTEGER NOT NULL,
    end_wall_ns INTEGER,
    end_mono_ns INTEGER,
    exit_code INTEGER,
    exit_signal INTEGER,
    identity_quality TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS process_lifetimes_pid_start
    ON process_lifetimes(host_pid, start_ticks);
CREATE INDEX IF NOT EXISTS process_lifetimes_start
    ON process_lifetimes(start_wall_ns);

CREATE TABLE IF NOT EXISTS host_samples (
    mono_ts_ns INTEGER PRIMARY KEY,
    wall_ts_ns INTEGER NOT NULL,
    cpu_user_ticks INTEGER NOT NULL,
    cpu_nice_ticks INTEGER NOT NULL,
    cpu_system_ticks INTEGER NOT NULL,
    cpu_idle_ticks INTEGER NOT NULL,
    cpu_iowait_ticks INTEGER NOT NULL,
    cpu_irq_ticks INTEGER NOT NULL,
    cpu_softirq_ticks INTEGER NOT NULL,
    cpu_steal_ticks INTEGER NOT NULL,
    mem_total_bytes INTEGER,
    mem_available_bytes INTEGER,
    swap_total_bytes INTEGER,
    swap_free_bytes INTEGER,
    load1 REAL,
    load5 REAL,
    load15 REAL,
    psi_cpu_some_total_us INTEGER,
    psi_mem_some_total_us INTEGER,
    psi_io_some_total_us INTEGER,
    net_rx_bytes INTEGER,
    net_tx_bytes INTEGER,
    disk_read_bytes INTEGER,
    disk_write_bytes INTEGER
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cgroup_samples (
    mono_ts_ns INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    cpu_usage_usec INTEGER,
    cpu_user_usec INTEGER,
    cpu_system_usec INTEGER,
    cpu_nr_periods INTEGER,
    cpu_nr_throttled INTEGER,
    cpu_throttled_usec INTEGER,
    memory_current_bytes INTEGER,
    memory_peak_bytes INTEGER,
    memory_anon_bytes INTEGER,
    memory_file_bytes INTEGER,
    memory_events_json TEXT,
    io_stat_json TEXT,
    pids_current INTEGER,
    psi_cpu_json TEXT,
    psi_memory_json TEXT,
    psi_io_json TEXT,
    PRIMARY KEY(mono_ts_ns, entity_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cgroup_samples_entity_time
    ON cgroup_samples(entity_id, mono_ts_ns);

CREATE TABLE IF NOT EXISTS process_samples (
    mono_ts_ns INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    cpu_user_ticks INTEGER,
    cpu_system_ticks INTEGER,
    rss_bytes INTEGER,
    virtual_bytes INTEGER,
    read_bytes INTEGER,
    write_bytes INTEGER,
    read_chars INTEGER,
    write_chars INTEGER,
    threads INTEGER,
    state TEXT,
    sample_flags INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(mono_ts_ns, process_instance_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY,
    wall_ts_ns INTEGER NOT NULL,
    mono_ts_ns INTEGER,
    source_clock TEXT,
    entity_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT,
    payload_json TEXT,
    provenance TEXT NOT NULL,
    lost_before INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_entity_time ON events(entity_id, wall_ts_ns);
CREATE INDEX IF NOT EXISTS events_type_time ON events(event_type, wall_ts_ns);

CREATE TABLE IF NOT EXISTS logs (
    log_id INTEGER PRIMARY KEY,
    wall_ts_ns INTEGER NOT NULL,
    mono_ts_ns INTEGER,
    entity_id TEXT,
    source_id TEXT NOT NULL,
    stream TEXT,
    level TEXT,
    request_id TEXT,
    message TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    incident_id INTEGER
);
CREATE INDEX IF NOT EXISTS logs_entity_time ON logs(entity_id, wall_ts_ns);
CREATE INDEX IF NOT EXISTS logs_request_id ON logs(request_id);

CREATE TABLE IF NOT EXISTS http_requests (
    request_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    wall_ts_ns INTEGER NOT NULL,
    mono_start_ns INTEGER NOT NULL,
    duration_ns INTEGER NOT NULL,
    method TEXT,
    route TEXT,
    status INTEGER,
    request_bytes INTEGER,
    response_bytes INTEGER,
    upstream_label TEXT,
    sampled INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS network_flows (
    flow_id INTEGER PRIMARY KEY,
    entity_id TEXT,
    netns_id TEXT,
    protocol TEXT NOT NULL,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    start_mono_ns INTEGER,
    end_mono_ns INTEGER,
    rx_bytes INTEGER,
    tx_bytes INTEGER,
    rx_packets INTEGER,
    tx_packets INTEGER,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS network_flows_entity_time
    ON network_flows(entity_id, start_mono_ns);

CREATE TABLE IF NOT EXISTS rollup_1m (
    bucket_wall_ns INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    cpu_avg_pct REAL,
    cpu_max_pct REAL,
    cpu_total_usec INTEGER,
    memory_avg_bytes INTEGER,
    memory_max_bytes INTEGER,
    net_rx_bytes INTEGER,
    net_tx_bytes INTEGER,
    io_read_bytes INTEGER,
    io_write_bytes INTEGER,
    psi_cpu_max REAL,
    psi_memory_max REAL,
    psi_io_max REAL,
    PRIMARY KEY(bucket_wall_ns, entity_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS rollup_1h (
    bucket_wall_ns INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    cpu_avg_pct REAL,
    cpu_max_pct REAL,
    cpu_total_usec INTEGER,
    memory_avg_bytes INTEGER,
    memory_max_bytes INTEGER,
    net_rx_bytes INTEGER,
    net_tx_bytes INTEGER,
    io_read_bytes INTEGER,
    io_write_bytes INTEGER,
    PRIMARY KEY(bucket_wall_ns, entity_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS collector_health (
    collector_id TEXT PRIMARY KEY,
    configured_state TEXT NOT NULL,
    availability TEXT NOT NULL,
    permission_state TEXT NOT NULL,
    last_success_wall_ns INTEGER,
    last_error_wall_ns INTEGER,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,
    received_count INTEGER NOT NULL DEFAULT 0,
    persisted_count INTEGER NOT NULL DEFAULT 0,
    dropped_count INTEGER NOT NULL DEFAULT 0,
    truncated_count INTEGER NOT NULL DEFAULT 0,
    queue_high_water INTEGER NOT NULL DEFAULT 0,
    coverage_json TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS integration_state (
    integration_id TEXT PRIMARY KEY,
    configured_state TEXT NOT NULL,
    detected_state TEXT NOT NULL,
    version TEXT,
    capabilities_json TEXT,
    last_seen_wall_ns INTEGER,
    last_error TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY,
    started_wall_ns INTEGER NOT NULL,
    ended_wall_ns INTEGER,
    entity_id TEXT,
    metric TEXT NOT NULL,
    reason TEXT NOT NULL,
    peak REAL,
    baseline REAL,
    evidence_json TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    evidence_loss INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_start
    ON incidents(started_wall_ns);
```

Additional tables for network flows, 1-minute/hour rollups, integration state and collector health should be added as their corresponding features land. Keep JSON payloads bounded and use normalized columns for frequently queried fields.

### 11.4 Retention proposal

The original container-only proposal used:

- raw 5-second samples: 48 hours;
- 1-minute rollups: 14 days;
- 1-hour rollups: 90 days;
- incidents: 180 days;
- unattached/non-incident logs: up to 7 days;
- default DB hard cap: 200 MB.

Retain these as an initial profile for a host with modest container counts, but universal per-process sampling can grow much faster. Introduce per-table retention and per-entity budgets.

Suggested small-host profile:

- host/cgroup raw samples: 48 hours;
- selected process raw samples: 12–48 hours depending on volume;
- 1-minute rollups: 14 days;
- 1-hour rollups: 90 days;
- incident summaries: 180 days;
- logs: only selected records/incident windows, with a configurable cap;
- process lifecycle summaries: compact records retained longer than raw samples;
- default disk budget configurable, e.g. 50–200 MB depending on host capacity.

### 11.5 Storage growth estimate

The original estimate was:

```text
10 containers × 17,280 samples/day × approximately 100 bytes
≈ 17 MB/day
≈ 34 MB for 48 hours
```

This is a useful back-of-envelope estimate for a narrow container-sample row, not a guaranteed SQLite database size. Indexes, page layout, text payloads, WAL, log retention, process counts, and relationship/event churn add overhead. A universal per-process history may be much larger. Measure actual bytes per row and bytes written per workload.

### 11.6 SQLite WAL and vacuum rules

- WAL plus `synchronous=NORMAL` is a reasonable starting trade-off for telemetry.
- WAL creates a `-wal` file while the database is open and may have a `-shm` companion; count them in the disk budget.
- SQLite performs automatic checkpoints by default, but checkpoint starvation can occur when readers keep old transactions open. Keep read transactions short.
- `auto_vacuum=INCREMENTAL` must be planned before tables are created or require a rebuild/VACUUM migration. `incremental_vacuum` must be called to reclaim pages.
- Deleting rows does not automatically imply the DB file shrinks.
- Do not run large vacuum or checkpoint jobs during an incident or under heavy disk pressure.
- Keep one writer and use prepared statements and batch transactions.
- Bound the write queue. If the writer cannot keep up, record the loss/degradation and drop low-priority samples rather than exhausting RAM.
- Use `PRAGMA user_version` and explicit, tested schema migrations. Back up or preserve the old DB before destructive migrations.
- Count the main DB, `-wal`, `-shm`, temporary files and any report/export staging files against the configured disk budget.
- Under pressure, prune low-priority INFO logs and high-volume process samples first; then expire raw samples according to policy. Preserve compact incident summaries, process lifetime records, critical events and collector-loss records as long as the disk guard allows.

---

## 12. Runtime architecture and Rust implementation choices

### 12.1 One process, deliberately few threads

Recommended baseline:

- one Tokio current-thread runtime for asynchronous event streams and timers;
- one dedicated SQLite writer thread for synchronous database calls;
- no general worker pool;
- no permanent TUI thread;
- HTML report generation runs only when invoked;
- optional eBPF loader/runtime only when advanced mode is enabled.

This is technically two persistent threads, not one. The writer thread prevents synchronous SQLite work from blocking the event loop.

### 12.2 Dependency policy

Initial candidate dependency set (versions should be pinned via Cargo.lock and reviewed at implementation time):

```toml
[dependencies]
anyhow = "1"
bytes = "1"
clap = { version = "4", features = ["derive"] }
futures-util = "0.3"
log = "0.4"
env_logger = "0.11"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
time = { version = "0.3", features = ["formatting", "parsing", "macros"] }
tokio = { version = "1", features = ["rt", "macros", "time", "net", "signal", "sync", "io-util"] }
toml = "0.8"

# Optional features/dependencies should be added only when their adapters land:
# bollard for Docker API
# ratatui + crossterm for the configuration TUI
# zbus (or another reviewed D-Bus approach) for systemd integration
# aya / eBPF object for advanced kernel collection
```

Version values above reflect the original draft's illustrative dependencies. Check current compatible versions before implementation and pin them in `Cargo.lock`.

Avoid adding `sysinfo`, large regex engines, serde_yaml, OpenTelemetry SDKs, a web server, a full metrics stack or a second database without a demonstrated need. Direct `/proc` and cgroup parsers are small and deterministic.

Bollard is a useful safe Docker API client; do not replace it with a hand-written Unix HTTP client merely to shave dependencies until profiling shows it matters. A tiny custom client still has to handle HTTP framing, chunked responses, reconnects, versioning and error cases.

### 12.3 Compile profile

A reasonable release starting point:

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = true
panic = "abort"
```

Measure binary size, startup time and runtime overhead separately. Static linking is a portability decision, not automatically a runtime performance win. A musl target can be used where practical; validate all optional dependencies and BPF payload packaging against the target systems.

### 12.4 Project layout

Keep one crate and one main binary initially, but keep the modules explicit and cohesive:

```text
sarf/
├── Cargo.toml
├── Cargo.lock
├── AGENTS.md
├── skills/
│   └── ponytail/
│       └── SKILL.md             # vendor or reference the canonical skill
├── config/
│   ├── defaults.toml
│   └── integrations/
│       ├── arvancloud.toml
│       └── gapcode.toml
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── daemon.rs
│   ├── core/
│   │   ├── entity.rs
│   │   ├── identity.rs
│   │   ├── event.rs
│   │   ├── metrics.rs
│   │   └── capabilities.rs
│   ├── collectors/
│   │   ├── host.rs
│   │   ├── procfs.rs
│   │   ├── cgroup.rs
│   │   ├── process_events.rs
│   │   ├── taskstats.rs
│   │   ├── psi.rs
│   │   ├── network.rs
│   │   └── logs.rs
│   ├── integrations/
│   │   ├── registry.rs
│   │   ├── systemd.rs
│   │   ├── docker.rs
│   │   ├── tmux.rs
│   │   ├── zellij.rs
│   │   ├── cron.rs
│   │   ├── webservers.rs
│   │   ├── proxies.rs
│   │   ├── networking.rs
│   │   ├── development.rs
│   │   └── cloud.rs
│   ├── pipeline/
│   │   ├── bounded.rs
│   │   ├── normalize.rs
│   │   └── writer.rs
│   ├── storage/
│   │   ├── db.rs
│   │   ├── schema.rs
│   │   └── retention.rs
│   ├── analysis/
│   │   ├── ewma.rs
│   │   ├── incidents.rs
│   │   └── correlation.rs
│   ├── tui/
│   │   └── configure.rs
│   └── export/
│       ├── html.rs
│       └── process_graph.rs
└── tests/
    ├── fixtures/
    ├── parsers/
    ├── collectors/
    └── integration/
```

Do not create all these files on day one. The layout is the intended separation of responsibilities as features land. A small module is preferable to an empty abstraction or speculative framework.

---

## 13. TUI: `sarf configure`

The configuration interface should be easy to use but must not add runtime overhead when it is closed.

### 13.1 Suggested implementation

Use Ratatui with Crossterm as an on-demand TUI candidate. Ratatui provides terminal widgets and immediate-mode rendering. It is invoked only for `sarf configure`; the daemon does not render or retain the UI.

### 13.2 Suggested screens

**Integrations**

- categories and searchable tool catalog;
- installed / detected / running / supported / enabled statuses;
- global baseline state, which cannot be accidentally disabled;
- per-integration enrichment switch;
- per-integration collection depth;
- last successful collection and error state.

**Processes**

- currently running process inventory;
- filters by executable, cgroup, systemd unit, container, user and session;
- pin/unpin process groups for higher-detail sampling;
- distinguish process monitoring from integration enrichment.

**Collectors**

- `/proc`, cgroup v2/v1, PSI, process connector, taskstats, Docker, systemd, journald, network and eBPF;
- availability, permissions, kernel support and estimated/observed overhead;
- show when a collector is unavailable rather than silently falling back.

**Policies**

- sample intervals;
- adaptive sampling bounds;
- log ring budgets;
- retention and database size limits;
- redaction and privacy settings;
- incident thresholds.

### 13.3 Defaults

| Feature | Default |
|---|---|
| Host resources | ON |
| Universal process inventory | ON |
| Basic process lifetime/resource accounting | ON, bounded cadence |
| cgroup accounting | ON when available |
| Systemd mapping | AUTO when systemd is available |
| Container discovery | AUTO when supported runtime is available |
| Lifecycle events | AUTO when kernel permissions/interfaces allow |
| Taskstats | AUTO/optional after feature detection |
| Basic incident detection | ON |
| Selective critical log ingestion | ON for configured available sources |
| Detailed tmux/Zellij topology | OFF |
| HTTP request instrumentation | OFF until application opts in |
| Detailed flow inspection | OFF |
| Packet capture | OFF |
| eBPF | OFF |
| Full argv/environment capture | OFF |

### 13.4 Interaction model

Proposed keys:

```text
↑ / ↓      Navigate
Space      Toggle optional integration
Enter      Inspect integration/capabilities
/          Search
Tab        Change screen
S          Save configuration
R          Revert unsaved changes
Q          Quit
```

Before saving, show a concise diff and explain which collectors will start/stop. Configuration changes should be validated and written atomically. The daemon should reload supported settings safely or require an explicit restart for settings that cannot be hot-reloaded.

### 13.5 Example TUI concept

```text
SARF Monitor Configuration                         daemon: running
────────────────────────────────────────────────────────────────
[Integrations] [Processes] [Collectors] [Policies]

CORE MONITORING
  [ON]  Host resources                 CPU / memory / disk / PSI
  [ON]  Universal process inventory   All discoverable processes
  [ON]  Cgroup accounting              Per-service/container totals
  [AUTO] Systemd mapping               Units and cgroup ownership
  [AUTO] Container discovery           Docker / supported runtimes

OPTIONAL ENRICHMENT
  [OFF] tmux / Zellij                  Session, window and pane topology
  [OFF] HTTP / curl / wget             Request-level instrumentation
  [OFF] Build tools                    Cargo / rustc / pip / Git metadata
  [OFF] Proxy / VPN                    Tunnels and proxy-specific counters
  [OFF] Detailed network flows         Remote IP/port and connection events
  [OFF] eBPF advanced tracing          Kernel-level optional collection
  [ON]  Selective logs                 Bounded error and incident windows

↑ ↓ Navigate  Space Toggle  Enter Details  / Search  S Save  Q Quit
```

This is a functional layout proposal, not a completed UI implementation.

---

## 14. Interactive standalone HTML reports

HTML export should be a report-generation command, not a permanent web service.

### 14.1 Commands

```bash
sarf graph --since 1h --output incident.html
sarf graph --incident 42 --output incident-42.html
sarf graph --process <process-instance-id> --since 30m --output process.html
sarf graph --service fastapi --since 24h --output fastapi.html
```

### 14.2 Four coordinated views

1. **Process cascade/tree**
   - parent/child process relationships;
   - exec generations;
   - process lifetime bars;
   - service/cgroup/container/systemd/session associations;
   - collapse/expand and search.

2. **Resource timeseries**
   - CPU percentage and cumulative CPU time;
   - RSS/virtual memory with clear semantics;
   - cgroup current/peak/working-set context;
   - disk I/O bytes and operations;
   - network RX/TX and optional flow counters;
   - throttling and PSI timelines.

3. **Event/log/request timeline**
   - process fork/exec/exit;
   - container/systemd/session/scheduler events;
   - selected logs and application events;
   - request IDs, durations and statuses;
   - incident markers and evidence-loss annotations.

4. **Resource contribution view**
   - top processes/services by CPU time;
   - peak memory by cgroup/process with shared-memory caveats;
   - disk and network contributors;
   - treemap or ranked bar chart for selected interval.

### 14.3 Implementation constraints

- one HTML file;
- inline CSS and JavaScript;
- no CDN, remote fonts, external network calls or web server;
- SVG for process graphs and moderate node counts;
- Canvas for dense timeseries;
- lazy rendering and level-of-detail for large process trees;
- no loading the entire SQLite database into browser memory;
- serialize only the selected report window and relevant records;
- safe escaping of logs, arguments and labels (treat them as untrusted data);
- content security policy appropriate for a local `file://` artifact;
- optional redaction before export;
- warn before exporting secrets or internal infrastructure details;
- report generation must never run in the daemon's hot path.

SVG and Canvas are sufficient for the first version; do not add a large charting framework without profiling evidence. The HTML report is a forensic artifact, not a replacement for a live dashboard.

---

## 15. CLI design

Keep the CLI small and predictable. Proposed commands:

```text
sarf run [--config /etc/sarf.toml]          # run daemon
sarf init                                  # initialize database/config
sarf doctor                                # check kernel, /proc, cgroups, permissions, DB
sarf configure                             # on-demand TUI
sarf tools list                            # list known/detected integrations
sarf tools search <query>                  # search catalog
sarf tools show <integration>              # capabilities and collection status
sarf top [--since 1h] [--by cpu|mem|net|io] [--limit 15]
sarf processes [--since 1h] [--filter ...]
sarf tree [--process ...] [--service ...]
sarf incidents [--since 24h] [--service ...]
sarf show <incident-id>                    # evidence timeline
sarf logs <source> [--since 1h] [--grep ...]
sarf graph [--since 1h] --output report.html
sarf export [--since 24h] [--format csv|json]
sarf prune                                 # maintenance/retention
```

Useful additional diagnostics:

- `sarf status` — daemon and collector health;
- `sarf capabilities` — detected kernel/runtime capabilities;
- `sarf inspect <entity>` — entity metadata and relationship graph;
- `sarf benchmark` — run a bounded self-overhead check;
- `sarf gaps` — show missing permissions, dropped events and unavailable log/network sources.

Do not implement every command before the corresponding data model and use case exist.

---

## 16. Example configuration

An illustrative configuration. Final field names and defaults should be validated during implementation.

```toml
[general]
db_path = "/var/lib/sarf/sarf.db"
interval_secs = 5
process_interval_secs = 5
container_discovery_secs = 30
raw_retention_hours = 48
rollup_1m_days = 14
rollup_1h_days = 90
incident_retention_days = 180
max_db_mb = 100
max_wal_mb = 16

[process]
enabled = true
reconcile_secs = 30
lifecycle_events = "auto"       # off | auto | required
sample_all_processes = false
top_n_persistence = 20
store_arguments = false
store_environment = false
store_open_files = false

[cgroup]
enabled = true
prefer_v2 = true
allow_v1_fallback = true
sample_secs = 5

[taskstats]
enabled = "auto"
collect_exit_accounting = true
collect_delay_accounting = false

[events]
queue_capacity = 4096
high_priority_reserve = 256

[logs]
enabled = true
ring_lines = 1000
ring_minutes = 10
ring_bytes_per_source = 524288
max_line_bytes = 4096
persist_info_sample_percent = 0
persist_warnings = true
persist_errors = true
always_store_patterns = [
  "WARN", "ERROR", "FATAL", "PANIC", "Traceback",
  "ENOSPC", "OOM", "Timeout", "ConnectionRefused", "unhealthy"
]

[network]
interface_counters = true
container_counters = true
flow_mode = false
conntrack_mode = false
ebpf_mode = false

[adaptive]
enabled = true
incident_interval_ms = 500
max_incident_secs = 120
max_entities_high_resolution = 8

[thresholds]
host_cpu_pct = 10.0
service_cpu_pct = 20.0
memory_pct = 80.0
psi_some_pct = 10.0
disk_free_pct = 15.0
error_rate_per_min = 5

[integrations]
systemd = "auto"
docker = "auto"
containerd = "auto"
tmux = false
zellij = false
cron = "auto"
http_requests = false
proxies = false
cloud_cli_enrichment = false
```

The configuration should distinguish `false`, `true` and `auto` when an integration can be detected but may require permissions or optional dependencies.

---

## 17. systemd service and privilege model

The daemon should be independent of the application's Docker Compose stack and survive a `compose down`.

### 17.1 Suggested service skeleton

```ini
[Unit]
Description=SARF lightweight Linux activity recorder
After=local-fs.target
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sarf run --config /etc/sarf.toml
Restart=on-failure
RestartSec=5

User=sarf
Group=sarf

Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
CPUWeight=1
IOWeight=1
MemoryMax=32M
TasksMax=8

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/sarf

[Install]
WantedBy=multi-user.target
```

This is a starting hardening profile, not a universal drop-in. Test all required `/proc`, `/sys/fs/cgroup`, journal, D-Bus and socket permissions with the actual systemd version and kernel.

`Wants=docker.service` plus `After=docker.service` allows SARF to start even if Docker is unavailable; `Requires=docker.service` would contradict the desired behavior of continuing host monitoring when Docker is down.

`CPUWeight=1` and `IOWeight=1` are relative priorities under contention, not hard caps. Avoid `CPUQuota=2%` as an initial default. A `CPUQuota=2%` setting means at most 2% of one CPU's time, not 2% of all machine CPUs. It can cause sampling delays and event backlog if SARF reaches the cap. Add a quota only after measuring and proving that the system remains correct under throttling.

`MemoryMax=32M` is a safety limit, not a predicted RSS. Tune for the target device and ensure the daemon degrades gracefully before reaching it.

### 17.2 Network address families

A basic implementation using only local Unix sockets may need `AF_UNIX`. Process connector, taskstats, socket diagnostics and other Netlink collectors require `AF_NETLINK`. The systemd sandbox's `RestrictAddressFamilies` must match enabled collector capabilities. Do not copy an `AF_UNIX`-only policy into a build that expects Netlink to work.

### 17.3 Privileges

- Baseline `/proc` and cgroup reads should use the least privilege that works on the target host.
- Reading another user's `/proc/PID/io`, command line or file descriptors may be restricted.
- Docker socket access is root-equivalent and should not be granted casually.
- D-Bus/journald access should be read-only and documented.
- eBPF, packet/flow observation and some Netlink facilities may need additional capabilities or privileges that vary by kernel and mechanism.
- Use feature detection and `sarf doctor`; do not silently run with weaker coverage while claiming full visibility.

---

## 18. Security and privacy requirements

SARF will observe potentially sensitive operational data. Treat it as a security-sensitive local agent.

### 18.1 Default collection policy

- Do not store process environment variables.
- Do not store complete command-line arguments by default.
- Do not capture HTTP bodies, cookies, authorization headers or tokens.
- Do not capture TLS plaintext or attempt TLS MITM.
- Do not collect private keys or credential files.
- Do not inspect arbitrary open file descriptors continuously.
- Do not execute integration-defined shell commands.
- Do not expose a network listener by default.
- Redact common secret patterns and allow explicit source-level exclusions.

### 18.2 Data protection

- database directory default `0750`, owned by the SARF service account;
- database default `0640` or stricter, after deciding CLI reader group behavior;
- restrict HTML report permissions and warn before exporting sensitive records;
- make retention and deletion behavior explicit;
- do not allow log text to become executable HTML/JavaScript;
- escape all untrusted labels, messages, paths and command strings;
- record whether fields were redacted or truncated.

### 18.3 Failure safety

- SARF must never start/stop/reconfigure monitored services.
- Read-only collectors must remain read-only.
- If SQLite fails, keep a small bounded in-memory queue, retry with backoff, then drop low-priority samples with explicit loss counters.
- If Docker is unavailable, continue host/process/cgroup collection.
- If one log source floods, do not allow it to starve others.
- If disk is low (original example: under 500 MB free), stop or reduce raw samples/log writes, preserve a tiny incident/control budget, and report the storage guard.
- Never let SARF's own failure take down the monitored workload.

---

## 19. Collector coverage, loss accounting and degradation policy

A monitoring tool must be able to explain its own blind spots.

For each collector/source, retain:

- configured state: enabled / disabled / auto;
- detected state: available / unavailable / unknown;
- permission state: permitted / denied / partial;
- last successful observation;
- last error and error count;
- reconnect count;
- queue high-water mark;
- messages/records received;
- records persisted;
- records dropped, sampled or truncated;
- known event gap/reconciliation status;
- source clock and timestamp precision.

Example status:

```text
process_connector: available; 0 receive overflows observed
 taskstats: unavailable; kernel CONFIG_TASKSTATS not exposed
 cgroup_v2: active; cpu/memory/io controllers detected
 docker: unavailable; socket absent; host monitoring continues
 journald: partial; current user cannot read system journal
 network_flows: disabled by policy
```

No unavailable value should be serialized as zero. Use `NULL` plus a status/quality marker.

### Degradation priority

1. Preserve critical process/host lifecycle, OOM, restart and incident markers.
2. Preserve bounded error/fatal logs and selected incident evidence.
3. Preserve cgroup and host samples.
4. Preserve selected/top-N process samples.
5. Reduce or drop ordinary INFO logs and low-value process samples.
6. Report all loss, gaps and skipped samples.

---

## 20. Alternatives and why SARF should remain small

| Alternative | Why not as the core design |
|---|---|
| Prometheus + node_exporter + cAdvisor + Grafana | Powerful, but multiple services and more memory/storage/operational overhead than desired for a tiny VPS |
| Loki + Promtail | Duplicates or centralizes logs and can be storage-heavy for this use case |
| `docker stats` in a loop | Subprocess overhead, no process tree history, no robust correlation or incident evidence |
| `ps`, `top`, `htop`, `btop`, `sar` subprocess loops | Human-oriented tools, repeated process creation and parsing; useful for validation, not the daemon collector |
| Python/shell agent | Interpreter/startup/runtime overhead and more dependencies; not aligned with the single Rust binary goal |
| eBPF-only design | Rich but adds kernel/permission/BTF/CO-RE complexity; reserve it for advanced needs |
| Full OpenTelemetry Collector | Broad capability but more components and configuration than needed in the base profile |
| Full APM agent in every app | Valuable for request tracing, but not a universal host process monitor |
| Dynamic plugin system | More security, ABI, versioning and deployment complexity than static adapters/manifests in v1 |

Keep `sysstat`/`sar` as an independent host-level validation source during early deployment if it is already installed. Compare SARF's host CPU/steal metrics with `sar -u`; do not immediately delete an existing five-minute CSV or monitoring job. Disable it only after SARF has run reliably and comparisons are satisfactory.

---

## 21. Testing and validation plan

### 21.1 Unit tests

- `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/pressure/*`, `/proc/net/dev`, `/proc/diskstats`, `/proc/PID/stat`, `/proc/PID/status`, `/proc/PID/io` parsers;
- tricky `/proc/PID/stat` `comm` strings containing spaces and closing parentheses;
- counter wrap/reset/decrease and zero elapsed-time handling;
- cgroup v1/v2 parsers and missing controller files;
- cgroup path discovery through mountinfo and namespace paths;
- process identity and PID reuse;
- process exec generation and reparenting;
- taskstats version/attribute parser;
- process connector message parser and sequence/overrun handling;
- Docker stats CPU/memory formulas, cgroup v1/v2 differences and absent fields;
- Docker log multiplex framing and TTY/non-TTY behavior;
- RFC3339 timestamps and wall/monotonic conversion;
- log redaction/truncation/buffer accounting;
- bounded queue overflow/fairness/drop counters;
- EWMA startup/variance/hysteresis;
- incident open/close/deduplication and evidence caps;
- retention and database-size guards;
- HTML escaping and offline report generation;
- integration manifest validation and capability constraints.

### 21.2 Integration tests

- run on a real cgroup v2 host;
- compare host CPU with `sar -u` and independent kernel counters;
- compare Docker cgroup totals with `docker stats` within a defined tolerance;
- run 1, 5 and 10 containers;
- test a systemd service and a transient scope;
- run tmux and Zellij sessions and check mapping;
- start/stop/restart/OOM containers and units;
- execute thousands of short-lived commands and validate process lifecycle/taskstats capture;
- run a short-lived `curl`, `jq`, `rg`, `openssl`, `git`, `systemctl` and `cargo` child-process test;
- flood Docker/journald/file logs and verify bounded RAM and explicit drop counters;
- rotate and truncate application log files;
- test Docker `none`, `local`, `json-file` and a remote logging configuration where available;
- generate network traffic and compare RX/TX accounting;
- test unavailable Docker socket: host monitoring must continue;
- test inaccessible `/proc` fields and missing capabilities;
- test event socket overflow/reconnect and reconciliation;
- test low disk space and SQLite write failures;
- generate a self-contained HTML report and open it with networking disabled.

### 21.3 Load matrix

At minimum test:

| Workload | Variation |
|---|---|
| Processes | 20, 100, 500, 2,000 |
| Containers/services | 1, 5, 10, 25 |
| Process churn | low, moderate, bursty short-lived commands |
| Log volume | idle, 100 lines/s, 1,000 lines/s, burst flood |
| Network | idle, sustained traffic, high connection churn |
| CPU | idle, 50%, saturated, quota-throttled |
| Memory | stable, cache-heavy, reclaim pressure, OOM |
| Disk | idle, sequential write, random I/O, low free space |
| Event loss | small and constrained receive buffers, forced reconnects |

### 21.4 Acceptance criteria

Functional:

- universal process inventory observes new/removed processes and exec transitions;
- PID reuse does not corrupt history;
- taskstats/process event coverage and gaps are reported accurately;
- per-service/cgroup counters match trusted references within declared tolerances;
- Docker down does not stop host monitoring;
- log queues remain bounded under flood;
- incidents contain synchronized samples and bounded evidence;
- HTML reports are self-contained and safe to open offline;
- optional integrations do not break baseline monitoring when disabled/unavailable.

Performance:

- publish baseline CPU and RSS for each profile and workload;
- measure the daemon with and without SARF on the same host/workload;
- establish a target for average CPU, p95 burst and RSS on a named reference machine;
- target the original `<0.5%` average CPU / `<2%` burst / `10–20 MB` RSS as an initial baseline for a modest host;
- treat `<0.1%` average CPU as a stretch goal to validate under a specifically defined low-churn profile;
- no unbounded RAM, disk, queue or WAL growth;
- no unreported loss during stress tests;
- a 24-hour soak test plus high-churn process/log stress tests before declaring stable.

---

## 22. Implementation roadmap

Build the universal process and cgroup foundation before the advanced integrations. Avoid starting with HTML visualization, eBPF or a large integration catalog.

### Phase 0 — Repository and design constraints

**Deliverables**

- Rust crate and one executable;
- `AGENTS.md` and Ponytail-aligned project rules;
- architecture decision records for process identity, timestamps, cgroup discovery, storage, permissions and event sources;
- small benchmark harness;
- fixture-based parser tests.

**Done when**

- core data types are defined;
- dependencies are justified;
- the target host's cgroup/proc/permission capabilities are documented;
- no speculative plugin framework exists.

### Phase 1 — Host and cgroup v2 core

**Deliverables**

- host `/proc` sampler;
- cgroup v2 discovery and read-only CPU/memory/I/O/PID/PSI collection;
- stable host/cgroup entities;
- raw counter/delta calculations;
- SQLite schema, writer thread, bounded channel and basic retention;
- `sarf init`, `sarf doctor`, `sarf top`.

**Done when**

- host metrics compare with `sar`/trusted references;
- cgroup resource counters compare with Docker stats on a test host;
- synchronous DB work does not block event consumers;
- write and memory budgets are measured.

### Phase 2 — Universal process inventory

**Deliverables**

- `/proc` process discovery and reconciliation;
- process/thread identity and PID reuse handling;
- parent/child graph;
- executable identity and safe labels;
- selected/top-N process samples;
- process tree and process top CLI.

**Done when**

- short- and long-lived processes are not confused;
- parent identity is time-bounded;
- command arguments and environments are not stored by default;
- process scanning cost is benchmarked at increasing process counts.

### Phase 3 — Process lifecycle and taskstats

**Deliverables**

- optional process connector event source;
- optional taskstats exit accounting;
- Netlink receive-buffer/loss monitoring;
- source availability detection;
- reconciliation after event loss/reconnect;
- exec generations and exit summaries.

**Done when**

- short-lived process test suite captures a high percentage of executions and their exit accounting where supported;
- unavailable kernel features are reported;
- event loss is explicit and does not corrupt the process graph.

### Phase 4 — Docker and systemd adapters

**Deliverables**

- Docker discovery/events/logs/Stats API fallback;
- container-to-cgroup mapping;
- systemd D-Bus unit/job state and PID/cgroup mapping;
- journald integration as an optional configured source;
- service/container metadata and health events.

**Done when**

- daemon works if Docker is absent;
- Docker socket privilege implications are documented and tested;
- systemd data is obtained without repeated `systemctl` subprocesses;
- missing logging drivers/sources are correctly identified.

### Phase 5 — Logs and incident forensics

**Deliverables**

- bounded per-source log rings;
- Docker, journald and explicitly configured file log sources;
- severity/pattern rules;
- log flood detection and backpressure;
- EWMA/threshold incident engine;
- evidence window capture and `sarf show`.

**Done when**

- log floods cannot consume unbounded memory or starve other collectors;
- important incident evidence is retained;
- drops/truncation are visible;
- no causation claims are made from correlation alone.

### Phase 6 — Integration registry and TUI

**Deliverables**

- declarative integration catalog and capability model;
- universal process names/aliases;
- `sarf tools list/search/show`;
- `sarf configure` TUI built with Ratatui/Crossterm;
- default core/optional integration profiles;
- atomic config write and reload behavior.

**Done when**

- user can select/deselect enrichment without disabling universal process accounting;
- a new manifest can add simple recognition without core code changes;
- TUI adds no daemon overhead when closed.

### Phase 7 — Initial specialized adapters

Recommended order:

1. tmux;
2. Zellij;
3. cron/systemd timers;
4. common networking utilities and network namespace metadata;
5. Nginx/Caddy/Traefik metrics interfaces;
6. sing-box/Tailscale/proxy enrichment;
7. Cargo/rustc/Git/pip build execution grouping;
8. ArvanCLI and GapCode basic recognition/enrichment where APIs allow.

**Done when**

- adapters add useful metadata beyond universal process monitoring;
- adapters do not spawn persistent polling commands unnecessarily;
- every adapter has a capability/permission/coverage report.

### Phase 8 — HTTP request and network-flow observability

**Deliverables**

- optional structured application request schema;
- request/correlation IDs and FastAPI middleware example;
- outbound request instrumentation guidance;
- optional conntrack/socket diagnostics;
- network namespace/interface/connection entities;
- secret redaction and sampling.

**Done when**

- request data can be joined to logs/process/service timelines;
- no bodies or credential headers are collected by default;
- network flow overhead is measured and off by default.

### Phase 9 — Standalone HTML forensic reports

**Deliverables**

- report-window query builder;
- process cascade/tree;
- synchronized timeseries and event/log/request timeline;
- resource contribution view;
- embedded HTML/CSS/JS;
- safe escaping, redaction and file permissions.

**Done when**

- report opens offline without network access;
- large trees/timeseries remain usable through bounded data and lazy rendering;
- report generation runs only on demand.

### Phase 10 — eBPF and advanced collectors

**Deliverables**

- optional eBPF process/network collectors;
- BTF/CO-RE/privilege compatibility detection;
- embedded BPF object packaging if a single executable remains a goal;
- advanced process-to-socket attribution and selected kernel events.

**Done when**

- a concrete use case cannot be adequately served by the simpler collectors;
- supported kernels and privileges are documented;
- eBPF loss/queue health is visible;
- baseline mode works when eBPF is absent.

### Phase 11 — Stabilization and release

**Deliverables**

- 24-hour and multi-day soak tests;
- performance report for small and larger reference hosts;
- security review;
- upgrade/schema migration tests;
- installation/uninstallation scripts and systemd unit;
- release artifacts for target architectures;
- operator documentation.

---

## 23. Ponytail, SOLID and maintainability rules for coding agents

The user specifically wants the Ponytail agent skill applied. The canonical Ponytail skill describes a “smallest complete change” discipline: question whether a feature needs to exist, reuse the codebase, prefer the standard library/platform features, use existing dependencies before adding new ones, avoid unnecessary abstractions and scaffolding, but never remove validation, error handling, security or necessary tests. It defines `lite`, `full` and `ultra` levels. See the canonical [Ponytail skill](https://github.com/DietrichGebert/ponytail/blob/main/skills/ponytail/SKILL.md) and [compact AGENTS.md](https://github.com/DietrichGebert/ponytail/blob/main/AGENTS.md).

### 23.1 Project rules

- No abstraction without a real second implementation or a clear boundary requirement.
- No speculative plugin framework.
- No dependency for a few lines of standard-library/platform code.
- No repeated parsing of the same source when one normalized event can be shared.
- No duplicate collection of metrics already provided by cgroups.
- No permanent UI, web server or monitoring-side agent framework.
- No background shell subprocess loops.
- No arbitrary command execution in manifests.
- No unbounded queues, ring buffers, DB writes or HTML exports.
- No hidden fallback that silently reduces coverage.
- No storing credentials, environment variables or raw request bodies by default.
- Every collector must expose availability, permissions, errors and loss counters.
- Every new parser, state machine, data-loss path or security boundary gets a small targeted test.
- A shortcut must state its limitation and upgrade path.
- Keep modules small, but do not split one concept into many files merely to make the tree look architectural.

### 23.2 Applying SOLID pragmatically

| Principle | SARF application |
|---|---|
| Single Responsibility | Each collector reads one source; normalization/storage/analysis are separate responsibilities |
| Open/Closed | Add adapters and manifests without changing the universal collector |
| Liskov Substitution | Alternative process event sources preserve the same normalized lifecycle semantics |
| Interface Segregation | Small capability-specific traits; no giant all-purpose plugin interface |
| Dependency Inversion | Core entities/events do not depend on Docker, systemd, a specific DB query or an individual tool |

### 23.3 Agent workflow

Before coding, the agent must:

1. Read the relevant code and current project rules.
2. Identify the smallest complete scope and every caller, test, fixture, config and CLI surface affected.
3. Check whether the platform/kernel already exposes the needed data.
4. Check whether an existing dependency already solves the problem.
5. Explain new dependencies and abstractions before adding them.
6. Implement the smallest correct solution.
7. Add tests for non-trivial logic, parsers, data-loss paths and security boundaries.
8. Run formatting, linting and relevant tests.
9. State what was not tested and the remaining risks.

Do not interpret Ponytail as permission to omit correctness, security or error handling. The goal is less unnecessary code, not less engineering rigor.

---

## 24. Deployment and build plan

The initial target described in the original proposal is Ubuntu 24.04. Build on a compatible Linux build environment and deploy a prebuilt binary; do not compile on a low-resource VPS.

Example glibc build on a compatible host:

```bash
cargo build --release
strip target/release/sarf
```

If static portability is needed and dependencies support it, evaluate musl:

```bash
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
```

Validate the binary against the actual target kernel, libc, CPU architecture and optional features. eBPF object support can impose separate compatibility requirements even when the userspace executable is static.

Example deployment skeleton:

```bash
sudo install -m755 target/release/sarf /usr/local/bin/sarf
sudo useradd --system --home /var/lib/sarf --shell /usr/sbin/nologin sarf
sudo install -d -o sarf -g sarf -m0750 /var/lib/sarf
sudo install -m0644 sarf.toml /etc/sarf.toml
sudo install -m0644 sarf.service /etc/systemd/system/sarf.service
sudo systemctl daemon-reload
sudo systemctl enable --now sarf
sarf doctor
```

Do not add the `sarf` account to the Docker group as an assumed safe default. If Docker access is enabled, follow the security model described above.

### Rollout safety

1. Keep existing `sysstat` and the current CSV sampler.
2. Run SARF alongside them for several days.
3. Compare host CPU/steal and resource figures.
4. Compare cgroup/Docker counters.
5. Validate log and event capture under controlled test incidents.
6. Check RSS, CPU and DB/WAL growth.
7. Only after stability, disable redundant sampling jobs while keeping independent verification available.

---

## 25. Operational examples

### 25.1 Find which service caused a CPU peak

```bash
sarf top --since 1h --by cpu
sarf incidents --since 24h
sarf show 42
```

The incident report should include host pressure, cgroup throttling, per-process contributors and relevant logs/events.

A compact `sarf top` report should resemble:

```text
RANGE 1h
ENTITY                 CPU avg  CPU max  MEM max  NET RX  NET TX  IO R/W
fastapi                0.42%    7.8%     86 MiB   1.2 MB  3.4 MB  0/0
logo-updater           0.01%   15.7%     52 MiB     0 B     0 B   0/0
cargo-build            3.1%    68.0%    240 MiB  14 MB   2 MB    8/3 MB
```

Values are illustrative, not benchmark data.

### 25.2 Investigate a Rust build

```bash
sarf tree --service <build-service>
sarf graph --process <cargo-process-instance> --since 30m --output cargo-build.html
```

Expected graph:

```text
shell / CI job
  └─ cargo build
       ├─ rustc (crate A)
       │    ├─ rustc helper/thread group
       │    └─ linker
       ├─ rustc (crate B)
       └─ build script
```

The actual children depend on the toolchain/build configuration. SARF should display observed processes, not invent a build topology.

### 25.3 Investigate a short-lived command

```bash
sarf processes --since 10m --filter curl
sarf inspect <process-instance-id>
```

If process lifecycle events and taskstats are available, show start/exec/exit, elapsed time, exit code and task accounting. If unavailable, explicitly report that the process may have been missed by periodic `/proc` sampling.

### 25.4 Investigate an HTTP-related spike

```bash
sarf incidents --since 1h --service fastapi
sarf show <incident-id>
sarf graph --incident <incident-id> --output api-incident.html
```

Join request IDs, application logs, process/cgroup metrics and outbound request metadata only if the app has been instrumented.

### 25.5 Check why a source is missing

```bash
sarf doctor
sarf capabilities
sarf gaps
```

Show the missing permission/kernel feature/log driver or disabled integration; do not misrepresent a missing source as zero activity.

---

## 26. Decisions to lock before implementation

The following decisions should be recorded as architecture decision records and revisited only with evidence:

1. **Linux-first:** Linux host process/resource monitoring is the v1 scope.
2. **One binary:** one installable SARF binary; one daemon process; on-demand subcommands.
3. **cgroup v2 primary:** direct kernel accounting where available; Docker stats fallback/validation.
4. **Universal baseline:** all discoverable processes get baseline recognition; integrations only enrich.
5. **Event + reconciliation:** event-driven process discovery plus periodic `/proc` reconciliation.
6. **Taskstats optional:** use exit-time accounting for short-lived processes when kernel support exists.
7. **eBPF optional:** never required for baseline functionality.
8. **Bounded logs/queues:** no unbounded memory/disk path.
9. **SQLite local storage:** one writer thread, WAL, short readers, explicit retention.
10. **No permanent web UI:** TUI and HTML report are on-demand.
11. **Static adapters first:** no dynamic third-party plugin ABI in v1.
12. **Privacy-first:** argv/environment/body capture disabled by default.
13. **No causal overclaiming:** reports distinguish correlation from causation.
14. **Measured performance:** publish workload-specific benchmarks; do not promise 0.1% on every host.

---

## 27. Open questions and risks

These are engineering decisions that require prototype testing rather than speculative answers.

- Which minimum Linux kernel versions must be supported?
- Is cgroup v2 guaranteed on all target VPS deployments, or is v1 fallback required?
- Which host permissions are acceptable for process connector/taskstats/systemd/journald access?
- Should the default deployment target include Docker support, or should Docker integration be optional at compile time?
- How much per-process sample history is useful on a 256 MiB RAM / 5 GB disk VPS?
- Which taskstats fields are enabled on the actual VPS kernel configuration?
- What process event source is available in the VPS provider's kernel?
- How should namespace PID identities be resolved when containers use nested PID namespaces?
- Which systemd D-Bus crate/binding meets the binary-size and compatibility goals?
- Should HTML reports include raw command arguments only after explicit opt-in?
- Which integrations are worth implementing first based on tools actually installed and used?
- Does the first advanced networking feature use conntrack, socket diagnostics or eBPF? Benchmark before choosing.
- What database budget is acceptable on a 5 GB disk versus a larger VPS?
- What event-loss rate is acceptable, and how should loss be presented to the user?

---

## 28. Source references and research notes

Research checked on **16 November 2026**. Kernel APIs and project documentation evolve; re-check compatibility at implementation time. The sources below support the interface descriptions and limitations. Where a source describes a capability, SARF still has to verify that the target kernel/build/permissions actually expose it.

### Linux kernel and process accounting

1. [Linux kernel: Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) — authoritative cgroup v2 hierarchy, controller files, CPU accounting, memory, I/O and process membership.
2. [Linux kernel: PSI — Pressure Stall Information](https://docs.kernel.org/accounting/psi.html) — host PSI format, `some`/`full`, cumulative stall totals and pollable threshold triggers.
3. [Linux `proc_pid_stat(5)`](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html) — process stat fields and access restrictions.
4. [Linux `proc_pid_status(5)`](https://www.man7.org/linux/man-pages/man5/proc_pid_status.5.html) — human-readable process status, memory, thread and context-switch information.
5. [Linux `proc_pid_io(5)`](https://www.man7.org/linux/man-pages/man5/proc_pid_io.5.html) — per-process I/O counters and their semantics.
6. [Linux kernel process connector implementation](https://github.com/torvalds/linux/blob/master/drivers/connector/cn_proc.c) — event implementation, sequence handling and send behavior.
7. [Linux UAPI `cn_proc.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/cn_proc.h) — process connector event definitions.
8. [Linux scheduler tracepoints](https://github.com/torvalds/linux/blob/master/include/trace/events/sched.h) — fork, exec and exit tracepoint definitions.
9. [Linux kernel: Per-task statistics interface (taskstats)](https://docs.kernel.org/accounting/taskstats.html) — per-task/process statistics during task lifetime and on exit, process/thread-group accounting and Netlink flow control.
10. [Linux kernel: `struct taskstats`](https://docs.kernel.org/accounting/taskstats-struct.html) — taskstats field groups and kernel config requirements (`CONFIG_TASKSTATS`, `CONFIG_TASK_XACCT`, `CONFIG_TASK_DELAY_ACCT`).
11. [Linux kernel: Delay accounting](https://docs.kernel.org/accounting/delay-accounting.html) — task resource-wait delay measurements and configuration requirements.

### Docker and systemd

12. [Docker Engine API reference](https://docs.docker.com/reference/api/engine/version/v1.44/) — container stats endpoint, `stream=false`, `one-shot=true`, CPU formulas and cgroup v1/v2 field differences. Treat the API version shown as a reference; negotiate/confirm daemon API compatibility.
13. [Docker container stats CLI reference](https://docs.docker.com/reference/cli/docker/container/stats/) — stats semantics, memory cache handling and process/thread count note.
14. [Docker logging configuration](https://docs.docker.com/engine/logging/configure/) — logging drivers and limitations.
15. [Docker logging / `docker logs`](https://docs.docker.com/engine/logging/) — missing logs when applications write to files or remote driver behavior prevents local retrieval.
16. [Docker dual logging](https://docs.docker.com/engine/logging/dual-logging/) — local cache behavior and limits for remote logging drivers.
17. [Docker local logging driver](https://docs.docker.com/engine/logging/drivers/local/) — storage format is daemon-managed; avoid external access to internal log files.
18. [Docker Engine security](https://docs.docker.com/engine/security/) — daemon attack surface and trusted-user requirement.
19. [Docker post-installation](https://docs.docker.com/engine/install/linux-postinstall/) — explicit warning that Docker group membership grants root-level privileges.
20. [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control) — CPU quota/weight, memory accounting and cgroup controls.
21. [systemd D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) — Manager, Unit and job objects and metadata.
22. [systemd journal API](https://www.freedesktop.org/software/systemd/man/latest/sd-journal.html) — journal access and cursor-oriented reading APIs.

### Storage, runtime and TUI

23. [SQLite Write-Ahead Logging](https://sqlite.org/wal.html) — WAL files, checkpointing, concurrency and checkpoint starvation.
24. [SQLite PRAGMA documentation](https://www.sqlite.org/pragma.html#pragma_auto_vacuum) — auto-vacuum and incremental-vacuum behavior; initialization/migration considerations.
25. [Rust `std::time::Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html) — monotonic nondecreasing elapsed-time measurement and platform caveats.
26. [Tokio runtime documentation](https://docs.rs/tokio/latest/tokio/runtime/) — current-thread runtime behavior.
27. [Tokio `spawn_blocking`](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html) — why synchronous blocking operations should not run directly in asynchronous tasks.
28. [Ratatui documentation](https://docs.rs/ratatui/latest/ratatui/) — Rust terminal UI widgets, rendering model and Crossterm setup.
29. [Aya documentation](https://docs.rs/aya/latest/aya/) — Rust eBPF userspace library and BTF support.
30. [Aya CO-RE support status](https://aya-rs.dev/book/aya/co-re/support.html) — current Rust/BTF/CO-RE compatibility considerations; re-check as it evolves.

### Tool integrations and agent engineering

31. [tmux Control Mode](https://github.com/tmux/tmux/wiki/Control-Mode) — structured control-mode output, pane/window/session listing and subscriptions.
32. [Zellij plugin API type reference](https://zellij.dev/documentation/plugin-api-types.html) — session and pane metadata.
33. [Caddy metrics directive](https://caddyserver.com/docs/caddyfile/directives/metrics) — optional native metrics endpoint.
34. [sing-box Clash API](https://www.singbox.ai/wiki/configuration/experimental/clash-api/index.html) — optional local API/controller and authentication considerations.
35. [ArvanCloud CLI documentation](https://docs.arvancloud.ir/en/developer-tools/cli) — ArvanCLI command structure and service/subcommand pattern.
36. [ArvanCloud official CLI repository](https://github.com/arvancloud/cli) — official executable/repository identity.
37. [GapCode product and CLI documentation](https://gapgpt.app/gapcode) — public description of desktop/CLI operation and documented Linux installation route.
38. [Ponytail canonical skill](https://github.com/DietrichGebert/ponytail/blob/main/skills/ponytail/SKILL.md) — minimal-change/YAGNI/stdlib/platform-first discipline and safety carve-outs.
39. [Ponytail compact AGENTS.md](https://github.com/DietrichGebert/ponytail/blob/main/AGENTS.md) — concise project/agent rule set.

### Research boundary

- The documentation verifies the named interfaces and their stated semantics; it does not prove that every target VPS kernel enables them.
- The ArvanCLI and GapCode sources support basic executable/CLI recognition. They do not establish universal internal telemetry APIs for every cloud/AI operation.
- The TUI and HTML report designs are architectural recommendations, not claims about an already implemented product.
- Resource targets remain hypotheses until tested on the intended VPS size, kernel, number of processes/containers, log rate and storage device.

---

## 29. Final recommendation

Build SARF in this order:

1. **Host + cgroup v2 accounting.**
2. **Universal process inventory and identity.**
3. **Process lifecycle events plus taskstats for short-lived commands.**
4. **Docker and systemd adapters.**
5. **Bounded logs, incidents and evidence capture.**
6. **Integration registry and on-demand TUI.**
7. **Session, scheduler, network, proxy, web-server, build and cloud adapters.**
8. **Structured request correlation and optional network flows.**
9. **Offline interactive HTML process/resource forensics.**
10. **Optional eBPF after a measured need exists.**

The ideal implementation is not the one that permanently samples everything at the highest possible frequency. It is the one that:

- continuously records cheap kernel-maintained counters;
- recognizes all visible processes without requiring a catalog entry;
- captures lifecycle events and short-lived task accounting where supported;
- consumes logs in bounded buffers;
- enables rich adapters only when selected;
- raises observation detail only for the affected entities during an incident;
- preserves synchronized evidence in one local database;
- exposes the process/service/activity graph through a simple CLI, TUI and standalone HTML report;
- explains every known collection gap;
- measures its own overhead and degrades safely.

**SARF should answer: “Which service/process was doing what, how did the kernel account for its resource consumption, what events/logs/requests/flows coincided with it, and what evidence supports the likely explanation?”**

That is the product worth building.
