# Profiling: resource use and per-function cost

Tools for finding where the benchmarks (or any command, such as an OxiBelt build) spend CPU, memory, disk and network, and which functions spend it. They produce profiles of one run on one machine. They are not benchmark results: a profile goes into [benchmarks.md](benchmarks.md) only with its environment recorded (the `environment.txt` each run writes), and hosted CI runners only check that the tools work.

## Quick start

```sh
scripts/profile.sh                       # resource use of bench-system, bench-mimalloc, bench-allocatbelt
scripts/profile.sh --alloc allocatbelt perf faults   # CPU and page faults per function
scripts/profile.sh --only pairs --alloc allocatbelt all   # one workload, every installed tool
scripts/profile.sh resources perf -- ./target/release/oxibelt --config c.toml   # any command
scripts/profile.sh --help
```

Output goes to `target/profile/<UTC time>/` (or `--out DIR`), one directory per profiled binary, plus `environment.txt` (commit, kernel, CPU, rustc, options). The script builds with `cargo --profile bench`, which is `release` with debug info, so the tools can name functions and lines.

`--quick` runs a twentieth of each workload and a shorter idle wait. It is for smoke runs and for callgrind, which is slow; its timings mean nothing. `--only KEYS` runs only the named workloads (`single`, `local`, `small`, `pairs`, `idle`, `oversubscribed`, `aligned`, `region`); the benchmark binaries accept the same `--quick` and `--only` arguments when run directly.

`aligned` churns boxes aligned to 64 and 256 bytes. `region` exercises explicit
64-byte region allocations, chunk reuse after reset, and release. The explicit
region always uses allocatbelt, including in the system and mimalloc binaries;
those rows compare the same region implementation with different global
allocators, not three region providers.

## Modes

| Mode | Tool | What it answers | Files |
|---|---|---|---|
| `resources` (default) | `resource-profile` (this repository) | CPU, memory, disk, network, threads and context switches over the run, and per thread | `resources/samples.csv`, `threads.csv`, `threads-by-name.csv`, `summary.tsv`, `stdout.txt` |
| `perf` | `perf record` (CPU clock, DWARF call graphs) | Which functions use the CPU, by themselves and with their callees, per thread | `perf-self.txt`, `perf-inclusive.txt`, `perf-by-thread.txt`, `perf-callgraph.txt`, `perf.data`; `flamegraph.svg` with inferno |
| `faults` | `perf record -e page-faults` | Which functions make memory resident (every page fault is one sample) | `faults-by-function.txt`, `faults-callgraph.txt`, `faults.data` |
| `syscalls` | `strace -f -c` | System calls by time and count: memory (`mmap`, `madvise`, `munmap`), locks (`futex`), disk and network | `syscalls.txt` |
| `callgrind` | `valgrind --tool=callgrind` | Instructions per function, exact, self and inclusive, without perf permissions | `callgrind-self.txt`, `callgrind-inclusive.txt`, `callgrind.out` (open in KCachegrind) |
| `all` | every mode whose tool is installed | | |

A mode named on the command line fails when its tool is missing; under `all` it is skipped with a note.

**Optional tools.** `perf` (Linux `linux-tools` or `linux-perf` package; it needs `kernel.perf_event_paranoid` at 2 or below to profile your own processes), `strace`, `valgrind`, and from crates.io `rustfilt` (Rust's v0 symbol names, which older perf builds print mangled) and `inferno` (flame graphs):

```sh
cargo install rustfilt inferno
```

**callgrind cannot run `bench-allocatbelt`.** allocatbelt reserves a 64 GiB arena at start-up, which valgrind cannot map, so the run aborts with an allocation failure; the script reports it and goes on. Use `perf` for allocatbelt, and callgrind for the system allocator and mimalloc baselines.

## The benchmarks' own columns

### Resource-aware blocking runtime

The runtime matrix uses one binary per allocator and chooses the executor
at run time. It compares blocking jobs, not Tokio's async scheduling:

```sh
bash scripts/bench-runtime.sh --reps 12 --start warm --workers 4 --window 16 \
  --jobs 20000 --bytes 32768 --cpu-iters 1024 --out target/runtime-bench/matrix
bash scripts/bench-runtime.sh --quick --reps 1 --profile \
  --out target/runtime-bench/smoke
scripts/profile.sh perf -- ./target/release/bench-runtime-allocatbelt \
  --executor bounded --workers 4 --window 16 --jobs 20000 --bytes 32768 --cpu-iters 1024
```

`--allocs` and `--executors` select matrix entries. The script records fresh
processes in balanced Williams order, environment metadata, raw per-run files and
`results.tsv`; `--profile` adds the existing resource profiler to every run.
Profiled and unprofiled runs are different experiments: do not pool their times.
Use full balancing cycles (six repetitions for the full matrix). An occupied
output directory is refused, and every failed attempt retains a results row
and its raw output. Provenance hashes tracked changes and untracked contents.

Each binary validates completed count and deterministic checksum against a
sequential reference outside the timed job region. Output includes elapsed
time, throughput, user/system CPU, RSS, kernel peak RSS, faults and validation
columns. RSS/HWM are captured before the reference. Whole-process profiles
include construction, reference work and shutdown, unlike those job-region
columns. `job_work` is out of line to support function attribution.
`--start warm` waits for all configured workers before timing; cold mode is an
asymmetric startup experiment. The bounded runtime includes shard/cache park
hooks, unlike the plain Tokio blocking-pool baseline, so these are integrated
runtime comparisons, not isolated async-scheduler costs.

See [the contract](../runtime.md) and
[research report](runtime-foundation.md) for admission semantics, comparison
limits and results. No timing gate is enabled in hosted CI.

### Runtime allocation and rejection diagnostics

```sh
cargo build --release --locked -p allocatbelt-bench --bin bench-runtime-diagnostic
target/release/bench-runtime-diagnostic --workers 4 --jobs 512 --window 512 \
  --reject-iterations 100000
```

This separate binary wraps `System` to count requested Rust allocation layouts.
It reports construction and submission allocations, controlled-backlog p99
submission/start/work-completion times, and retained bytes for inline 4 KiB
results and returned cancellation tokens. Work completion is the closure's
timestamp, before admission release and result publication. These percentiles
describe this backlog workload, not application service latency.

Workers warm up before measurement. A gate holds the first jobs while the
driver fills the queue, then releases them together. Gate waits have a deadline
and cleanup releases blocked workers. The outstanding window must hold all jobs.
Use a larger window with the same job count to inspect sparsely used capacity.

Packet-release snapshots precede destruction of timing buffers. Runtime release
drops both the runtime and its handle. Token objects and their vector's backing
allocation are measured separately; surviving tokens also retain one shared
runtime identity. Counts describe requested heap bytes, excluding allocator
rounding, thread stacks and resident-memory effects. Use the resource profiler
for RSS and CPU measurements.

The optional rejection lane measures `Full`, `Closed`, `InvalidRequest` and
`InsufficientResources` independently, checking error priorities and returned
closure ownership. Compare identical diagnostic sources in fresh, balanced
baseline/candidate processes. Keep these observations separate from primary
throughput runs and from instrumented profiles.

### Allocator workloads

Each workload line of the benchmark binaries carries, after the time and `VmRSS`, the resources the process spent on that workload: user and system CPU time, minor and major page faults, and bytes read from and written to storage (`allocatbelt_profile::Usage`, from `/proc/self/stat` and `/proc/self/io`). These include every thread the workload started, exited ones too. The CPU times have the kernel's 10 ms resolution. Context switches are not among them: the kernel counts them per thread and drops a thread's count when it exits.

The workload threads are named (`local-churn`, `small-churn`, `producer`, `consumer`), so per-thread profiles (`threads-by-name.csv`, `perf-by-thread.txt`) tell them apart from the main thread and allocatbelt's maintenance thread (`allocatbelt-mnt`).

## `resource-profile`

```text
resource-profile [--interval-ms N] [--out DIR] [--root-only] [--] COMMAND [ARGS...]
```

Runs the command, reads `/proc` for it and every process descended from it (only the command with `--root-only`) every `N` ms (default 100), and exits with the command's exit code. It is built from `bench/profile` (`cargo build --release -p allocatbelt-profile`) and needs nothing but `/proc`.

`samples.csv` has one row per sample. Counters are cumulative from the start; `cpu_pct` (100 = one CPU), `rss_*`, `vm_kib`, `processes`, `threads`, `fds` and `sockets` are the values at that moment.

| Column | Source | Meaning |
|---|---|---|
| `cpu_user_s`, `cpu_sys_s`, `cpu_pct` | `stat` `utime`, `stime` | CPU time in user and kernel mode |
| `rss_kib`, `rss_anon_kib`, `rss_file_kib` | `status` `VmRSS`, `RssAnon`, `RssFile` | Resident memory; the heap is anonymous |
| `vm_kib` | `status` `VmSize` | Address space, including allocatbelt's reserved, never-touched arena |
| `minflt`, `majflt` | `stat` | Page faults without and with a disk read |
| `ctx_voluntary`, `ctx_involuntary` | per-thread `status` | Blocking (locks, sleeps, I/O) and preemption |
| `rchar`, `wchar`, `syscr`, `syscw` | `io` | Bytes and calls of `read`/`write`-like system calls on files, pipes and sockets |
| `read_bytes`, `write_bytes` | `io` | Bytes that reached storage (`write_bytes` less `cancelled_write_bytes`) |
| `fds`, `sockets` | `fd/` | Open descriptors, and those that are sockets |
| `net_*`, `lo_bytes` | `net/dev` | Network traffic of the whole network namespace, loopback apart |

`summary.tsv` (also printed to standard error) has the totals. Those without a suffix are exact: CPU time and page faults come from the profiler's counters for the children it waited for, and storage bytes from its own `io` file, which the kernel adds a waited-for child's to (the profiler's reads of `/proc` touch no storage). Those marked `_sampled` are the last or highest sample and miss what happened in the last interval. Those marked `_netns` cover the namespace.

### Limits

- **Network figures are not per process.** Linux keeps no per-process byte counts for sockets; `net/dev` counts every process in the namespace. Run the command in its own network namespace, or on an otherwise idle machine, to attribute traffic. `rchar`/`wchar` include socket reads and writes but also files and pipes.
- **Short-lived threads and processes can be missed.** A thread that starts and exits between two samples never appears in `threads.csv`; the totals in `summary.tsv` still include its CPU time and faults. Lower `--interval-ms` to see more, at more cost to the profiled machine.
- **Exited threads keep their last sampled values,** so their CPU time in `threads.csv` can be short by up to one interval.
- **CPU times have 10 ms resolution** (`USER_HZ` is 100 on x86_64, aarch64 and riscv64).
- **Peak RSS is sampled.** `root_vmhwm_kib` is the kernel's own high-water mark of the command, as last read; growth in the final interval is missed.
- **Reading `io` needs the same user** as the profiled process (or `CAP_SYS_PTRACE`); otherwise those columns stay zero.
