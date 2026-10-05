# Resource-aware runtime foundation

Research milestone, 2026-10-04; verification and native runtime matrix updated
2026-10-05.
The [runtime contract](../runtime.md) describes
what is implemented and what remains outside scope. No result here establishes
that allocatbelt is generally faster than secure mimalloc or that the job
runtime can replace Tokio.

## Initial allocator baseline

Source: allocator revision `b9a42a2`, unchanged by the runtime milestone.
Both hosts ran Linux `7.0.0-38-generic`, x86-64-v3 builds, native instructions
inside KVM guests with 14 exposed vCPUs. Process affinity was CPUs 0–7.
Five fresh-process pairs alternated secure mimalloc and allocatbelt using the
existing `--only local` workload (not `--quick`). Allocatbelt used its existing
maintenance-thread configuration. Hosts were measured separately.

| Guest CPU | Rust | allocatbelt median ms | secure mimalloc median ms | Median paired time ratio |
|---|---|---:|---:|---:|
| AMD engineering sample, family 25/model 116 | 1.98.1 | 93.0 | 88.7 | 1.135 |
| AMD Ryzen 7 PRO 8845HS, family 25/model 117 | 1.99.0 | 83.5 | 83.1 | 0.960 |

The last column is the median of per-pair allocatbelt/mimalloc ratios, not a
ratio of the independent medians. Pair ratios ranged from 0.726 to 1.319 on
the first guest and 0.680 to 1.179 on the second. This spread is substantial;
five short pairs do not qualify a performance improvement. Frequency, physical
host scheduling and background activity were not controlled. Different
toolchains also preclude direct comparison of absolute times across hosts.

Resource counters show a retention/fault tradeoff under the binaries' existing
policies, not matched reclamation settings:

| Guest model | Allocator | Median user/system ms | Median peak RSS KiB | Median minor faults |
|---|---|---:|---:|---:|
| 116 | allocatbelt | 480 / 130 | 50,828 | 40,290 |
| 116 | secure mimalloc | 490 / 120 | 460,620 | 574 |
| 117 | allocatbelt | 460 / 110 | 49,908 | 36,105 |
| 117 | secure mimalloc | 510 / 100 | 458,580 | 607 |

Peak RSS is the process's kernel high-water mark; CPU counters have 10 ms
resolution. The local-churn workload touches only part of each allocation.
These numbers are not a fully resident working-set comparison and do not
establish a general memory-efficiency advantage.

**Decision:** retain the allocator and scalar dispatch unchanged. Do not infer
that SIMD, alternate shard policy or a new runtime improves allocation from
this baseline. Native ARM64 and RISC-V throughput remains unmeasured.

Software `cpu-clock` sampling at 199 Hz also ran on each guest, with DWARF
call graphs. Each short local-churn profile contained only 109 samples and no
reported lost samples. `dealloc_cached` had about 16.5% and 22.0% self samples;
`CachedBlocks::holds` had about 10.1% and 3.7%. These are low-resolution leads
for a longer profile, not reliable per-call cost measurements or evidence for
an optimization. Unprivileged perf was blocked by `perf_event_paranoid = 4`;
privileged recording worked without changing that system setting. The raw
root-owned perf files could not be downloaded with the available permissions.

## Experiment design

The runtime benchmark crosses two executors (bounded job runtime and Tokio's
blocking pool) with three allocators (system, secure mimalloc and allocatbelt).
Jobs use the same deterministic function, fully touch their working buffers,
and validate completed count and aggregate checksum against a sequential
reference. Fixed workers and an identical FIFO outstanding window apply to
both executors. The reference and runtime construction are outside job timing,
but whole-process resource and per-function profiles include them.

Compare a worker-sized outstanding window and a larger window as policy
variants. Neither changes an allocator algorithm. Report each configuration
and host independently, preserve unsuccessful or slower variants, and do not
promote a default from a single throughput number. This first workload is CPU
and memory work; disk/network admission tests are not disk/network performance
evidence, and the benchmark does not measure async scheduling or I/O reactors.

The default warm mode requires all configured workers to be running warm-up
jobs simultaneously before it begins timing. The full six-entry matrix uses
six-repetition Williams balancing cycles. Cold mode is an asymmetric startup
experiment and is not used for steady-state qualification.

Results compare integrated blocking runtimes, including admission, worker
lifecycle and allocator-cache/shard hooks; they do not isolate scheduler
superiority. The bounded runtime assigns shards and flushes caches before
parking; the plain Tokio blocking-pool baseline does not install those hooks.

## Native runtime matrix

Source: signed commit `91d9dfa026b5e3ea7ffd3d307cec7b3b718958c1`; the allocator
algorithm and instruction dispatch are unchanged from the baseline above. The
same two guests ran it: Linux `7.0.0-38-generic`, native x86-64-v3
instructions in KVM with 14 exposed vCPUs, affinity CPUs 0–7. Guest model
116 used Rust 1.98.1 and model 117 used Rust 1.99.0. The source was
transferred as a hash-checked bundle; on each guest the checked-out commit
matched the signed local commit byte for byte, the checkout was clean before
and after, and the recorded source SHA-256 was
`656e15338356bfd6d10af7d2071ca6e814f9850add31ef8a8eb0f1090e51089b`. Each
collector invocation built fresh native binaries (no `--bin-dir`). After the
runs, the three benchmark executables and `resource-profile` on each guest
were rehashed independently and matched every recorded artifact manifest.
Executable and build-info hashes are kept with the raw run records outside
this repository.

Workload: warm start, 4 workers, 20,000 jobs, 32,768 fully touched bytes and
1,024 CPU iterations per job. Every run matched the sequential reference
checksum `447862912158047136` and count 20,000. The primary matrix ran windows
4 and 16, each as six repetitions (one Williams cycle) of the six
allocator/executor variants on each guest: 144 valid fresh-process runs, with
no failed attempts. A separate profiled window-16 collection added 36
resource-profile rows per guest (72 total); those runs are not pooled with
the primary timings.

Reproduce from the repository root with the same configuration:

```sh
taskset -c 0-7 bash scripts/bench-runtime.sh --reps 6 --start warm \
  --workers 4 --window 4 --jobs 20000 --bytes 32768 --cpu-iters 1024
taskset -c 0-7 bash scripts/bench-runtime.sh --reps 6 --start warm \
  --workers 4 --window 16 --jobs 20000 --bytes 32768 --cpu-iters 1024
taskset -c 0-7 bash scripts/bench-runtime.sh --reps 6 --start warm \
  --workers 4 --window 16 --jobs 20000 --bytes 32768 --cpu-iters 1024 \
  --profile
```

The script builds with `cargo build --profile bench --locked`; the `bench`
profile is `release` with debug info. Output defaults to an untracked
directory under `target/runtime-bench/`.

Job wall time, ms (median [min, max] of six runs) and the bounded/Tokio
ratio (median [min, max] of six paired ratios):

| Guest model | Window | Allocator | Bounded | Tokio | Paired bounded/Tokio |
|---|---:|---|---:|---:|---:|
| 116 | 4 | system | 168.2 [165.8, 173.0] | 178.6 [176.2, 182.2] | 0.94 [0.91, 0.98] |
| 116 | 4 | secure mimalloc | 166.9 [164.6, 171.9] | 178.8 [177.6, 183.1] | 0.94 [0.91, 0.96] |
| 116 | 4 | allocatbelt | 167.6 [167.0, 172.4] | 179.7 [177.6, 183.4] | 0.94 [0.91, 0.95] |
| 116 | 16 | system | 136.6 [134.6, 137.4] | 134.4 [132.7, 138.7] | 1.02 [0.98, 1.03] |
| 116 | 16 | secure mimalloc | 136.6 [134.1, 143.0] | 134.9 [130.9, 136.5] | 1.02 [1.00, 1.05] |
| 116 | 16 | allocatbelt | 137.5 [135.4, 140.2] | 139.0 [134.5, 142.4] | 0.99 [0.97, 1.03] |
| 117 | 4 | system | 159.7 [157.4, 169.7] | 176.5 [174.8, 178.0] | 0.91 [0.88, 0.96] |
| 117 | 4 | secure mimalloc | 162.3 [159.7, 168.9] | 178.1 [176.4, 180.0] | 0.91 [0.89, 0.96] |
| 117 | 4 | allocatbelt | 162.7 [158.1, 165.2] | 179.5 [175.9, 180.2] | 0.91 [0.88, 0.92] |
| 117 | 16 | system | 131.1 [130.2, 134.6] | 129.6 [126.2, 133.5] | 1.02 [0.98, 1.04] |
| 117 | 16 | secure mimalloc | 130.2 [127.8, 131.4] | 127.5 [126.7, 133.0] | 1.02 [0.96, 1.03] |
| 117 | 16 | allocatbelt | 132.2 [130.8, 133.7] | 131.0 [128.0, 132.4] | 1.01 [1.00, 1.04] |

Each paired ratio divides the bounded run by the Tokio run with the same
allocator and repetition number. The two runs are in the same balanced
cycle but not necessarily adjacent. The last column is not a ratio of the
independent medians. Each window is one full balanced cycle per guest, and
the runs are short (127–183 ms). Frequency, physical host scheduling and
background activity were not controlled, and the guests used different
toolchains, so the hosts are reported separately and not aggregated.

Window-16 resource medians from the unprofiled primary runs (job-region CPU
and fault counters; CPU counters have 10 ms kernel resolution). Peak RSS is
the kernel high-water mark captured before the sequential reference:

| Guest model | Allocator | Executor | User / system ms | Peak RSS KiB | Minor faults |
|---|---|---|---:|---:|---:|
| 116 | system | bounded | 545 / 25 | 3,598 | 36 |
| 116 | system | Tokio | 535 / 20 | 3,584 | 35 |
| 116 | secure mimalloc | bounded | 545 / 25 | 10,214 | 49 |
| 116 | secure mimalloc | Tokio | 540 / 20 | 10,114 | 14 |
| 116 | allocatbelt | bounded | 545 / 25 | 4,146 | 95 |
| 116 | allocatbelt | Tokio | 555 / 20 | 4,156 | 80.5 |
| 117 | system | bounded | 530 / 20 | 3,590 | 36 |
| 117 | system | Tokio | 520 / 20 | 3,580 | 35 |
| 117 | secure mimalloc | bounded | 520 / 25 | 10,188 | 47 |
| 117 | secure mimalloc | Tokio | 510 / 20 | 8,136 | 27 |
| 117 | allocatbelt | bounded | 530 / 25 | 4,156 | 102 |
| 117 | allocatbelt | Tokio | 525 / 20 | 4,170 | 80 |

Every run in the matrix reported zero major faults.

With a window of 4, the bounded runtime's median paired ratios were
0.91–0.94: about 6–9% lower integrated job runtime than the Tokio blocking
pool for this workload. With a window of 16 the executors were near parity
(0.99–1.02), with small reversals in favor of Tokio. The window change
shifted every variant's time far more than the allocator or executor choice
did. These results do not isolate scheduler quality, say nothing about async
Tokio tasks or I/O, and do not generalize to other workloads, hosts or
production use.

No consistent allocatbelt speedup over secure mimalloc appeared under the
same executor; allocatbelt's medians were equal or slightly higher, mostly
within overlapping ranges. Its lower peak RSS than secure mimalloc came with
more minor faults, under each binary's existing configuration rather than
matched purge policies. It is not a general RSS or memory-efficiency claim.

## Resource-profile scope

An independent reviewer checked the separate window-16 profiled collection:
36 rows per guest, with no rows mixed into the primary timings.
`resource-profile` sampled at 100 ms, giving 7 samples per run on model 117
and 8 on model 116. Samples cover the whole process, including warm-up, the
sequential reference and shutdown, so they are coarser than the job timings
above. Median whole-process CPU was 1.03–1.07 s user on model 116 and
0.99–1.005 s user on model 117, with 0.015–0.03 s system. Peak sampled thread
counts were 5 for system and secure mimalloc and 6 for allocatbelt, including
its maintenance thread. No sampled sockets or loopback traffic appeared.
Storage reads were 0 bytes and writes 4,096 bytes in every run, with zero
major faults. Occasional network-namespace counters reflected background
traffic, not job network performance. A 100 ms sampler can miss short-lived
threads and peaks between samples.

## Per-function sampling leads

Software `cpu-clock` sampling at 199 Hz with DWARF call graphs (16,384-byte
stack dumps) ran on each guest with the same qualified binaries, using warm
start, 4 workers, window 16, 100,000 jobs, 32,768 bytes and 1,024 CPU
iterations. Every completed run matched count 100,000 and reference checksum
`16461914320422589141`. The benchmark ran unprivileged as a child while the
recorder was privileged; no system setting was changed. Profiles cover the
whole process, including the sequential reference, so they do not isolate
scheduler time or give per-call costs.

| Guest model | Completed profiles | Samples | `job_work` self samples |
|---|---:|---:|---:|
| 116 | 6 of 6 | 1,034–1,049 | 73.49–78.72% |
| 117 | 4 of 6 | 991–1,003 | 74.97–76.08% |

On model 117, recording failed for system with Tokio and secure mimalloc with
the bounded runtime. That is a coverage gap in the recording tool, not a
benchmark failure; those variants have no function profile on that guest.
Every completed profile validated its count and checksum and reported zero
lost samples. Every report also emitted an `Invalid HEADER_EVENT_DESC`
warning (`nre=1 sz=144 (min 64)`); its effect was not established. Raw event
attributes corroborate the sampling settings, but that does not establish
that the warning is harmless. Reports also note missing build-ID metadata.
The results are therefore exploratory leads, not cost measurements or proof
that unwinding was correct. Raw recordings, record logs and command-grouped
reports are kept outside this repository. Command-name grouping combines
identically named workers; it is not individual-thread attribution. Each
variant has only one recording, with no repeated-profile uncertainty estimate.

The deterministic job function dominates reported self samples in every
completed profile, including substantial sequential-reference work. These
profiles do not justify changing allocator/runtime defaults or ISA dispatch,
and instrumented timings are not primary performance comparisons.

## Verification scope

On Rust 1.98.1, workspace formatting, warnings-denied all-target/all-feature
clippy and release tests passed, including 44 runtime unit tests, two real
allocator integration tests, one runtime doctest and 13 benchmark tests.
All 11 allocator feature combinations and the package/clean-consumer checks
passed. RustSec checks passed with cargo-audit 0.22.2; dependency advisory, ban,
license and source checks passed with cargo-deny 0.20.2. Existing allocator core
loom checks passed all 15 models on unchanged allocator source; three runtime
loom models passed.

The current cleanup-identity correction preserves per-runtime cleaner marks
across nested cleanup and retains worker identity through thread-local
destruction at exit. Five direct regressions cover nested cleanup, exit-time
joins, guard unwind restoration, concurrent cleaner identities and identifier
exhaustion. The allocator integration test checks that both claimed blocks and
buffered frees are returned before parking. The native runtime matrix above
has run on both x86_64 guests at the recorded source revision; its scope is
the measured configuration only, and passing correctness checks is not
performance evidence.

Runtime loom checks share the actual start-state and admission helpers but
hand-model queue, worker, cancellation and close transitions. They do not
verify condvar parking, result publication, real allocator integration or
arbitrary user destructors. Deterministic thread tests and global-allocator
integration tests cover those paths separately; this is not complete formal
scheduler verification.

The script's fixture tests validate ordering, provenance, parameter handling
and retention of failed attempts. Their stand-in binaries are not performance
evidence. Native measurements must use built binaries from the recorded
source and retain executable hashes and build metadata.

Container, platform/ISA and rseq verification scripts were not rerun for this
milestone; qemu-user, cross targets and the required nightly toolchain are not
installed locally. Allocator source, unsafe boundaries, features and platform
gates are unchanged. Core Miri and bits/class mutation checks are not applicable
to these runtime-only logic changes.
