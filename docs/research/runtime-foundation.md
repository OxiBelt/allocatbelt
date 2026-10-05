# Resource-aware runtime foundation

Research milestone, 2026-10-04; verification updated 2026-10-05.
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
buffered frees are returned before parking. Native runtime matrix qualification
has not run; passing correctness checks is not performance evidence.

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
