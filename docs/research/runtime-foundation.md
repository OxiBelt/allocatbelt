# Resource-aware runtime foundation

Research milestone, 2026-10-04. The [runtime contract](../runtime.md) describes
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

**Decision:** retain the allocator and scalar dispatch unchanged. Do not infer
that SIMD, alternate shard policy or a new runtime improves allocation from
this baseline. Native ARM64 and RISC-V throughput remains unmeasured.

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
