# Cargo features

Cargo features decide which optional parts of allocatbelt are compiled into a binary. They are a ceiling, not a selection: which compiled part a process uses is decided at run time, by the embedding application and by what the system allows (single-package directive §5). `Allocatbelt::compiled_capabilities()` (`CompiledCapabilities::CURRENT`) reports what a build contains; `Allocatbelt::platform()`, `purge_backend()`, `io_uring_error()`, `maintenance_is_batch()` and `rseq_status()` report what the running system allowed and what is in use.

Every feature is additive: turning one on only adds code and API, so the union Cargo builds when several crates of one graph ask for different features is always valid. None needs nightly Rust, on any target. `scripts/check-features.sh` (CI job "Feature combinations") lints and tests each supported combination, and `scripts/check-package.sh` builds a consumer of the packaged crate with the defaults, with `default-features = false` and with each optional feature.

| Feature | Status | Default | Nightly | Compiles in | Selected at run time by | Where the system lacks it |
|---|---|---|---|---|---|---|
| `maintenance` | stable | yes | no | the background maintenance thread: `start_maintenance_thread`, `start_purge_thread`, `purge_backend`, `maintenance_is_batch`, `PurgeBackend` | `Allocatbelt::start_maintenance_thread()` | spawning fails: the call returns the error and allocating threads keep running housekeeping inline |
| `scheduler` | stable, implies `maintenance` | yes | no | `sched_setscheduler(SCHED_BATCH)` on the maintenance thread | starting the thread | the thread keeps the default policy; `maintenance_is_batch()` is `false` |
| `io-uring` | stable, implies `maintenance` | no | no | the restricted io_uring purge ring (`set_io_uring`, `io_uring_error`, `RingError`) and rustix's `io_uring` bindings | `Allocatbelt::set_io_uring(true)` before the thread starts; off otherwise, because it has not won in measurements (docs/research/benchmarks.md, Phase 8) | the thread purges with `madvise`; `purge_backend()` is `Madvise` and `io_uring_error()` names the failed step and errno |
| `experimental-rseq` | experimental | no | no | shard selection by the rseq `mm_cid` (`set_rseq_policy`, `rseq_status`, `mm_cid`, `RseqPolicy`, `RseqStatus`, `RseqUnavailable`); links glibc's `__rseq_offset` and `__rseq_size` (glibc 2.35+) | `Allocatbelt::set_rseq_policy(RseqPolicy::Prefer)` or `Require`; the default `Auto` does not select it | per-thread shards, as without the feature; `rseq_status().available` says why, and `Require` returns that error |

Without any feature (`default-features = false`) the allocator is complete: allocation, the per-thread caches, delayed purging with the dirty budget and hard limit, `purge()`, `request_purge()` (inline), guard pages, randomized placement and fork handling are the same in every build. What is missing is only the background thread, so the decay and budget passes run on the allocating threads, and idle memory is returned on the next allocator call instead of while the process sleeps.

## Not features

Allocator correctness and hardening cannot be compiled out (directive §5.3): out-of-band metadata, the double-free detection protocol, the page and segment ownership protocol, guard pages, fork handling, the start-up platform probes, abort-on-unwind in `GlobalAlloc`, and the core's atomic ordering. The platform contract (docs/platform.md) is not a feature either: on x86_64 every build needs `-C target-cpu=x86-64-v3` or newer.

No feature names are reserved ahead of code. NUMA and the experimental ISA paths the directive lists (`experimental-aarch64-sve`, `experimental-aarch64-sve2`, `experimental-riscv-rvv`) will be added when they have an implementation; until then no SIMD kernel is compiled into any build (`KernelSet::Baseline`), and `CompiledCapabilities` has no field for them.
