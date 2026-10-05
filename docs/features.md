# Cargo features

Cargo features decide which optional parts of allocatbelt are compiled into a binary. They are a ceiling, not a selection: which compiled part a process uses is decided at run time, by the embedding application and by what the system allows (single-package directive §5). `Allocatbelt::compiled_capabilities()` (`CompiledCapabilities::CURRENT`) reports what a build contains; `Allocatbelt::platform()`, `purge_backend()`, `io_uring_error()`, `maintenance_is_batch()` and `rseq_status()` report what the running system allowed and what is in use.

Every feature is additive: turning one on only adds code and API, so the union Cargo builds when several crates of one graph ask for different features is always valid. All features build on stable Rust. `experimental-riscv-rvv` uses stable naked assembly on riscv64 and compiles nothing on other targets. `scripts/check-features.sh` (CI job "Feature combinations") lints and tests each supported combination, and `scripts/check-package.sh` builds a consumer of the packaged crate with the defaults, with `default-features = false` and with each optional feature.

| Feature | Status | Default | Nightly | Compiles in | Selected at run time by | Where the system lacks it |
|---|---|---|---|---|---|---|
| `maintenance` | stable | yes | no | the background maintenance thread: `start_maintenance_thread`, `start_purge_thread`, `purge_backend`, `maintenance_is_batch`, `PurgeBackend` | `Allocatbelt::start_maintenance_thread()` | spawning fails: the call returns the error and allocating threads keep running housekeeping inline |
| `scheduler` | stable, implies `maintenance` | yes | no | `sched_setscheduler(SCHED_BATCH)` on the maintenance thread | starting the thread | the thread keeps the default policy; `maintenance_is_batch()` is `false` |
| `io-uring` | stable, implies `maintenance` | no | no | the restricted io_uring purge ring (`set_io_uring`, `io_uring_error`, `RingError`) and rustix's `io_uring` bindings | `Allocatbelt::set_io_uring(true)` before the thread starts; off otherwise, because it has not won in measurements (docs/research/benchmarks.md, Phase 8) | the thread purges with `madvise`; `purge_backend()` is `Madvise` and `io_uring_error()` names the failed step and errno |
| `experimental-aarch64-sve` | experimental, not measured | no | no | on aarch64 only: the decay pass's page-age scan compiled for SVE (`KernelSet::Sve`); nothing on other architectures | `Policy::experimental_isa = Prefer` or `Require`, on a CPU whose auxiliary vector reports SVE; `Auto` never selects it | the baseline kernels; `detected_capabilities().experimental_isa` says `unavailable (cpu features or thread permission)`, and `Require` makes `configure` fail |
| `experimental-aarch64-sve2` | experimental, not measured, implies `experimental-aarch64-sve` | no | no | on aarch64 only: the same scan compiled for SVE2 (`KernelSet::Sve2`) | as above, on a CPU that reports SVE2; preferred over SVE | the SVE kernel where SVE is reported, else the baseline |
| `experimental-riscv-rvv` | experimental, not measured | no | no | on riscv64 only: the decay pass's page-age scan in a stable naked assembly leaf with local V assembler option; the rest of the binary stays RV64GC; nothing on other architectures | `Policy::experimental_isa = Prefer` or `Require`, where `riscv_hwprobe` reports V on all online CPUs and `PR_RISCV_V_GET_CONTROL` allows it for the calling thread; `Auto` never selects it | the baseline kernels, as for SVE |
| `experimental-rseq` | experimental | no | no | shard selection by the rseq `mm_cid` (`set_rseq_policy`, `rseq_status`, `mm_cid`, `RseqPolicy`, `RseqStatus`, `RseqUnavailable`); links glibc's `__rseq_offset` and `__rseq_size` (glibc 2.35+); on musl it compiles but never reads `mm_cid` (allocatbelt registers no rseq area of its own, docs/platform.md) | `Allocatbelt::set_rseq_policy(RseqPolicy::Prefer)` or `Require`; the default `Auto` does not select it | per-thread shards, as without the feature; `rseq_status().available` says why, and `Require` returns that error |

## Run-time policy

`Allocatbelt::configure(Policy)` selects, within what a build contains, what a process uses; `Policy` has one `FeaturePolicy` per capability:

| `FeaturePolicy` | Meaning |
|---|---|
| `Auto` (default) | the allocator's qualified default for that capability (below) |
| `Prefer` | use it where the system allows, fall back safely elsewhere |
| `Require` | use it or fail: `configure` returns `PolicyError::NotCompiled` for a capability the build lacks, and the operation that sets it up returns `PolicyError::Unavailable` (with the failed step and errno) where the system refuses it |
| `Disable` | never use it |

| Field | `Auto` | Applied | After the maintenance thread started |
|---|---|---|---|
| `scheduler` | ask for `SCHED_BATCH`, keep the default policy if refused (qualified in plan Phase 7) | when the maintenance thread starts; `Require` makes `start_maintenance_thread` fail if the kernel refuses | frozen: `configure` returns `PolicyError::Frozen` |
| `io_uring` | `madvise`: the ring has not won in measurements (Phase 8) | when the maintenance thread starts; `Require` makes `start_maintenance_thread` fail if the ring cannot be set up | frozen |
| `rseq` | off: experimental, not qualified | at once; `Require` makes `configure` fail where `mm_cid` cannot be read | switchable at any time (shard hints are only a preference) |
| `experimental_isa` | off: the baseline kernels (the experimental ones are not measured) | at once, by the next decay pass; `Require` makes `configure` fail where no experimental kernel is compiled in (`NotCompiled`), the CPU lacks its extension or the calling thread cannot use it (`Unavailable`, step `cpu features or thread permission`) | switchable at any time (every kernel set computes the same results) |

Lifecycle: allocations before `configure` (including those before `main`) run under `Policy::DEFAULT`, and nothing `configure` does changes how an existing allocation is laid out or owned. `configure` is allocation-free and applies the whole policy or nothing: the policy and the maintenance thread's phase share one atomic word. `start_maintenance_thread` freezes `scheduler` and `io_uring`; when a `Require`d one cannot be made effective, it returns an `io::Error` of kind `Unsupported` that wraps the `PolicyError`, no thread runs, and the policy stays open. The purge delay stays adjustable at any time with `set_purge_delay`.

The earlier setters are kept as shorthands of the same policy, so there is one mechanism: `set_io_uring(true)` is `io_uring = Prefer` and `false` is `Auto` (it now returns `Result<(), PolicyError>`, `Frozen` once the thread started, where it used to be ignored silently), and `set_rseq_policy` sets `rseq` (`RseqPolicy` is now another name for `FeaturePolicy`).

## Diagnostics

- `compiled_capabilities()`: what the build contains (`CompiledCapabilities`).
- `detected_capabilities()`: what this process found (`DetectedCapabilities`): the start-up probe, the CPU features, and per capability an `Availability`: `NotCompiled`, `NotTried`, `Available` or `Unavailable { step, errno }`, as the syscall reported it (an `EPERM` is reported as such, not interpreted).
- `effective_profile()`: what is in use (`EffectiveProfile`): the policy, whether it is frozen, whether the maintenance thread runs and as `SCHED_BATCH`, the purge backend, rseq shard selection, and the kernel set (`Baseline`, or `Sve`/`Sve2` when selected).
- `report()`: all three; its `Display` renders them for logs:

```text
allocator: allocatbelt 0.1.0
kernel: 7.0.0
guard_markers: true, getrandom: true
cpu_features: {"x86-64-v3", "avx2", "avx512f", ...}
kernel_set: Baseline
policy_frozen: true
maintenance: compiled=true detected=available effective=true
scheduler: compiled=true policy=auto detected=available effective=true
io_uring: compiled=true policy=prefer detected=unavailable (setup, errno 1) effective=false
rseq: compiled=false policy=auto detected=not compiled effective=false
experimental_isa: compiled=false policy=auto detected=not compiled effective=false
purge_backend: Madvise
```

The three queries are allocation-free; formatting the report allocates in the caller.

Without any feature (`default-features = false`) the allocator is complete: allocation, the per-thread caches, delayed purging with the reclamation thresholds ([reclamation.md](reclamation.md)), `purge()`, `request_purge()` (inline), guard pages, randomized placement and fork handling are the same in every build. What is missing is only the background thread, so the decay sweeps and budget cycles run on the allocating threads, in bounded slices, and idle memory is returned on the next allocator call instead of while the process sleeps.

## Not features

Allocator correctness and hardening cannot be compiled out (directive §5.3): out-of-band metadata, the double-free detection protocol, the page and segment ownership protocol, guard pages, fork handling, the start-up platform probes, abort-on-unwind in `GlobalAlloc`, and the core's atomic ordering. The platform contract (docs/platform.md) is not a feature either: on x86_64 every build needs `-C target-cpu=x86-64-v3` or newer.

No feature names are reserved ahead of code. NUMA and the RISC-V path the directive lists (`experimental-riscv-rvv`) will be added when they have an implementation, and `CompiledCapabilities` has no field for them until then.

## Experimental ISA kernels

The SVE and SVE2 kernels (directive Phase F) and the RVV kernel (Phase G) do one allocator operation: the age scan of a decay pass, which decides which free dirty pages of a segment have waited the purge delay (`since[i] <= cutoff` for the 64 pages). It is the operation `bench/simd` measured as `age` / `age-meta`; plan Phase 5 did not promote a kernel for it, and that decision stands: these kernels are experimental opt-ins, not a default, and **no benchmark was run for them**.

- **Selection:** compiled in (the feature, on its architecture) ∩ detected (`AT_HWCAP` SVE, `AT_HWCAP2` SVE2; on riscv64, V in `riscv_hwprobe` for all online CPUs and current-thread ON permission from `PR_RISCV_V_GET_CONTROL`) ∩ `experimental_isa` `Prefer` or `Require` = selected (`kernel_set()`). Failed queries and any current state other than ON select the baseline. RVV checks permission again when executing its guarded wrapper; a stored kernel pointer cannot grant another thread permission. Before the allocator's first allocation, and under `Auto` or `Disable`, it is `Baseline`.
- **Semantics:** the core first takes a private snapshot of the 64 ages with one atomic load each; the kernel only reads that copy, never the shared metadata with vector loads (directive §10.2). Every kernel returns exactly what the portable loop `core::aged_pages` returns, so switching at any time changes no allocation, purge or ownership decision.
- **Code:** the SVE/SVE2 kernels compile the portable loop inside target-feature functions. The RVV leaf uses stable naked assembly with `.option arch,+v` scoped to that function; its `vsetvli` strip-mines the 64-element snapshot at the hardware's actual VLEN. It uses no global `-C target-feature=+v`, which could let the compiler place V instructions elsewhere in the binary.
- **Checks:** unit tests compare each kernel with the portable loop on edge and random inputs; a model test runs decay passes through the snapshot path and checks they purge exactly what the portable scan purges; `tests/experimental_isa.rs` checks selection, `Require` failures and decay with the kernel selected. `scripts/check-experimental-isa.sh` (CI job "Experimental aarch64 SVE/SVE2 kernels") runs them natively on the arm64 runner and under qemu CPU models without SVE (Cortex-A72), with SVE (Neoverse V1) and SVE2 (Neoverse N2), and at vector lengths of 128, 512 and 2048 bits. `scripts/check-experimental-rvv.sh` (CI job "Experimental riscv64 RVV kernel (stable)", on Rust 1.99.0) lints the RVV build, checks with `llvm-objdump` that V instructions appear only in the kernel, and runs the tests under qemu with VLEN 128, 256 and 1024, and without V (skipped where the cross C library itself needs V).

The [full-system RISC-V guest](../scripts/riscv-guest/README.md) additionally
checks the Linux 7.0 baseline and real thread-local V permission, including
fresh-exec V-off policy, a saved kernel used across OFF/ON threads and a denied
permission query. The guest requires these scenarios to execute and validates
their results against the current source and executable hashes.
