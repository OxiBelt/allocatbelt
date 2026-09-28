# Single-package directive: baseline at `33dfc7b` (Phase A)

Date: 2026-09-28. This records the state the single-package directive (project file `allocatbelt-general-purpose-single-package-directive.md`, §20 Phase A) starts from, before any restructuring: `research/rust-allocator` at `33dfc7b` ("test: wait for maintenance passes to be counted, not just to purge"), the head after plan phases 1–8, which the directive names as its starting point. The old plan's Phase 9 landed right after it as an off-by-default experiment (`450d960`, section 5). This change adds only this file and a link to it: no code, manifest or CI change.

Later phases compare against the figures below. A count or API item that changes must be explained in the commit that changes it.

## 1. Correctness suite

Local runs: Linux 6.18.44 VM with 4 vCPUs, Rust 1.98.1 (the CI toolchain; `rust-version = "1.98"`), x86_64 with the x86-64-v3 floor from `.cargo/config.toml`.

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean |
| Lints | `cargo clippy --all-targets --all-features --locked -- -D warnings` | clean |
| Tests | `cargo test --release --all-features --locked` | all pass: 100 run, 3 ignored (table below) |
| loom | `RUSTFLAGS="--cfg loom" cargo test --release --locked -p allocatbelt-core --lib loom` | all 13 models pass (203 s) |
| Platform gates | `scripts/check-platform-gates.sh` | pass: supported targets build, the others fail with the gate's message |
| Scalar ISA lowering | `scripts/check-scalar-isa.sh` | pass: `tzcnt`/`popcnt`/`lzcnt` on x86-64-v3, `ctz`/`cpop`/`clz` on riscv64 + Zbb, none in the rv64gc control build |

Tests per binary (`cargo test --release --all-features --locked`):

| Package | Binary | Passed | Ignored |
|---|---|---:|---:|
| allocatbelt-core | lib (model tests, 256 random `fuzz_programs`) | 63 | 1 (`contention_benchmark`) |
| allocatbelt-sys | lib (arena, probe, io_uring ring) | 6 | 1 (`ring_benchmark`) |
| allocatbelt-arch | lib | 6 | 0 |
| allocatbelt-arch | `tests/allocation_free.rs` | 1 | 0 |
| allocatbelt | `tests/global.rs` | 8 | 0 |
| allocatbelt | `tests/fork.rs`, `hardening.rs`, `maintenance.rs`, `purge_thread.rs` | 1 each | 0 |
| allocatbelt | `tests/platform.rs` | 2 | 0 |
| allocatbelt-simd-bench | lib (scalar reference checks) | 9 | 0 |
| allocatbelt-codegen-probes | lib | 1 | 0 |
| allocatbelt | doc test (the `#[global_allocator]` example) | 0 | 1 (`ignore`) |

CI on `33dfc7b` ([run 25](https://github.com/OxiBelt/allocatbelt/actions/runs/36439313300)) passed every job that ran: Rust checks on x86_64 and arm64 (fmt, clippy, tests, SIMD smoke run, io_uring report), riscv64 tests under qemu-user (rv64gc and rv64gc + Zbb), loom, platform gates, scalar ISA lowering, dependency admission (`cargo audit`, `cargo deny`) and core mutation testing (mewt 4.0.0).

Not covered at this baseline:

- **cargo-fuzz** runs only on `schedule` and `workflow_dispatch`, and GitHub runs scheduled workflows from the default branch (`main`, which holds only the licence), so it has not run on this branch in CI. The same interpreter runs as the `fuzz_programs` property test (256 programs per test run).
- **Miri** last ran on `0271678` (docs/unsafe-boundary.md, "Miri result"); not on this head.

## 2. unsafe inventory

Counted with `grep -rnE "unsafe (\{|fn|impl)"` over `src` directories, excluding comments and `#[cfg(test)]` modules; every site carries `#[expect(unsafe_code, reason = …)]` and a `// SAFETY:` comment. Per-site reasons are in [docs/unsafe-boundary.md](../unsafe-boundary.md).

| Crate | File | Blocks | `unsafe fn` | `unsafe impl` | Total |
|---|---|---:|---:|---:|---:|
| allocatbelt-core | all | 0 | 0 | 0 | **0** (`#![forbid(unsafe_code)]`) |
| allocatbelt-sys | `lib.rs` | 15 | 4 (`Region::purge`, `decommit`, `guard`, `guard_markers`) | 2 (`Send`/`Sync` for `Region`) | 21 |
| allocatbelt-sys | `platform.rs` | 5 | 0 | 0 | 5 |
| allocatbelt-sys | `ring.rs` | 10 | 1 (`PurgeRing::purge`) | 0 | 11 (+10 in its tests) |
| allocatbelt-arch | `x86_64.rs`, `aarch64.rs`, `riscv64.rs` | 1 + 2 + 1 | 0 | 0 | 4 |
| allocatbelt | `lib.rs` | 6 | 4 (`GlobalAlloc` methods) | 1 (`GlobalAlloc`) | 11 |
| **Production total** | | 43 | 9 | 3 | **52** |
| allocatbelt-simd-bench (benchmark only) | `kernels/x86_64.rs`, `kernels/aarch64.rs`, `perf.rs` | | | | 33 |

Test-only `unsafe` outside `src`: `allocatbelt-arch/tests/allocation_free.rs` (7 sites, a counting allocator), `allocatbelt/tests/fork.rs` and `global.rs` (one file-level `allow` each: `fork`/`alarm`/`_exit`/`waitpid`, and the raw `GlobalAlloc` API).

## 3. Public API of `allocatbelt`

Everything a user of the crate can name at this baseline (`crates/allocatbelt/src/lib.rs`):

- `struct Allocatbelt` (unit struct; `Debug`, `Clone`, `Copy`, `Default`) with `unsafe impl GlobalAlloc` (`alloc`, `alloc_zeroed`, `dealloc`, `realloc`) and these methods, all taking `self`:
  - allocation: `allocate(Layout) -> Option<NonNull<u8>>`, `usable_size(NonNull<u8>) -> usize`;
  - memory return: `purge()`, `set_purge_delay(Duration)`, `request_purge()`, `dirty_bytes() -> usize`, `segments_in_use() -> usize`;
  - maintenance: `start_maintenance_thread() -> io::Result<bool>`, `start_purge_thread() -> io::Result<bool>` (the old name), `maintenance_stats() -> MaintenanceStats`, `maintenance_is_batch() -> bool`;
  - io_uring: `set_io_uring(bool)`, `purge_backend() -> PurgeBackend`, `io_uring_error() -> Option<RingError>`;
  - diagnostics: `platform() -> Option<Capabilities>`, `cpu_features() -> CpuFeatures`, `kernel_set() -> KernelSet`.
- `enum PurgeBackend { NotStarted, Madvise, IoUring { sq_rewind: bool } }` (exhaustive).
- Re-exports: `CpuFeatures`, `KernelSet` (`#[non_exhaustive]`, only `Baseline`) from allocatbelt-arch; `MaintenanceStats` (eight public `u64` counters) from allocatbelt-core; `Capabilities` (`kernel`, `guard_markers`, `getrandom`), `KernelVersion` (`major`, `minor`, `patch`) and `RingError` (`step`, `errno`) from allocatbelt-sys.
- No Cargo features (the only one in the workspace is allocatbelt-core's `model`, the test mock and fuzz interpreter). All five library crates are `publish = false` through `[workspace.package]`, and `allocatbelt` depends on the others by path.

## 4. Confirmed behaviour

| Property | Where it holds | Evidence |
|---|---|---|
| `KernelSet::Baseline` everywhere | `allocatbelt_arch::initialize_dispatch` publishes `Baseline` unconditionally; `kernel_set` decodes only `Baseline` | `tests/platform.rs::dispatch_is_initialised_with_the_arena`, `allocation_free.rs` |
| io_uring off by default | `USE_IO_URING` starts `false`; the maintenance thread builds a ring only after `set_io_uring(true)`, and without a maintenance thread allocating threads purge with `madvise` | `tests/maintenance.rs` enables it explicitly; Phase 8 decision in [benchmarks.md](benchmarks.md) |
| Maintenance semantics | No thread unless `start_maintenance_thread` is called (then `SCHED_BATCH` if allowed, futex sleep until work or the next decay deadline). 32 MiB dirty budget (`DIRTY_BUDGET_PAGES = 512`), 64 MiB hard limit that makes frees purge inline, 1 s default purge delay, batches of up to `PURGE_BATCH = 64` runs | `tests/maintenance.rs`, `purge_thread.rs`, core `tests.rs` |
| Platform gates | `compile_error!` for non-Linux, non-64-bit, big-endian, other ISAs and x86_64 below v3; start-up probe of reservation, commit, `MADV_DONTNEED` and zero-after-purge | `scripts/check-platform-gates.sh`, `tests/platform.rs::probe_ran_before_the_first_allocation` |
| Safe core | `allocatbelt-core` is `#![no_std]` and `#![forbid(unsafe_code)]` | section 2 |

Performance thresholds are not part of this baseline (directive §18); the latest measurements are in [benchmarks.md](benchmarks.md) and [simd-benchmarks.md](simd-benchmarks.md).

## 5. Since the baseline: Phase 9 (`450d960`)

The old plan's Phase 9 was committed after `33dfc7b` as an experiment, without benchmarks. It changes nothing unless it is compiled in and selected, but it moves some of the counts above:

- **Cargo features:** `allocatbelt` gains `experimental-rseq` (not default), which turns on the new `rseq` feature of allocatbelt-sys.
- **unsafe:** allocatbelt-sys `rseq.rs`, compiled only with that feature: one `unsafe extern` block (glibc's `__rseq_offset`, `__rseq_size`) and 7 blocks in the source (3 in `MmCid::probe`, 1 in `field`, and a thread-pointer read per architecture, of which one is compiled), so 5 on any one target. The core and the adapter gain none; the core stays at 0.
- **Public API (with the feature only):** `RseqPolicy` (`Auto`, the default, `Prefer`, `Require`, `Disable`; `#[non_exhaustive]`), `RseqStatus`, `RseqUnavailable`, and `Allocatbelt::set_rseq_policy`, `rseq_status`, `mm_cid`. Without the feature the API is the one in section 3.
- **Core:** `Os::shard_hint` (default `None`), asked on cache refills and other uncached allocations. Tests: `shard_hints_override_the_attached_shard`, `migrating_threads_keep_the_heap_consistent`, and fuzz programs whose seed byte has bit 1 set move the hint on every call.


## 6. Phase B: one publishable package

Directive §20 Phase B folded `allocatbelt-core`, `allocatbelt-sys` and `allocatbelt-arch` into modules of `allocatbelt`, the only package that can be published. No allocator behaviour changed; the counts above move as follows.

- **Layout.** `crates/allocatbelt/src/`: `core/` (the old core, `#![forbid(unsafe_code)]` as an inner attribute of the module), `sys/`, `arch/`, `global.rs` (the old adapter `lib.rs`: `LinuxOs`, `RingPurger`, `GlobalAlloc`), `rseq.rs`, and a new `lib.rs` that declares the modules and re-exports the public API. The crate is `no_std` off Linux only, so bare-metal targets reach the platform gates' messages.
- **No-std core harness.** `crates/allocatbelt-core-check` (`publish = false`) compiles `crates/allocatbelt/src/core/` through `#[path]` as a `#![no_std]`, `#![forbid(unsafe_code)]` crate. It runs the core's unit, model and property tests (its build script sets `cfg(allocatbelt_core_check)`), loom (`RUSTFLAGS="--cfg loom" cargo test --release -p allocatbelt-core-check --lib loom`), the mutation campaign (`mewt.toml`), and, with its feature `model`, the fuzz target. The published package compiles none of that test code.
- **Tools.** `allocatbelt-codegen-probes` and `fuzz` use `allocatbelt-core-check`; `allocatbelt-simd-bench` uses it for the layout constants and `allocatbelt` for `CpuFeatures`. All stay `publish = false`.
- **Packaging.** `allocatbelt` has crates.io metadata, an `include` list (sources, tests, `LICENSE`, the repository README) and no path dependency; `experimental-rseq` is its own feature now, with no sys feature behind it. `scripts/check-package.sh` (CI job "crates.io package", x86_64 and arm64) runs `cargo package` and `cargo publish --dry-run`, checks the `.crate` contents and manifest, and builds and runs a consumer outside the repository, which on x86_64 must stop at the gate's message without `-C target-cpu=x86-64-v3` and build with it.
- **Tests.** 104 run, 3 ignored with `--all-features` (the Phase 9 additions included): `allocatbelt-core-check` lib 65 + 1 ignored (formerly allocatbelt-core); `allocatbelt` lib 14 + 1 ignored (sys 6, arch 6, rseq 1, and `allocation_free`, formerly `allocatbelt-arch/tests/`, now a unit test whose binary uses the counting allocator); the integration tests, simd-bench and probes unchanged.
- **unsafe.** Unchanged at 52 production sites (plus the `experimental-rseq` sites of section 5); only the paths changed (`sys/mod.rs` for the old sys `lib.rs`, `global.rs` for the old adapter `lib.rs`). Unused `Region::len`, `Region::is_empty` and `PurgeRing::entries` were removed with the crate boundary; none held `unsafe`.
- **Public API.** The names in section 3 and 5 are unchanged and still reached as `allocatbelt::…`; the former sys/arch/core crates are no longer separately nameable.

## 7. Phase C: compile-time capability features

Directive §20 Phase C made the optional parts of `allocatbelt` Cargo features ([docs/features.md](../features.md)); no allocator algorithm or run-time default changed.

- **Features.** `default = ["maintenance", "scheduler"]`; `maintenance` (the background thread and its API, now in `src/maintenance.rs`), `scheduler` (its `SCHED_BATCH` request, implies `maintenance`), `io-uring` (the purge ring, `sys/ring.rs`, and rustix's `io_uring` bindings, which left the workspace's rustix features; implies `maintenance`; not default), and `experimental-rseq` as before. All stable Rust, all additive.
- **Default build versus the baseline.** The default build keeps the baseline API except the io_uring part: `set_io_uring`, `io_uring_error` and `RingError` now need the feature `io-uring`, as the directive's suggested feature table has it, since the ring stays off at run time by default anyway. `PurgeBackend` keeps its `IoUring` variant in every build, so matching on it does not depend on another crate's features. With `default-features = false`, `start_maintenance_thread`, `start_purge_thread`, `purge_backend`, `maintenance_is_batch` and `PurgeBackend` are absent and housekeeping runs inline, as it did before a thread was started.
- **`CompiledCapabilities`.** `CompiledCapabilities::CURRENT` and `Allocatbelt::compiled_capabilities()`: one `bool` per feature with code (`maintenance`, `scheduler`, `io_uring`, `rseq`), `#[non_exhaustive]`, allocation-free and `const`. No field for NUMA or ISA backends, which are not implemented.
- **Unconditional.** The core, the platform gates and probes, guard pages, double-free detection, fork handling and abort-on-unwind are in every build.
- **Checks.** `scripts/check-features.sh` (CI job "Feature combinations", x86_64 and arm64): clippy with `-D warnings` and the tests for 8 combinations (none, `maintenance`, `io-uring` alone, `experimental-rseq` alone, default, default + `io-uring`, default + `experimental-rseq`, all). `tests/maintenance.rs` and `tests/purge_thread.rs` require `maintenance`; `compiled_capabilities_follow_the_features` checks `CompiledCapabilities` in each. `scripts/check-package.sh` builds and runs a consumer of the packaged crate with the defaults, `default-features = false`, `io-uring` with and without defaults, and `experimental-rseq`, and checks the capabilities each reports.
- **unsafe.** Unchanged in number: `RingPurger::purge_batch` moved to `maintenance.rs`, and it, the `sys/ring.rs` sites and `set_batch_scheduling` are compiled only with their features, so a default build has 12 fewer production sites (11 in `ring.rs`, 1 in `RingPurger`) and a `default-features = false` build 13 fewer.

## 8. Phase D: run-time policy and capability diagnostics

Directive §20 Phase D added the run-time policy within the compiled capabilities ([docs/features.md](../features.md#run-time-policy)). No allocator algorithm and no default changed: a process that configures nothing behaves as before (`SCHED_BATCH` asked for, io_uring off, rseq off).

- **Policy.** `FeaturePolicy` (`Auto`, `Prefer`, `Require`, `Disable`; `#[non_exhaustive]`), `Policy { scheduler, io_uring, rseq }` with `Policy::DEFAULT`, `Allocatbelt::configure` and `policy`. The maintenance thread has no policy field: the application starts it or not. NUMA and SIMD have none either, having no implementation (`KernelSet::Baseline` only).
- **Lifecycle.** Allocations before `configure` use `Policy::DEFAULT`. The policy and the maintenance thread's phase (idle, starting, running) share one `AtomicU32` (`src/policy.rs`), so `configure` is allocation-free, lock-free, all-or-nothing and fork-safe (a forked child resets the phase). `start_maintenance_thread` freezes `scheduler` and `io_uring` and waits until the thread has applied them; `rseq` stays switchable.
- **Errors.** `PolicyError::NotCompiled`, `Unavailable { step, errno }` and `Frozen`, each naming a `Capability`. A `Require`d scheduler or ring that the system refuses makes `start_maintenance_thread` return an `io::Error` of kind `Unsupported` wrapping the `PolicyError`, with no thread left running. Mandatory platform failures stay fatal, as before.
- **Diagnostics.** `detected_capabilities()` (`DetectedCapabilities`, with an `Availability` per capability recorded in atomic words), `effective_profile()` (`EffectiveProfile`) and `report()` (`Report`, whose `Display` renders all three). `PurgeBackend` now exists in every build.
- **API migration (pre-1.0, deliberate).** `set_io_uring(bool)` sets `io_uring` to `Prefer`/`Auto` and returns `Result<(), PolicyError>` (`Frozen` after the thread started, where it used to be ignored). `RseqPolicy` is an alias of `FeaturePolicy`; `set_rseq_policy` sets the policy's `rseq`. `sys::set_batch_scheduling` returns the errno. No other signature changed.
- **Tests.** `tests/policy.rs` (feature `maintenance`): `Require` of what is not compiled, a thread built with `scheduler = Disable` and `io_uring = Require` (or, where the ring is refused, the error, no thread, and a retry with `Prefer`), freezing, `rseq` after the freeze, and the report. `tests/platform.rs::policy_moves_only_within_the_build` runs in every feature combination. Unit tests check the policy word and the `Availability` encoding, and that every failure step the ring and the rseq probe report can be recorded.
- **unsafe.** Unchanged: no new site.

## 9. Phase E: sandbox and virtualization qualification

Directive §20 Phase E added behaviour checks for containers and VMs ([docs/sandbox.md](../sandbox.md)); no allocator code changed.

- **Hardened container.** `scripts/check-sandbox.sh` builds every test binary of `allocatbelt` (default features + `io-uring`) statically for musl and runs it in Docker with user 10001, `--cap-drop ALL`, a read-only root, no network, `no-new-privileges` and Docker's default seccomp profile, from an empty image. All pass: baseline correctness needs no extra privilege.
- **Fallbacks and errors** (`tests/sandbox.rs`, one process per scenario): io_uring denied by the default profile (`Require` fails with `Unavailable { setup, errno 1 }` and leaves no thread; `Prefer` falls back to `madvise`), allowed (`Require` gets the ring), and killed on use (`Disable` and `Auto` never call `io_uring_setup`); `sched_setscheduler` denied (`Require` fails, `Auto` keeps the default policy). Seccomp profiles in `scripts/seccomp/`.
- **Visible ISA.** Under qemu-user CPU models the detected features are the model's, not the host's: x86_64 `Haswell-noTSX` shows x86-64-v3 and AVX2 without AVX-512 on an AVX-512 host; aarch64 `cortex-a72`, `neoverse-v1` and `neoverse-n2` show no SVE, SVE and SVE2.
- **No hidden host.** `no_hidden_host_probes` checks the sources for host topology files, hypervisor `cpuid` leaves and CPU-count sizing.
- **fork.** `tests/fork_maintenance.rs`: a child forked after the maintenance thread started has none, keeps the policy, and starts its own, which chooses its backend again.
- CI job "Sandbox and virtualization" on x86_64 and arm64 runners (VMs, so Docker in a VM). Not automated: full system VMs, nested VMs and vNUMA guests.

## 10. Phase F: experimental ARM ISA opt-ins

Directive §20 Phase F adds its first concrete experimental kernel ([docs/features.md](../features.md#experimental-isa-kernels)). Nothing changes for a build without the new features, or for a process that configures nothing.

- **Operation.** The age scan of a decay pass (which free dirty pages of a segment have waited the purge delay), the `age`/`age-meta` family of `bench/simd`. The core gained `Os::age_kernel` (default `None`, the unchanged portable loop over the candidate bits) and `aged_pages`, the definition every kernel must match. With a kernel, `claim_segment` first takes a private snapshot of the 64 ages with one atomic load each (directive §10.2) and masks the kernel's result with the candidates.
- **Features.** `experimental-aarch64-sve` and `experimental-aarch64-sve2` (implies the former); non-default, stable Rust, compiling nothing on other architectures. `CompiledCapabilities` gained `experimental_aarch64_sve` and `experimental_aarch64_sve2` (true only on aarch64).
- **Selection.** `KernelSet` gained `Sve` and `Sve2` (present in every build). `Policy` gained `experimental_isa` and `Capability` gained `ExperimentalIsa`: compiled ∩ `AT_HWCAP`/`AT_HWCAP2` ∩ `Prefer`/`Require` = selected, SVE2 over SVE; `Auto` and `Disable` keep the baseline; `Require` fails in `configure` (`NotCompiled`, or `Unavailable { step: "cpu features" }`). It switches at any time; the policy word now packs each `FeaturePolicy` in two bits. `DetectedCapabilities` gained `experimental_isa`; the report prints a row for it.
- **Code.** `src/arch/sve.rs`: the portable loop inside `#[target_feature(enable = "sve")]` / `"sve2"` functions (LLVM emits SVE compares on scalable vectors; SVE intrinsics are not stable). The SVE2 kernel is the same loop with SVE2 enabled.
- **Tests.** Kernel unit tests against the portable loop; a core model test (`decay_with_an_age_kernel_purges_the_same_pages`) that decay through the snapshot path purges exactly what the portable scan purges; `tests/experimental_isa.rs` for selection, errors and decay with the kernel selected. `scripts/check-experimental-isa.sh` (CI job "Experimental aarch64 SVE/SVE2 kernels", arm64 runner) runs them natively and under qemu `cortex-a72`, `neoverse-v1`, `neoverse-n2` and `max` at 128, 512 and 2048-bit vectors; `check-features.sh` has 10 combinations; the package consumer builds with `experimental-aarch64-sve2`.
- **Not done.** No benchmark was run; the Phase 5 decision (no default kernel) stands, and a later qualification task decides whether any kernel becomes a default. No hand-written NEON kernel was added (none beat the compiler in Phase 4).
- **unsafe.** Two new sites, each compiled only with its feature on aarch64: the calls of the SVE and SVE2 target-feature functions (docs/unsafe-boundary.md).

## 11. Phase G: experimental RVV opt-in

Directive §20 Phase G adds the RVV version of the Phase F kernel ([docs/features.md](../features.md#experimental-isa-kernels)).

- **Toolchain.** The `v` target feature is unstable in Rust 1.98.1 (`riscv_target_feature`), so the feature `experimental-riscv-rvv` needs nightly on riscv64. `lib.rs` enables the gate only for that feature on riscv64 (`cfg_attr`), so the default crate, every other feature and every other architecture stay on stable; on x86_64 and aarch64 the feature compiles nothing. The nightly used for checks is pinned (`nightly-2026-09-27`).
- **Isolation.** V is enabled for one function, `arch::rvv::aged_pages_rvv_body` (`#[target_feature(enable = "v")]`), never for the build. `scripts/check-experimental-rvv.sh` checks with `llvm-objdump` that no other function of the test binaries contains V instructions.
- **Detection.** `CpuFeatures::RVV` now also requires that the kernel lets this process use V: `prctl(PR_RISCV_V_GET_CONTROL)` must not report it turned off (`abi.riscv_v_default_allow = 0` or a parent's control). `EINVAL` (no V state control: a kernel without V, whose hwprobe does not report it either, or qemu-user) keeps the hwprobe answer.
- **Selection and API.** `KernelSet::Rvv`, `CompiledCapabilities::experimental_riscv_rvv`; the same `Policy::experimental_isa` and `Capability::ExperimentalIsa` as Phase F (`Capability::feature()` names the feature of the build's architecture).
- **Tests.** The kernel unit test (shared with SVE, `arch/kernel_tests.rs`), `tests/experimental_isa.rs` and `tests/platform.rs` under qemu with VLEN 128, 256 and 1024 (`Rvv` selected), and with V off (`Baseline`; skipped where the cross glibc itself needs V, as Ubuntu 26.04's RVA23 build does). CI job "Experimental riscv64 RVV kernel (nightly)"; `check-features.sh` (11 combinations) and the package consumer build the feature on stable x86_64/aarch64. No native RVV hardware was available: correctness only, and qemu timings are not evidence (none were taken).
- **Not done.** No benchmark was run; no default changes.
- **unsafe.** Two new sites on riscv64: the call of the V target-feature function (feature-gated) and the `prctl` read in detection (every riscv64 build).
