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
