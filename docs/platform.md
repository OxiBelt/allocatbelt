# Platform contract

allocatbelt is a Linux-only allocator for a fixed set of 64-bit CPUs. This page is the contract; the code that enforces it is in [`crates/allocatbelt-sys/src/platform.rs`](../crates/allocatbelt-sys/src/platform.rs), and [`scripts/check-platform-gates.sh`](../scripts/check-platform-gates.sh) checks it in CI (the `platform-gates` job).

| | Supported | Rejected |
|---|---|---|
| Operating system | Linux 7.0 or newer | everything else (FreeBSD, macOS, bare metal, wasm, ...), at compile time |
| Architecture | x86_64, aarch64, riscv64 | x86/i686, arm/armv7, riscv32, powerpc*, s390x, loongarch*, wasm* and all others |
| Userspace | 64-bit, little-endian, with 64-bit atomics | 32-bit and ILP32 ABIs (x32), big-endian |
| x86_64 | x86-64-v3 or newer (`-C target-cpu=x86-64-v3`) | x86-64-v1/v2 builds, at compile time |
| aarch64 | any AArch64 Linux target (`aarch64_be` is rejected as big-endian) | |
| riscv64 | RV64GC (`riscv64gc-unknown-linux-gnu`); Zbb optional | riscv32 |

The gates are `compile_error!`s, so an unsupported build fails before anything runs, with a message that names the problem. `scripts/check-platform-gates.sh` checks one or more representatives of every rejected row: i686, armv7, x32, riscv32, wasm32, powerpc64le, loongarch64, s390x and FreeBSD. 32-bit targets stop at `allocatbelt-core`'s own 64-bit gate; everything else stops in `allocatbelt-sys`, which the `allocatbelt` adapter now depends on unconditionally so that the gates are always reached.

## x86-64-v3 is the floor

Every x86_64 build must enable the x86-64-v3 feature set: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE and XSAVE, on top of the v2 set (CMPXCHG16B, POPCNT, SSE3, SSSE3, SSE4.1, SSE4.2). `allocatbelt-sys` checks each of these with `cfg(target_feature = ...)`, so `-C target-cpu=x86-64-v4`, `-C target-cpu=native` on a v3 machine, or an explicit `-C target-feature=...` list all pass, and a generic build does not.

- **Inside this repository**, `.cargo/config.toml` adds `-C target-cpu=x86-64-v3` for every x86_64 target (`rustflags`, and `rustdocflags` for doctests on the gnu and musl triples). A `RUSTFLAGS` (or `RUSTDOCFLAGS`) environment variable *replaces* those flags rather than adding to them, so it must carry the CPU flag itself, for example `RUSTFLAGS="-C target-cpu=x86-64-v3 -C debuginfo=2"`. Builds of `allocatbelt-core` alone (the loom, fuzz and mutation jobs) are not gated.
- **In a crate that depends on allocatbelt** (OxiBelt's `oxibelt-allocator`), this repository's `.cargo/config.toml` is not read. The dependent workspace must build x86_64 artifacts with `-C target-cpu=x86-64-v3` (or newer) in its own `.cargo/config.toml` or `RUSTFLAGS`, and name them accordingly (for example `...-x86_64-v3-linux-gnu`, `...-x86_64-v3-linux-musl`). Without it the build fails with the gate's message.
- **There is no friendly run-time error on an older CPU.** A binary compiled for x86-64-v3 may execute v3 instructions before any of its own code can check the CPU, so on a v1/v2 machine it dies with `SIGILL`. The build baseline is the compatibility mechanism. If a clear error is ever needed, it belongs in a separate generic launcher that checks the CPU and then `exec`s the v3 binary, not in a lowered allocatbelt build.
- Higher ISA levels (AVX-512 and newer) are for later phases: they will be used only through run-time detection and per-kernel dispatch backed by benchmarks, never by raising the build floor.

## Linux 7.0 or newer

Linux 7.0 is the oldest kernel the project supports and tests against. The kernel version is **not** what the allocator checks, though: a version string says nothing reliable about backports, sandboxes or emulators. Instead, before it reserves its arena, the allocator runs `allocatbelt_sys::probe()` once. The probe works on a private 64 KiB scratch reservation and checks the facilities the allocator cannot run without:

| Facility | Mandatory | Checked by | Without it |
|---|---|---|---|
| Anonymous `PROT_NONE`, `MAP_NORESERVE` reservation | yes | reserving the scratch range | abort with a message |
| `mprotect(PROT_READ \| PROT_WRITE)` commit | yes | committing it | abort with a message |
| `madvise(MADV_DONTNEED)` returning zero-filled pages | yes | writing a byte, purging, reading back `0` | abort with a message: purged memory backs `alloc_zeroed` without a memset |
| Guard markers (`MADV_GUARD_INSTALL`, Linux 6.13+) | no | installing markers and checking that populating the range faults | guard pages use `mprotect(PROT_NONE)`; qemu-user takes this path |
| `getrandom(2)` without blocking | no | reading 8 bytes | the placement secret falls back to ASLR and the time |

A missing mandatory facility aborts the process with a one-line `allocatbelt: ...` message on stderr instead of returning null from the first allocation, which Rust would report only as a generic allocation failure. The probe issues only syscalls and does not allocate; afterwards the scratch range is `PROT_NONE` again and holds no memory.

The probe also reads the kernel release from `uname(2)`. `Allocatbelt::platform()` returns everything the probe found (`Capabilities`: kernel version, guard markers, getrandom) for diagnostics, and `KernelVersion::meets_minimum()` compares a release against 7.0. An older kernel is not rejected as long as every mandatory facility is present: that keeps the allocator usable under qemu-user and on CI hosts whose kernel is older than the contract, and a run there is outside the supported configuration, not a different code path. As later phases start to rely on Linux 7.0 interfaces, each one is added to the probe as a mandatory facility, so the check stays tied to what the allocator actually uses. The io_uring purge ring (phase 8) is not one of them: it is opt-in, uses `IORING_SETUP_SQ_REWIND` only when the kernel accepts it, and falls back to `madvise` when io_uring is unavailable (below).

## RISC-V

The baseline is RV64GC, as before. Zbb is optional: building with `-C target-feature=+zbb` turns the bitmap scans' `trailing_zeros`/`count_ones`/`leading_zeros` into single `ctz`/`cpop`/`clz` instructions, and CI tests both builds under qemu-user. The V extension is not required and not used yet. Feature detection with `riscv_hwprobe` belongs to the architecture capability layer (phase 2), not to this contract.

## CPU features and kernel dispatch (`allocatbelt-arch`)

Above the build floor, `crates/allocatbelt-arch` finds out at run time which ISA extensions the CPU and kernel support, and publishes which set of architecture kernels the allocator may use. It is the only place architecture-specific `unsafe` may go; `allocatbelt-core` never sees vector types.

| Architecture | Tracked features (`CpuFeatures`) | Source | Checked against |
|---|---|---|---|
| x86_64 | `X86_64_V3` (the whole v3 set), `AVX2`, `AVX512F`, `AVX512CD`, `AVX512BW`, `AVX512DQ`, `AVX512VL`, `AVX512VPOPCNTDQ` | `cpuid` leaves 1, 7 and 0x80000001, plus `xgetbv` for the XMM/YMM and opmask/ZMM state the OS enables | `std::arch::is_x86_feature_detected!` in the unit tests |
| aarch64 | `ASIMD`, `SVE`, `SVE2` | `getauxval(AT_HWCAP)`, `getauxval(AT_HWCAP2)` | `std::arch::is_aarch64_feature_detected!` in the unit tests |
| riscv64 | `ZBB`, `RVV` (the V extension) | `riscv_hwprobe(RISCV_HWPROBE_KEY_IMA_EXT_0)` over all online CPUs | the `+zbb` CI build must detect Zbb (`is_riscv_feature_detected!` is unstable); qemu-user `-cpu max` reports Zbb and V |

The kernel constants (HWCAP bits, hwprobe key, bits and syscall number) come from the Linux v7.0 UAPI headers, because the `libc` crate does not have all of them.

Dispatch follows the plan's reentrancy rule:

```text
allocations before initialize_dispatch()  -> KernelSet::Baseline (always correct)
initialize_dispatch()                     -> probe once (allocation-free), publish in an atomic
allocations afterwards                    -> the published KernelSet
```

The adapter calls `initialize_dispatch()` while it initialises the arena, right after the kernel probe. Detection issues only `cpuid`/`xgetbv`, reads libc's saved auxiliary vector, or makes one syscall; it never allocates, which `crates/allocatbelt-arch/tests/allocation_free.rs` checks with a counting global allocator. The result is cached in an `AtomicU32` and the kernel set in an `AtomicU8`, with no `OnceLock` or lazy framework. `Allocatbelt::cpu_features()` and `Allocatbelt::kernel_set()` expose both for diagnostics.

A detected feature does not mean a kernel exists for it. A kernel is admitted only with benchmark evidence that it speeds up a measured allocator cost, and the Phase 5 qualification admitted none ([research/simd-benchmarks.md](research/simd-benchmarks.md#phase-5-promotion-decision-2026-09-28)). So `KernelSet` has only `Baseline`, and every CPU runs the same code as before.

## Scalar bit instructions

The allocator's hot scans work on one `u64` bitmap word at a time with `trailing_zeros`, `count_ones` and `leading_zeros`. The right primitive for one word is a single scalar instruction, not a vector, so before any SIMD work `scripts/check-scalar-isa.sh` (CI job `scalar-isa`) checks that these operations lower to one:

| Operation | Where the allocator uses it | x86-64-v3 | riscv64 + Zbb | riscv64 (rv64gc) |
|---|---|---|---|---|
| `trailing_zeros` | `bits::find_run_aligned`, `bits::pick_bit`, the summary scans | `tzcnt`, never `bsf` | `ctz` | no `ctz`: a multi-instruction sequence |
| `count_ones` | free counters (`proto.rs`), dirty-page accounting (`heap.rs`) | `popcnt` | `cpop` | no `cpop` |
| `leading_zeros` | `class::class_of` | `lzcnt`, never `bsr` | `clz` | no `clz` |

These helpers are small enough that LLVM inlines them into their callers, so they have no symbol of their own. The script builds `crates/allocatbelt-codegen-probes`, which holds one out-of-line wrapper per operation around the real `allocatbelt-core` helper, with the allocator's own flags, emits assembly, and looks only at those four function bodies, which keeps it independent of scheduling and inlining elsewhere. The rv64gc column is a control: without Zbb none of the three instructions may appear, which shows the check can tell the builds apart and why `-C target-feature=+zbb` matters. A generic x86-64 (v1) build of the probes uses `bsf`/`bsr` and a software popcount, which the check would reject; the platform gate already rules that build out for the allocator itself.

The check needs only `rustup target add riscv64gc-unknown-linux-gnu`, no linker or qemu, since it stops at assembly. It verifies instruction selection only; whether a kernel is faster is a benchmark question for later phases. aarch64 has no scalar popcount before FEAT_CSSC (LLVM uses NEON `cnt`), so it is not part of this check.

## Not covered yet

Phases 1 to 5 of the Linux 7 / ISA / SIMD plan changed no allocator algorithm: phase 4 measured SIMD candidates and phase 5 promoted none of them. Phase 6 made the heap locks sleep on a futex, phase 7 moved housekeeping to a `SCHED_BATCH` maintenance thread and phase 8 added an opt-in io_uring purge ring for it (below).

## Maintenance thread scheduling

`Allocatbelt::start_maintenance_thread` starts the thread that runs purge passes (docs/research/README.md §4). The thread moves itself to `SCHED_BATCH` with `sched_setscheduler` (`allocatbelt_sys::set_batch_scheduling`), keeping the process's nice value, and the adapter reports whether that worked (`Allocatbelt::maintenance_is_batch`). If a sandbox refuses the call, the thread keeps the default policy. It is never real-time and never pinned to a CPU: it must not delay the process's own threads, and a pin would tie it to a CPU that may be busy (plan §11.2–11.3). It sleeps on a futex with a timeout (the next decay deadline) and wakes early when a freeing thread records work. The thread is named `allocatbelt-mnt` (Linux keeps 15 bytes of a thread name).

## io_uring purge ring

After `Allocatbelt::set_io_uring(true)`, the maintenance thread purges the page runs of each pass in batches through its own io_uring (`allocatbelt_sys::PurgeRing`, plan §10) instead of one `madvise` per run. `madvise` stays the default because the ring has not won in measurements yet (docs/research/benchmarks.md, Phase 8). The ring:

- is created by the maintenance thread with `IORING_SETUP_R_DISABLED`, `SINGLE_ISSUER`, `DEFER_TASKRUN` and `NO_SQARRAY`, plus `SQ_REWIND` on Linux 7.0 (the setup is retried without it when the kernel rejects the flag), and never with `SQPOLL`;
- registers restrictions before it is enabled: only `IORING_OP_MADVISE`, no SQE flags, no later `io_uring_register` calls; it registers no files or buffers, so allocator memory is never pinned;
- caps the kernel's io-wq workers at one, since `IORING_OP_MADVISE` always runs on a worker and parallel purges of one address space only contend;
- waits for every completion of a batch before the pass ends the pages' claim, so no purge is in flight after a pass (in particular not across `fork`, whose handler takes the purge lock first), and only a completion with result 0 marks pages clean.

If io_uring is unavailable (`kernel.io_uring_disabled`, a seccomp filter, qemu-user's `ENOSYS`) or `IORING_OP_MADVISE` is missing, the thread purges with `madvise`; `Allocatbelt::purge_backend` and `Allocatbelt::io_uring_error` say which and why. A forked child inherits the descriptor (close-on-exec) but never uses it: its own maintenance thread, if started, creates a new ring.

## No portability layer

Because Linux is a hard requirement, the crates do not carry generic-Unix abstractions or old-kernel compatibility paths. The one fallback that remains, `mprotect(PROT_NONE)` guard pages, is not for older kernels (every supported kernel has guard markers) but for environments that accept `MADV_GUARD_INSTALL` without implementing it, such as qemu-user, which the guard code detects with a populate check. The only `cfg(target_os = "linux")` left is on `allocatbelt-sys`'s own dependencies, so that a build for another OS stops at the gate's message instead of at a dependency that does not build there.
