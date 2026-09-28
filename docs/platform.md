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

The probe also reads the kernel release from `uname(2)`. `Allocatbelt::platform()` returns everything the probe found (`Capabilities`: kernel version, guard markers, getrandom) for diagnostics, and `KernelVersion::meets_minimum()` compares a release against 7.0. An older kernel is not rejected as long as every mandatory facility is present: that keeps the allocator usable under qemu-user and on CI hosts whose kernel is older than the contract, and a run there is outside the supported configuration, not a different code path. As later phases start to rely on Linux 7.0 interfaces (io_uring `IORING_SETUP_SQ_REWIND` for the purge backend, for example), each one is added to the probe as a mandatory facility, so the check stays tied to what the allocator actually uses.

## RISC-V

The baseline is RV64GC, as before. Zbb is optional: building with `-C target-feature=+zbb` turns the bitmap scans' `trailing_zeros`/`count_ones`/`leading_zeros` into single `ctz`/`cpop`/`clz` instructions, and CI tests both builds under qemu-user. The V extension is not required and not used yet. Feature detection with `riscv_hwprobe` belongs to the architecture capability layer (phase 2), not to this contract.

## Not covered yet

This is phase 1 of the Linux 7 / ISA / SIMD plan: no allocator algorithm changed. Run-time CPU feature detection, SIMD kernels, generated-code checks for the scalar bit instructions, and the Linux 7.0 maintenance plane (io_uring purge, futex waits, scheduler policy) come in later phases.

## No portability layer

Because Linux is a hard requirement, the crates do not carry generic-Unix abstractions or old-kernel compatibility paths. The one fallback that remains, `mprotect(PROT_NONE)` guard pages, is not for older kernels (every supported kernel has guard markers) but for environments that accept `MADV_GUARD_INSTALL` without implementing it, such as qemu-user, which the guard code detects with a populate check. The only `cfg(target_os = "linux")` left is on `allocatbelt-sys`'s own dependencies, so that a build for another OS stops at the gate's message instead of at a dependency that does not build there.
