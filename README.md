# allocatbelt

A Rust-based alternative to mimalloc (C) for [OxiBelt](https://github.com/OxiBelt/OxiBelt): research and a prototype.

- **One package.** `allocatbelt` is the only crate meant for crates.io; everything else in this workspace is `publish = false` tooling.
- **Allocation logic is safe Rust.** The `core` module carries `#![forbid(unsafe_code)]`, and the `allocatbelt-core-check` tool compiles the same source as a `#![no_std]`, `#![forbid(unsafe_code)]` crate to run its tests, model and loom checks.
- **`unsafe` lives only at the syscall, raw-memory and architecture boundaries.** That means the `sys` module (mmap/mprotect/madvise, exposing metadata as atomics), the `arch` module (CPU feature detection) and the `GlobalAlloc` adapter in `global`.
- The workspace lints are copied from OxiBelt (`unsafe_code = deny`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `missing_safety_doc`).

```text
crates/allocatbelt/                The published package:
  src/core/                        allocation logic (offsets, bitmaps, size classes, segments/pages); no unsafe
  src/sys/                         arena reservation/commit/purge and the metadata slab; the syscall unsafe boundary
  src/arch/                        CPU feature detection (cpuid, getauxval, riscv_hwprobe) and kernel dispatch
  src/global.rs, src/rseq.rs       the #[global_allocator] adapter (Allocatbelt)
crates/allocatbelt-core-check/     no_std build of src/core with its tests, the checking model and loom (not published)
crates/allocatbelt-codegen-probes/ out-of-line core helpers for the scalar ISA check (not published)
fuzz/                              cargo-fuzz over the checking model (not published)
bench/                    Comparison against system and secure mimalloc.
bench/simd/               SIMD candidate kernels and their benchmark (not linked into the allocator).
docs/                     Research reports, benchmark results, unsafe inventory.
```

## Using it from another crate

> **x86_64 consumers must build the final binary with `-C target-cpu=x86-64-v3` or a newer compatible CPU target.**
> Cargo does not apply this repository's `.cargo/config.toml` to crates that depend on allocatbelt, and a build without it stops with the compile error `allocatbelt on x86_64 must be built for x86-64-v3 or newer`. Set it in your own workspace, for example in `.cargo/config.toml`:
>
> ```toml
> [target.x86_64-unknown-linux-gnu]
> rustflags = ["-C", "target-cpu=x86-64-v3"]
> rustdocflags = ["-C", "target-cpu=x86-64-v3"]  # for doctests (`cargo test --doc`)
> ```
>
> or with `RUSTFLAGS="-C target-cpu=x86-64-v3"` (and the same `RUSTDOCFLAGS` for doctests). aarch64 and riscv64 need no flag.

allocatbelt is **not on crates.io yet**. The package is ready for it (`cargo publish --dry-run` passes, and the unpacked crate builds, tests and documents on its own: [docs/research/publish-readiness.md](docs/research/publish-readiness.md)), but publishing is a separate decision. Until then, depend on the repository:

```toml
[dependencies]
allocatbelt = { git = "https://github.com/OxiBelt/allocatbelt", branch = "research/rust-allocator" }
# once published: allocatbelt = "0.1"
```

Cargo features pick which optional parts are compiled in; which of them a process uses is chosen at run time, within that ceiling (`Allocatbelt::compiled_capabilities()`). All of them build on stable Rust except `experimental-riscv-rvv` on riscv64, and none turns allocator correctness or hardening on or off. Details in [docs/features.md](docs/features.md).

| Feature | Default | Adds |
|---|---|---|
| `maintenance` | yes | the background maintenance thread (`start_maintenance_thread`); without it, allocating threads run housekeeping inline |
| `scheduler` | yes | runs that thread as `SCHED_BATCH` |
| `io-uring` | no | batched purges through a restricted io_uring, off until `set_io_uring(true)`, with a `madvise` fallback |
| `experimental-rseq` | no | experimental shard selection by the rseq `mm_cid`, off until selected (`RseqPolicy`) |
| `experimental-aarch64-sve`, `experimental-aarch64-sve2` | no | experimental SVE/SVE2 kernels for the decay pass's age scan (aarch64 only), off until `Policy::experimental_isa` selects them; not measured |
| `experimental-riscv-rvv` | no | the same scan for RISC-V V (riscv64 only; **needs nightly Rust there**), off until selected; not measured |

`default-features = false` builds the allocator without the maintenance thread.

Features are the ceiling; `Allocatbelt::configure(Policy)` chooses within it at run time (`FeaturePolicy::Auto`, `Prefer`, `Require` or `Disable` per capability), and `Allocatbelt::report()` shows what was compiled, detected and selected ([docs/features.md](docs/features.md#run-time-policy)).

```rust
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::io::Result<()> {
    // Optional: run housekeeping (purging, returning idle memory) on a
    // background thread instead of the allocating threads, and tune how
    // long freed memory stays.
    GLOBAL.set_purge_delay(std::time::Duration::from_secs(1));
    // Optional: choose among the compiled capabilities before the thread
    // starts (here: the io_uring purge ring where available, which needs
    // the `io-uring` feature).
    let mut policy = allocatbelt::Policy::DEFAULT;
    policy.io_uring = allocatbelt::FeaturePolicy::Prefer;
    GLOBAL.configure(policy).map_err(std::io::Error::other)?;
    GLOBAL.start_maintenance_thread()?;
    eprintln!("{}", GLOBAL.report());
    Ok(())
}
```

What it does, in the terms of mimalloc (details in [docs/research/README.md](docs/research/README.md) §4):

- **Per-thread caches.** Each thread allocates small blocks (≤ 8 KiB) from a claimed bitmap word per size class, with no atomics or locks, and batches its frees per bitmap word. A shard lock is taken only to claim the next word. Threads hand their caches back at exit.
- **Two-level summaries.** A word summary per page and per-class availability bitmaps per segment find the next free blocks with `trailing_zeros`, never by scanning pages.
- **Delayed purging.** Freed memory stays resident for the purge delay (1 s), then goes back to the OS (`MADV_DONTNEED`) and empty segments to the arena; a 32 MiB budget bounds the freed pages awaiting a purge (tracked dirty pages; not RSS, which also holds live and cached blocks and is decided by the OS). With the maintenance thread started, allocating threads only set a flag and the thread (`SCHED_BATCH`) runs the passes. It can also purge each pass's page runs in batches through a restricted io_uring (feature `io-uring`, then `set_io_uring(true)`; opt-in).
- **Hardening.** Free blocks live in out-of-band bitmaps, so user writes cannot corrupt allocator state, and double frees are caught when they reach the bitmap. Every segment ends in a guard page (`MADV_GUARD_INSTALL`, or `mprotect`). Refills, block order and segment placement are randomized with a `getrandom` seed.
- **fork.** `pthread_atfork` handlers keep the heap usable in children forked while other threads allocate.

Status: **research prototype**. Not recommended for production.

**Platform contract** ([docs/platform.md](docs/platform.md)): Linux 7.0 or newer, 64-bit little-endian userspace, on x86_64 (**x86-64-v3 or newer**), aarch64 or riscv64 (RV64GC, Zbb optional). Every other target, and any x86_64 build below x86-64-v3, fails at compile time with a message saying why. Inside this repository `.cargo/config.toml` builds x86_64 with `-C target-cpu=x86-64-v3`; a `RUSTFLAGS` variable replaces it and must carry that flag too, and crates depending on allocatbelt (OxiBelt) must set it in their own build ([above](#using-it-from-another-crate)). At start-up the allocator probes the kernel facilities it cannot run without (reservation, commit, `MADV_DONTNEED` zeroing) and aborts with a message if one is missing. x86_64 and aarch64 are tested natively in CI (`ubuntu-26.04` and `ubuntu-26.04-arm` runners); riscv64 is tested in CI under qemu-user, with and without Zbb; the `platform-gates` job checks that the supported targets build and the others are rejected. Every supported CPU runs the same scalar code by default: none of the SIMD candidates measured in `bench/simd` qualified ([docs/research/simd-benchmarks.md](docs/research/simd-benchmarks.md)). The experimental SVE/SVE2 and RVV kernels run only when compiled in, exposed to the process and selected by the policy ([docs/features.md](docs/features.md#experimental-isa-kernels)).
allocatbelt does not depend on OxiBelt, and OxiBelt does not need it: an application opts in with `#[global_allocator]` (above), and any Rust program on a supported platform can use it the same way. OxiBelt keeps secure mimalloc as its default; the research summary recommends adding allocatbelt there only as an experimental option and comparing it under real traffic first ([docs/research/README.md](docs/research/README.md)).
Containers and VMs are first-class: the allocator needs no Linux capability, writable filesystem or `seccomp=unconfined`, falls back when a sandbox refuses io_uring or `SCHED_BATCH`, and uses only the ISA the guest exposes ([docs/sandbox.md](docs/sandbox.md)).
For the conclusions and recommendations see [docs/research/README.md](docs/research/README.md), for measurements see [docs/research/benchmarks.md](docs/research/benchmarks.md), for the unsafe inventory see [docs/unsafe-boundary.md](docs/unsafe-boundary.md), and for the diagnostics (purge, search and thread-cache counters, memory usage, and why none of them is RSS) see [docs/observability.md](docs/observability.md).

## Verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --release --locked                                   # core tests (allocatbelt-core-check) + global-allocator integration tests
scripts/check-features.sh                                       # clippy and tests for each supported feature combination
scripts/check-package.sh                                        # cargo package/publish --dry-run, package contents, the unpacked crate's tests and docs.rs build, clean-consumer builds
scripts/check-sandbox.sh                                        # hardened container, seccomp fallbacks, visible ISA under qemu (docs/sandbox.md)
scripts/check-experimental-isa.sh                               # experimental SVE/SVE2 kernels under qemu CPU models (docs/features.md)
scripts/check-experimental-rvv.sh                               # experimental RVV kernel on the pinned nightly, under qemu (docs/features.md)
scripts/check-rseq.sh                                           # experimental rseq mm_cid: glibc, glibc with rseq off, musl (docs/platform.md)
scripts/check-platform-gates.sh                                 # supported targets build, others are rejected (needs `rustup target add`, see the script)
scripts/check-scalar-isa.sh                                     # bit scans lower to tzcnt/popcnt/lzcnt (x86-64-v3) and ctz/cpop/clz (riscv64 + Zbb)
cargo audit && cargo deny check                                 # RustSec advisories, licenses, bans, sources
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p allocatbelt-core-check
scripts/run-mutation-testing.sh                                 # mewt campaign over the core's bits/classes
RUSTFLAGS="--cfg loom" cargo test --release -p allocatbelt-core-check --lib loom   # loom models of the lock-free protocols
(cd fuzz && cargo +nightly fuzz run heap_ops)                   # cargo-fuzz over the checked heap model; see fuzz/README.md
cargo run --release -p allocatbelt-bench --bin bench-allocatbelt   # also bench-system, bench-mimalloc (built for x86-64-v3)
cargo run --release -p allocatbelt-simd-bench --bin bench-simd  # SIMD candidates vs scalar; see docs/research/simd-benchmarks.md
```

Code style, pinned tool versions and the commit-message format follow OxiBelt; see [CONTRIBUTING.md](CONTRIBUTING.md).

### RISC-V (riscv64)

`.cargo/config.toml` sets the linker and a qemu-user runner for `riscv64gc-unknown-linux-gnu`, so the tests can run on an x86_64 host. The runner uses `-cpu max`, which provides Zbb for the second command and the RVA23 extensions that Ubuntu 26.04's riscv64 cross glibc is built for, so both commands below run. Use qemu 10.2.1 or later (Ubuntu 26.04's `qemu-user`): qemu 8.2 intermittently crashes with `QEMU internal SIGSEGV` on the multithreaded tests.

```sh
sudo apt-get install qemu-user gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
rustup target add riscv64gc-unknown-linux-gnu
cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt -p allocatbelt-core-check -p allocatbelt-simd-bench
RUSTFLAGS="-C target-feature=+zbb" cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt -p allocatbelt-core-check
```

- Build with `-C target-feature=+zbb` (part of the RVA22 profile) when the hardware has it. Without Zbb, the bitmap scans' `trailing_zeros`/`count_ones`/`leading_zeros` compile to multi-instruction sequences instead of `ctz`/`cpop`/`clz`.
- The fixed 64 KiB granule is a multiple of every Linux page size (4, 16 and 64 KiB), so the kernel's page size does not matter. Under Sv39 the user address space is 256 GiB, so the 64 GiB arena reservation (`PROT_NONE`, `MAP_NORESERVE`, no RSS) takes a quarter of it. Sv48/Sv57 leave plenty of room.
- The `bench` crate builds secure mimalloc from C, so cross-building it needs a riscv64 C compiler (`CC_riscv64gc_unknown_linux_gnu=riscv64-linux-gnu-gcc`). Throughput on riscv64 has not been measured, since qemu numbers are meaningless.
