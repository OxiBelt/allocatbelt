# allocatbelt

A Rust-based alternative to mimalloc (C) for [OxiBelt](https://github.com/OxiBelt/OxiBelt): research and a prototype.

- **Allocation logic is safe Rust.** `allocatbelt-core` is `#![no_std]` + `#![forbid(unsafe_code)]`.
- **`unsafe` lives only at the syscall, raw-memory and architecture boundaries.** That means `allocatbelt-sys` (mmap/mprotect/madvise, exposing metadata as atomics), `allocatbelt-arch` (CPU feature detection) and the `GlobalAlloc` adapter in `allocatbelt`.
- The workspace lints are copied from OxiBelt (`unsafe_code = deny`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `missing_safety_doc`).

```text
crates/allocatbelt-core   Allocation logic (offsets, bitmaps, size classes, segments/pages). No unsafe.
crates/allocatbelt-sys    Arena reservation/commit/purge and the metadata slab. The syscall unsafe boundary.
crates/allocatbelt-arch   CPU feature detection (cpuid, getauxval, riscv_hwprobe) and kernel dispatch. The architecture unsafe boundary.
crates/allocatbelt        #[global_allocator] adapter (Allocatbelt).
bench/                    Comparison against system and secure mimalloc.
docs/                     Research reports, benchmark results, unsafe inventory.
```

```rust
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() -> std::io::Result<()> {
    // Optional: return idle memory from a background thread (otherwise
    // allocating threads do it), and tune how long freed memory stays.
    GLOBAL.set_purge_delay(std::time::Duration::from_secs(1));
    GLOBAL.start_purge_thread()?;
    Ok(())
}
```

What it does, in the terms of mimalloc (details in [docs/research/README.md](docs/research/README.md) §4):

- **Per-thread caches.** Each thread allocates small blocks (≤ 8 KiB) from a claimed bitmap word per size class, with no atomics or locks, and batches its frees per bitmap word. A shard lock is taken only to claim the next word. Threads hand their caches back at exit.
- **Two-level summaries.** A word summary per page and per-class availability bitmaps per segment find the next free blocks with `trailing_zeros`, never by scanning pages.
- **Delayed purging.** Freed memory stays resident for the purge delay (1 s), then goes back to the OS (`MADV_DONTNEED`) and empty segments to the arena; a 32 MiB dirty budget bounds RSS under churn.
- **Hardening.** Free blocks live in out-of-band bitmaps, so user writes cannot corrupt allocator state, and double frees are caught when they reach the bitmap. Every segment ends in a guard page (`MADV_GUARD_INSTALL`, or `mprotect`). Refills, block order and segment placement are randomized with a `getrandom` seed.
- **fork.** `pthread_atfork` handlers keep the heap usable in children forked while other threads allocate.

Status: **research prototype**. Not recommended for production.

**Platform contract** ([docs/platform.md](docs/platform.md)): Linux 7.0 or newer, 64-bit little-endian userspace, on x86_64 (**x86-64-v3 or newer**), aarch64 or riscv64 (RV64GC, Zbb optional). Every other target, and any x86_64 build below x86-64-v3, fails at compile time with a message saying why. `.cargo/config.toml` builds x86_64 with `-C target-cpu=x86-64-v3`; a `RUSTFLAGS` variable replaces it and must carry that flag too, and crates depending on allocatbelt (OxiBelt) must set it in their own build. At start-up the allocator probes the kernel facilities it cannot run without (reservation, commit, `MADV_DONTNEED` zeroing) and aborts with a message if one is missing. x86_64 and aarch64 are tested natively in CI (`ubuntu-26.04` and `ubuntu-26.04-arm` runners); riscv64 is tested in CI under qemu-user, with and without Zbb; the `platform-gates` job checks that the supported targets build and the others are rejected.
For the conclusions and recommendations see [docs/research/README.md](docs/research/README.md), for measurements see [docs/research/benchmarks.md](docs/research/benchmarks.md), and for the unsafe inventory see [docs/unsafe-boundary.md](docs/unsafe-boundary.md).

## Verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --release --locked                                   # model tests + global-allocator integration tests
scripts/check-platform-gates.sh                                 # supported targets build, others are rejected (needs `rustup target add`, see the script)
cargo audit && cargo deny check                                 # RustSec advisories, licenses, bans, sources
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p allocatbelt-core
scripts/run-mutation-testing.sh                                 # mewt campaign over `allocatbelt-core` bits/classes
RUSTFLAGS="--cfg loom" cargo test --release -p allocatbelt-core --lib loom   # loom models of the lock-free protocols
(cd fuzz && cargo +nightly fuzz run heap_ops)                   # cargo-fuzz over the checked heap model; see fuzz/README.md
cargo run --release -p allocatbelt-bench --bin bench-allocatbelt   # also bench-system, bench-mimalloc (built for x86-64-v3)
```

Code style, pinned tool versions and the commit-message format follow OxiBelt; see [CONTRIBUTING.md](CONTRIBUTING.md).

### RISC-V (riscv64)

`.cargo/config.toml` sets the linker and a qemu-user runner for `riscv64gc-unknown-linux-gnu`, so the tests can run on an x86_64 host. The runner uses `-cpu max`, which provides Zbb for the second command and the RVA23 extensions that Ubuntu 26.04's riscv64 cross glibc is built for, so both commands below run. Use qemu 10.2.1 or later (Ubuntu 26.04's `qemu-user`): qemu 8.2 intermittently crashes with `QEMU internal SIGSEGV` on the multithreaded tests.

```sh
sudo apt-get install qemu-user gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
rustup target add riscv64gc-unknown-linux-gnu
cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt-arch -p allocatbelt-core -p allocatbelt
RUSTFLAGS="-C target-feature=+zbb" cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt-arch -p allocatbelt-core -p allocatbelt
```

- Build with `-C target-feature=+zbb` (part of the RVA22 profile) when the hardware has it. Without Zbb, the bitmap scans' `trailing_zeros`/`count_ones`/`leading_zeros` compile to multi-instruction sequences instead of `ctz`/`cpop`/`clz`.
- The fixed 64 KiB granule is a multiple of every Linux page size (4, 16 and 64 KiB), so the kernel's page size does not matter. Under Sv39 the user address space is 256 GiB, so the 64 GiB arena reservation (`PROT_NONE`, `MAP_NORESERVE`, no RSS) takes a quarter of it. Sv48/Sv57 leave plenty of room.
- The `bench` crate builds secure mimalloc from C, so cross-building it needs a riscv64 C compiler (`CC_riscv64gc_unknown_linux_gnu=riscv64-linux-gnu-gcc`). Throughput on riscv64 has not been measured, since qemu numbers are meaningless.
