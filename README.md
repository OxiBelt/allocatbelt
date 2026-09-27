# allocatbelt

A Rust-based alternative to mimalloc (C) for [OxiBelt](https://github.com/OxiBelt/OxiBelt): research and a prototype.

- **Allocation logic is safe Rust.** `allocatbelt-core` is `#![no_std]` + `#![forbid(unsafe_code)]`.
- **`unsafe` lives only at the syscall and raw-memory boundaries.** That means `allocatbelt-sys` (mmap/mprotect/madvise, exposing metadata as atomics) and the `GlobalAlloc` adapter in `allocatbelt`.
- The workspace lints are copied from OxiBelt (`unsafe_code = deny`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `missing_safety_doc`).

```text
crates/allocatbelt-core   Allocation logic (offsets, bitmaps, size classes, segments/pages). No unsafe.
crates/allocatbelt-sys    Arena reservation/commit/purge and the metadata slab. The only unsafe boundary.
crates/allocatbelt        #[global_allocator] adapter (Allocatbelt).
bench/                    Comparison against system and secure mimalloc.
docs/                     Research reports, benchmark results, unsafe inventory.
```

```rust
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;
```

Status: **research prototype**. Only 64-bit Linux is supported: x86_64, aarch64 and riscv64. x86_64 and aarch64 are tested natively in CI (`ubuntu-26.04` and `ubuntu-26.04-arm` runners); riscv64 is tested in CI under qemu-user, with and without Zbb. 32-bit targets (including riscv32) are rejected at compile time. Not recommended for production.
For the conclusions and recommendations see [docs/research/README.md](docs/research/README.md), for measurements see [docs/research/benchmarks.md](docs/research/benchmarks.md), and for the unsafe inventory see [docs/unsafe-boundary.md](docs/unsafe-boundary.md).

## Verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --release --locked                                   # model tests + global-allocator integration tests
cargo audit && cargo deny check                                 # RustSec advisories, licenses, bans, sources
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p allocatbelt-core
scripts/run-mutation-testing.sh                                 # mewt campaign over `allocatbelt-core` bits/classes
cargo run --release -p allocatbelt-bench --bin bench-allocatbelt   # also bench-system, bench-mimalloc
```

Code style, pinned tool versions and the commit-message format follow OxiBelt; see [CONTRIBUTING.md](CONTRIBUTING.md).

### RISC-V (riscv64)

`.cargo/config.toml` sets the linker and a qemu-user runner for `riscv64gc-unknown-linux-gnu`, so the tests can run on an x86_64 host. The runner emulates a CPU with Zbb (`-cpu rv64,zbb=true`), so both commands below run. Use qemu 10.2.1 or later (Ubuntu 26.04's `qemu-user`): qemu 8.2 intermittently crashes with `QEMU internal SIGSEGV` on the multithreaded tests.

```sh
sudo apt-get install qemu-user gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
rustup target add riscv64gc-unknown-linux-gnu
cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt-core -p allocatbelt
RUSTFLAGS="-C target-feature=+zbb" cargo test --release --target riscv64gc-unknown-linux-gnu -p allocatbelt-core -p allocatbelt
```

- Build with `-C target-feature=+zbb` (part of the RVA22 profile) when the hardware has it. Without Zbb, the bitmap scans' `trailing_zeros`/`count_ones`/`leading_zeros` compile to multi-instruction sequences instead of `ctz`/`cpop`/`clz`.
- The fixed 64 KiB granule is a multiple of every Linux page size (4, 16 and 64 KiB), so the kernel's page size does not matter. Under Sv39 the user address space is 256 GiB, so the 64 GiB arena reservation (`PROT_NONE`, `MAP_NORESERVE`, no RSS) takes a quarter of it. Sv48/Sv57 leave plenty of room.
- The `bench` crate builds secure mimalloc from C, so cross-building it needs a riscv64 C compiler (`CC_riscv64gc_unknown_linux_gnu=riscv64-linux-gnu-gcc`). Throughput on riscv64 has not been measured, since qemu numbers are meaningless.
