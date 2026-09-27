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

Status: **research prototype**. Only Linux (x86_64 and aarch64 in principle; only x86_64 was tested) is supported. Not recommended for production.
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
