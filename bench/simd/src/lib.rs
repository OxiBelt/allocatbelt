//! Microbenchmarks of candidate SIMD kernels for allocatbelt (plan phase 4).
//!
//! Nothing here is linked into the allocator. The crate measures candidate
//! kernels for allocator operations (plan §7.2, §14) against scalar,
//! compiler auto-vectorized and library baselines, so that a later phase can
//! promote only kernels with evidence behind them. Run it with
//! `cargo run --release -p allocatbelt-simd-bench --bin bench-simd`; see
//! `docs/research/simd-benchmarks.md` for the method and recorded results.

pub mod harness;
pub mod kernels;
pub mod perf;
pub mod segment;
