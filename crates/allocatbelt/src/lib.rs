//! A Linux global allocator whose allocation logic is safe Rust.
//!
//! ```ignore
//! #[global_allocator]
//! static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;
//! ```
//!
//! Only 64-bit little-endian Linux on x86_64, aarch64 and riscv64 is
//! supported, and other builds stop with a `compile_error!`. **On x86_64 the
//! final binary must be built for x86-64-v3 or a newer CPU**, for example with
//! `RUSTFLAGS="-C target-cpu=x86-64-v3"` or a `.cargo/config.toml` in the
//! consuming workspace: Cargo does not apply this package's own build
//! configuration to its dependents. Before it reserves its arena, the
//! allocator checks the kernel facilities it cannot run without and aborts
//! with a message if one is missing (see `docs/platform.md` in the
//! repository).
//!
//! The package keeps the boundaries of the crates it was assembled from as
//! modules:
//!
//! - `core`: the allocation logic, on offsets into a reserved arena.
//!   `forbid(unsafe_code)`, and `core`-only (no `std`); a development
//!   package compiles it as its own `#![no_std]` crate to keep it that way.
//! - `sys`: the syscalls and raw-memory conversions, one `unsafe` operation
//!   per block, and the platform contract.
//! - `arch`: allocation-free CPU feature discovery and kernel dispatch.
//! - `global`: the `GlobalAlloc` adapter that joins them, and
//!   `maintenance`, its background thread.
//!
//! # Cargo features
//!
//! Features decide which optional parts are compiled in; what a process
//! then uses is chosen at run time, within what was compiled
//! ([`CompiledCapabilities`]). All build on stable Rust, except
//! `experimental-riscv-rvv` on riscv64. Allocator
//! correctness and hardening (out-of-band metadata, double-free detection,
//! guard pages, fork handling, the platform probes) are not features.
//!
//! | Feature | Default | Status | Adds |
//! |---|---|---|---|
//! | `maintenance` | yes | stable | the background maintenance thread (`start_maintenance_thread`, `purge_backend`, `PurgeBackend`) |
//! | `scheduler` | yes | stable | runs that thread as `SCHED_BATCH`; implies `maintenance` |
//! | `io-uring` | no | stable, off at run time until `set_io_uring(true)` | batched purges through a restricted io_uring, falling back to `madvise` (`set_io_uring`, `io_uring_error`, `RingError`); implies `maintenance` |
//! | `experimental-rseq` | no | experimental, off at run time until `set_rseq_policy` | shard selection by the rseq `mm_cid`, glibc 2.35+ (`RseqPolicy`, `RseqStatus`) |
//! | `experimental-aarch64-sve` | no | experimental, off at run time until `Policy::experimental_isa` selects it | on aarch64, the decay pass's age scan compiled for SVE ([`KernelSet::Sve`]) |
//! | `experimental-aarch64-sve2` | no | as above; implies `experimental-aarch64-sve` | the same compiled for SVE2 ([`KernelSet::Sve2`]) |
//! | `experimental-riscv-rvv` | no | as above; **nightly Rust on riscv64** (the `v` target feature is unstable), stable elsewhere, where it compiles nothing | on riscv64, the same compiled for the V extension ([`KernelSet::Rvv`]) |
//!
//! Within what was compiled, [`Allocatbelt::configure`] sets the run-time
//! [`Policy`] ([`FeaturePolicy`] `Auto`, `Prefer`, `Require` or `Disable`
//! per capability), and [`Allocatbelt::report`] shows what was compiled,
//! detected and selected. Details, and what happens where the system lacks
//! a facility, are in `docs/features.md` in the repository.
//!
//! Every `unsafe` site is listed in `docs/unsafe-boundary.md`.

// On a target without Linux, which the platform gates reject anyway, the
// crate is `no_std`: such a target may have no `std` (bare metal), and a
// missing `std` prelude would stop the build before the gates' messages.
#![cfg_attr(not(target_os = "linux"), no_std)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]
// The one nightly requirement, only for the experimental RVV kernel on
// riscv64 (directive §5.5): the `v` target feature is unstable in Rust 1.98.
#![cfg_attr(
  all(target_arch = "riscv64", feature = "experimental-riscv-rvv"),
  feature(riscv_target_feature)
)]
// docs.rs (nightly, `--cfg docsrs`) labels feature-gated items with the
// Cargo feature they need.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod arch;
mod capabilities;
mod core;
mod global;
#[cfg(feature = "maintenance")]
mod maintenance;
mod policy;
mod report;
#[cfg(feature = "experimental-rseq")]
mod rseq;
mod sys;

pub use crate::arch::{CpuFeatures, KernelSet};
pub use crate::capabilities::CompiledCapabilities;
pub use crate::core::MaintenanceStats;
pub use crate::global::Allocatbelt;
pub use crate::policy::{Capability, FeaturePolicy, Policy, PolicyError};
pub use crate::report::{
  Availability, DetectedCapabilities, EffectiveProfile, PurgeBackend, Report,
};
#[cfg(feature = "experimental-rseq")]
pub use crate::rseq::{RseqPolicy, RseqStatus, RseqUnavailable};
#[cfg(feature = "io-uring")]
pub use crate::sys::RingError;
pub use crate::sys::{Capabilities, KernelVersion};
