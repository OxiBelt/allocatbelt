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
//! - `global`: the `GlobalAlloc` adapter that joins them.
//!
//! Every `unsafe` site is listed in `docs/unsafe-boundary.md`.

// On a target without Linux, which the platform gates reject anyway, the
// crate is `no_std`: such a target may have no `std` (bare metal), and a
// missing `std` prelude would stop the build before the gates' messages.
#![cfg_attr(not(target_os = "linux"), no_std)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod arch;
mod core;
mod global;
#[cfg(feature = "experimental-rseq")]
mod rseq;
mod sys;

pub use crate::arch::{CpuFeatures, KernelSet};
pub use crate::core::MaintenanceStats;
pub use crate::global::{Allocatbelt, PurgeBackend};
#[cfg(feature = "experimental-rseq")]
pub use crate::rseq::{RseqPolicy, RseqStatus, RseqUnavailable};
pub use crate::sys::{Capabilities, KernelVersion, RingError};
