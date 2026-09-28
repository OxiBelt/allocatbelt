//! What this build contains: the optional parts selected with Cargo
//! features (directive §6.2).

use crate::Allocatbelt;

/// The optional parts compiled into this build of allocatbelt, one field per
/// Cargo feature with code behind it. Fixed at compile time; what the
/// running system supports is [`Allocatbelt::platform`], and what is in use
/// is reported by the methods of each part.
///
/// Only parts with an implementation have a field: no SIMD or other ISA
/// backend is compiled into any build yet ([`crate::KernelSet`]). Fields
/// may be added as features are.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledCapabilities {
  /// Feature `maintenance`: the background maintenance thread
  /// ([`Allocatbelt::start_maintenance_thread`]). Without it, allocating
  /// threads run every housekeeping pass inline.
  pub maintenance: bool,
  /// Feature `scheduler`: the maintenance thread asks for `SCHED_BATCH`.
  pub scheduler: bool,
  /// Feature `io-uring`: the maintenance thread can purge through a
  /// restricted io_uring (off unless selected at run time).
  pub io_uring: bool,
  /// Feature `experimental-rseq`: shard selection by the rseq `mm_cid`
  /// (experimental, off unless selected at run time).
  pub rseq: bool,
}

impl CompiledCapabilities {
  /// The capabilities of this build.
  pub const CURRENT: Self = Self {
    maintenance: cfg!(feature = "maintenance"),
    scheduler: cfg!(feature = "scheduler"),
    io_uring: cfg!(feature = "io-uring"),
    rseq: cfg!(feature = "experimental-rseq"),
  };
}

impl Allocatbelt {
  /// The optional parts compiled into this build
  /// ([`CompiledCapabilities::CURRENT`]).
  #[must_use]
  pub const fn compiled_capabilities(self) -> CompiledCapabilities {
    CompiledCapabilities::CURRENT
  }
}
