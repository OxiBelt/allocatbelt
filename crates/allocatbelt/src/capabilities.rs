//! What this build contains: the optional parts selected with Cargo
//! features (directive §6.2).

use crate::Allocatbelt;

/// The optional parts compiled into this build of allocatbelt, one field per
/// Cargo feature with code behind it. Fixed at compile time; what the
/// running system supports is [`Allocatbelt::platform`], and what is in use
/// is reported by the methods of each part.
///
/// Only parts with an implementation have a field, and an ISA backend
/// counts as compiled only on the architecture it is for: the SVE features
/// compile nothing on x86_64 or riscv64, the RVV feature nothing on x86_64
/// or aarch64. Fields may be added as features
/// are.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledCapabilities {
  /// Feature `runtime`: the safe bounded blocking worker runtime.
  pub runtime: bool,
  /// Feature `runtime-io-uring`: bounded owned-buffer positional file I/O.
  /// A separate driver must start successfully before it accepts operations.
  pub runtime_io_uring: bool,
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
  /// Feature `experimental-aarch64-sve` on aarch64: the SVE kernels
  /// ([`crate::KernelSet::Sve`]; experimental, off unless selected at run
  /// time).
  pub experimental_aarch64_sve: bool,
  /// Feature `experimental-aarch64-sve2` on aarch64: the SVE2 kernels
  /// ([`crate::KernelSet::Sve2`]; experimental, off unless selected at run
  /// time).
  pub experimental_aarch64_sve2: bool,
  /// Feature `experimental-riscv-rvv` on riscv64: the V kernel
  /// ([`crate::KernelSet::Rvv`]; experimental, needs nightly Rust, off
  /// unless selected at run time).
  pub experimental_riscv_rvv: bool,
}

impl CompiledCapabilities {
  /// The capabilities of this build.
  pub const CURRENT: Self = Self {
    runtime: cfg!(feature = "runtime"),
    runtime_io_uring: cfg!(feature = "runtime-io-uring"),
    maintenance: cfg!(feature = "maintenance"),
    scheduler: cfg!(feature = "scheduler"),
    io_uring: cfg!(feature = "io-uring"),
    rseq: cfg!(feature = "experimental-rseq"),
    experimental_aarch64_sve: cfg!(all(
      target_arch = "aarch64",
      feature = "experimental-aarch64-sve"
    )),
    experimental_aarch64_sve2: cfg!(all(
      target_arch = "aarch64",
      feature = "experimental-aarch64-sve2"
    )),
    experimental_riscv_rvv: cfg!(all(
      target_arch = "riscv64",
      feature = "experimental-riscv-rvv"
    )),
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
