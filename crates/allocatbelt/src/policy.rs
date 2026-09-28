//! Run-time policy for the optional parts (directive §6): which of the
//! compiled capabilities a process uses, set with
//! [`Allocatbelt::configure`] after its early allocations.
//!
//! The policy only moves downward from what was compiled in: a part that is
//! not compiled cannot be selected, and `Require` of one fails. Allocation
//! itself (layout, ownership, hardening) never depends on it, so allocations
//! made before [`Allocatbelt::configure`], under the default policy, stay
//! valid whatever is configured later.
//!
//! The whole configuration is one atomic word, so `configure` is
//! allocation-free, never blocks, and is fork-safe: the maintenance thread's
//! start freezes the parts it is built from (`scheduler`, `io_uring`) by
//! moving the word's phase, and `rseq`, whose shard hints are only a
//! preference, and `experimental_isa`, whose kernels compute the same
//! results as the baseline, stay switchable at any time.

use core::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Allocatbelt;

/// How the process uses one optional capability. Only a capability compiled
/// in ([`crate::CompiledCapabilities`]) can be used.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum FeaturePolicy {
  /// The allocator's qualified default for this build and environment,
  /// which is not necessarily `Prefer`: see [`Policy`] for each capability.
  #[default]
  Auto,
  /// Use it where the system allows; fall back safely where not.
  Prefer,
  /// Use it, or fail: [`Allocatbelt::configure`] fails if it is not
  /// compiled in (or, where that can be checked then, not available), and
  /// the operation that sets it up fails if it cannot be made effective.
  Require,
  /// Never use it, even where it is compiled in and available.
  Disable,
}

impl FeaturePolicy {
  const fn to_bits(self) -> u32 {
    match self {
      Self::Auto => 0,
      Self::Prefer => 1,
      Self::Require => 2,
      Self::Disable => 3,
    }
  }

  const fn from_bits(bits: u32) -> Self {
    match bits & FIELD {
      1 => Self::Prefer,
      2 => Self::Require,
      3 => Self::Disable,
      _ => Self::Auto,
    }
  }

  /// Whether the capability is asked for (`Prefer` or `Require`).
  #[cfg(any(feature = "io-uring", feature = "experimental-rseq"))]
  pub(crate) const fn wanted(self) -> bool {
    matches!(self, Self::Prefer | Self::Require)
  }
}

impl fmt::Display for FeaturePolicy {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Auto => "auto",
      Self::Prefer => "prefer",
      Self::Require => "require",
      Self::Disable => "disable",
    })
  }
}

/// The run-time policy of the optional capabilities.
///
/// | Field | Needs | `Auto` means | Applied |
/// |---|---|---|---|
/// | `scheduler` | feature `scheduler` | `Prefer`: ask for `SCHED_BATCH`, keep the default policy if refused | when the maintenance thread starts |
/// | `io_uring` | feature `io-uring` | off: purge with `madvise` (the ring has not won in measurements) | when the maintenance thread starts |
/// | `rseq` | feature `experimental-rseq` | off (experimental, not qualified) | at once, switchable at any time |
/// | `experimental_isa` | feature `experimental-aarch64-sve` or `-sve2` on aarch64, `experimental-riscv-rvv` on riscv64 | off: the baseline kernels (the experimental ones are not measured) | at once, switchable at any time |
///
/// The maintenance thread itself has no field: the application starts it
/// with [`Allocatbelt::start_maintenance_thread`], or not. The purge delay
/// stays adjustable at any time with [`Allocatbelt::set_purge_delay`].
///
/// Build one from [`Policy::DEFAULT`] and set the fields that matter.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Policy {
  /// Whether the maintenance thread runs as `SCHED_BATCH`.
  pub scheduler: FeaturePolicy,
  /// Whether the maintenance thread purges through a restricted io_uring.
  pub io_uring: FeaturePolicy,
  /// Whether cache refills pick shards by the rseq `mm_cid`
  /// (experimental).
  pub rseq: FeaturePolicy,
  /// Whether experimental architecture kernels are used where compiled in
  /// and supported by the CPU ([`crate::KernelSet`]): `Prefer` and
  /// `Require` select the best one (SVE2 over SVE on aarch64, RVV on
  /// riscv64), `Auto` and `Disable` keep the baseline.
  pub experimental_isa: FeaturePolicy,
}

impl Policy {
  /// Every capability at [`FeaturePolicy::Auto`]: the policy of a process
  /// that configures nothing, and of every allocation before
  /// [`Allocatbelt::configure`].
  pub const DEFAULT: Self = Self {
    scheduler: FeaturePolicy::Auto,
    io_uring: FeaturePolicy::Auto,
    rseq: FeaturePolicy::Auto,
    experimental_isa: FeaturePolicy::Auto,
  };
}

/// An optional capability, as named in errors and reports.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
  /// The maintenance thread (feature `maintenance`).
  Maintenance,
  /// `SCHED_BATCH` for the maintenance thread (feature `scheduler`).
  Scheduler,
  /// The io_uring purge ring (feature `io-uring`).
  IoUring,
  /// Shard selection by the rseq `mm_cid` (feature `experimental-rseq`).
  Rseq,
  /// Experimental architecture kernels (features
  /// `experimental-aarch64-sve` and `experimental-aarch64-sve2` on aarch64,
  /// `experimental-riscv-rvv` on riscv64).
  ExperimentalIsa,
}

impl Capability {
  /// The capability's name in reports.
  #[must_use]
  pub const fn name(self) -> &'static str {
    match self {
      Self::Maintenance => "maintenance",
      Self::Scheduler => "scheduler",
      Self::IoUring => "io_uring",
      Self::Rseq => "rseq",
      Self::ExperimentalIsa => "experimental_isa",
    }
  }

  /// The Cargo feature that compiles it in (for `ExperimentalIsa`, the one
  /// for the architecture of this build).
  #[must_use]
  pub const fn feature(self) -> &'static str {
    match self {
      Self::Maintenance => "maintenance",
      Self::Scheduler => "scheduler",
      Self::IoUring => "io-uring",
      Self::Rseq => "experimental-rseq",
      Self::ExperimentalIsa if cfg!(target_arch = "riscv64") => "experimental-riscv-rvv",
      Self::ExperimentalIsa => "experimental-aarch64-sve",
    }
  }
}

impl fmt::Display for Capability {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.name())
  }
}

/// Why a policy could not be applied. Nothing is changed when one is
/// returned.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
  /// `Require` of a capability this build does not contain.
  NotCompiled {
    /// The capability.
    capability: Capability,
  },
  /// `Require` of a capability the system does not provide: `step` is the
  /// operation that failed, `errno` the kernel's error code (0 when there
  /// was none). The error is reported as found; an `EPERM` may come from a
  /// seccomp filter or from something else.
  Unavailable {
    /// The capability.
    capability: Capability,
    /// The operation that failed.
    step: &'static str,
    /// The kernel's error code, or 0.
    errno: i32,
  },
  /// A change to a capability the maintenance thread was already built
  /// with (it is starting or running).
  Frozen {
    /// The capability.
    capability: Capability,
  },
}

impl fmt::Display for PolicyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::NotCompiled { capability } => write!(
        f,
        "allocatbelt: {capability} is required but not compiled in (Cargo feature `{}`)",
        capability.feature()
      ),
      Self::Unavailable {
        capability,
        step,
        errno,
      } => write!(
        f,
        "allocatbelt: {capability} is required but unavailable ({step} failed, errno {errno})"
      ),
      Self::Frozen { capability } => write!(
        f,
        "allocatbelt: {capability} cannot change after the maintenance thread started"
      ),
    }
  }
}

impl std::error::Error for PolicyError {}

/// Phase of the maintenance thread, in the low byte of [`WORD`]: the
/// `scheduler` and `io_uring` policies are frozen unless it is `IDLE`.
pub(crate) const IDLE: u32 = 0;
#[cfg(any(test, feature = "maintenance"))]
pub(crate) const STARTING: u32 = 1;
pub(crate) const RUNNING: u32 = 2;

const SCHEDULER: u32 = 8;
const IO_URING: u32 = 10;
const RSEQ: u32 = 12;
const ISA: u32 = 14;
/// Each [`FeaturePolicy`] takes two bits.
const FIELD: u32 = 0b11;

/// Phase in the low byte, then two bits per [`FeaturePolicy`]: all `Auto`
/// and `IDLE` at start-up.
static WORD: AtomicU32 = AtomicU32::new(0);

const fn pack(phase: u32, p: Policy) -> u32 {
  phase
    | p.scheduler.to_bits() << SCHEDULER
    | p.io_uring.to_bits() << IO_URING
    | p.rseq.to_bits() << RSEQ
    | p.experimental_isa.to_bits() << ISA
}

const fn unpack(word: u32) -> (u32, Policy) {
  (
    word & 0xff,
    Policy {
      scheduler: FeaturePolicy::from_bits(word >> SCHEDULER),
      io_uring: FeaturePolicy::from_bits(word >> IO_URING),
      rseq: FeaturePolicy::from_bits(word >> RSEQ),
      experimental_isa: FeaturePolicy::from_bits(word >> ISA),
    },
  )
}

/// The current policy and the maintenance thread's phase.
pub(crate) fn current() -> (u32, Policy) {
  unpack(WORD.load(Ordering::Acquire))
}

/// Updates the word with `f`, which sees the phase and policy and returns
/// the new ones or an error; retried on a concurrent update.
fn update(
  mut f: impl FnMut(u32, Policy) -> Result<(u32, Policy), PolicyError>,
) -> Result<(u32, Policy), PolicyError> {
  let mut cur = WORD.load(Ordering::Acquire);
  loop {
    let (phase, policy) = unpack(cur);
    let (phase, policy) = f(phase, policy)?;
    match WORD.compare_exchange_weak(
      cur,
      pack(phase, policy),
      Ordering::AcqRel,
      Ordering::Acquire,
    ) {
      Ok(_) => return Ok((phase, policy)),
      Err(now) => cur = now,
    }
  }
}

/// Moves the phase from `IDLE` to `STARTING` and returns the policy the
/// maintenance thread is to be built with, or `None` if it is already
/// starting or running.
#[cfg(feature = "maintenance")]
pub(crate) fn begin_start() -> Option<Policy> {
  update(|phase, policy| {
    if phase == IDLE {
      Ok((STARTING, policy))
    } else {
      Err(PolicyError::Frozen {
        capability: Capability::Maintenance,
      })
    }
  })
  .ok()
  .map(|(_, p)| p)
}

/// Sets the phase (`RUNNING` after a start, `IDLE` after a failed one or in
/// a forked child), keeping the policy.
#[cfg(feature = "maintenance")]
pub(crate) fn set_phase(phase: u32) {
  let _ = update(|_, policy| Ok((phase, policy)));
}

/// Whether cache refills pick shards by `mm_cid` (the policy asks for it;
/// the caller checks availability).
#[cfg(feature = "experimental-rseq")]
#[inline]
pub(crate) fn rseq_wanted() -> bool {
  let bits = WORD.load(Ordering::Relaxed) >> RSEQ;
  FeaturePolicy::from_bits(bits).wanted()
}

/// Sets only the `rseq` policy (never frozen).
#[cfg(feature = "experimental-rseq")]
pub(crate) fn set_rseq(rseq: FeaturePolicy) {
  let _ = update(|phase, policy| Ok((phase, Policy { rseq, ..policy })));
}

/// The `experimental_isa` policy, for the kernel dispatch.
#[inline]
pub(crate) fn experimental_isa() -> FeaturePolicy {
  FeaturePolicy::from_bits(WORD.load(Ordering::Relaxed) >> ISA)
}

/// Checks `Require` against what is compiled in, and what can be checked
/// now: whether `mm_cid` can be read and whether the CPU exposes an
/// extension an experimental kernel is compiled for. `scheduler` and
/// `io_uring` are checked when the maintenance thread starts.
fn validate(p: Policy) -> Result<(), PolicyError> {
  let compiled = crate::CompiledCapabilities::CURRENT;
  for (capability, policy, compiled) in [
    (Capability::Scheduler, p.scheduler, compiled.scheduler),
    (Capability::IoUring, p.io_uring, compiled.io_uring),
    (Capability::Rseq, p.rseq, compiled.rseq),
    (
      Capability::ExperimentalIsa,
      p.experimental_isa,
      crate::arch::EXPERIMENTAL_COMPILED,
    ),
  ] {
    if policy == FeaturePolicy::Require && !compiled {
      return Err(PolicyError::NotCompiled { capability });
    }
  }
  #[cfg(feature = "experimental-rseq")]
  if p.rseq == FeaturePolicy::Require
    && let Err(e) = crate::rseq::available()
  {
    return Err(PolicyError::Unavailable {
      capability: Capability::Rseq,
      step: e.step(),
      errno: 0,
    });
  }
  if p.experimental_isa == FeaturePolicy::Require
    && crate::arch::experimental(crate::arch::detected_features()).is_none()
  {
    return Err(PolicyError::Unavailable {
      capability: Capability::ExperimentalIsa,
      step: ISA_STEP,
      errno: 0,
    });
  }
  Ok(())
}

/// The step of an unavailable experimental kernel: the CPU or kernel does
/// not expose the extension (`AT_HWCAP`).
pub(crate) const ISA_STEP: &str = "cpu features";

impl Allocatbelt {
  /// Sets the run-time policy of the optional capabilities, after the
  /// early allocations (which use [`Policy::DEFAULT`]) and typically once
  /// the application has read its configuration. Allocation-free, and
  /// either applies the whole policy or nothing.
  ///
  /// `scheduler` and `io_uring` take effect when the maintenance thread
  /// starts, and are frozen from then on; `rseq` takes effect at each
  /// thread's next cache refill, `experimental_isa` at once, and both may
  /// change at any time.
  ///
  /// # Errors
  ///
  /// - [`PolicyError::NotCompiled`]: `Require` of a capability this build
  ///   does not contain.
  /// - [`PolicyError::Unavailable`]: `rseq` is `Require`d but `mm_cid`
  ///   cannot be read here, or `experimental_isa` is `Require`d but the
  ///   CPU does not expose an extension an experimental kernel is compiled
  ///   for.
  /// - [`PolicyError::Frozen`]: `scheduler` or `io_uring` differ from the
  ///   policy the maintenance thread was started with.
  pub fn configure(self, policy: Policy) -> Result<(), PolicyError> {
    validate(policy)?;
    update(|phase, old| {
      if phase != IDLE {
        if policy.scheduler != old.scheduler {
          return Err(PolicyError::Frozen {
            capability: Capability::Scheduler,
          });
        }
        if policy.io_uring != old.io_uring {
          return Err(PolicyError::Frozen {
            capability: Capability::IoUring,
          });
        }
      }
      Ok((phase, policy))
    })
    .map(|_| ())
  }

  /// The policy set last with [`Allocatbelt::configure`] (or the
  /// shorthands `set_io_uring` and `set_rseq_policy`).
  #[must_use]
  pub fn policy(self) -> Policy {
    current().1
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn policies_round_trip_through_the_word() {
    let all = [
      FeaturePolicy::Auto,
      FeaturePolicy::Prefer,
      FeaturePolicy::Require,
      FeaturePolicy::Disable,
    ];
    for scheduler in all {
      for io_uring in all {
        for rseq in all {
          for experimental_isa in all {
            let p = Policy {
              scheduler,
              io_uring,
              rseq,
              experimental_isa,
            };
            for phase in [IDLE, STARTING, RUNNING] {
              assert_eq!(unpack(pack(phase, p)), (phase, p));
            }
          }
        }
      }
    }
    assert_eq!(pack(IDLE, Policy::DEFAULT), 0);
  }
}
