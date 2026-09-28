//! Experimental shard selection by the rseq `mm_cid` (Phase 9, feature
//! `experimental-rseq`).
//!
//! Each thread normally prefers the shard it was given when its cache was
//! attached (round robin). With this selected, a thread's cache refills and
//! other uncached allocations prefer the shard numbered by its current
//! `mm_cid` instead, which the kernel keeps distinct among the threads
//! running at a moment and dense (below the CPUs the process may use), so
//! running threads rarely meet on a shard lock and a process with many more
//! threads than CPUs keeps its memory in fewer shards. The cached fast path
//! is unchanged.
//!
//! It is a preference only: the shard is locked either way, so a thread
//! that migrates between reading its `mm_cid` and using it loses
//! locality, not correctness. There is no rseq critical section to abort.
//! allocatbelt never registers rseq itself; it reads the area glibc
//! registered, and falls back to the per-thread shards where there is none
//! (musl, qemu-user, `glibc.pthread.rseq=0`, kernels without `mm_cid`).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use allocatbelt_sys::MmCid;
pub use allocatbelt_sys::RseqUnavailable;

use crate::Allocatbelt;

/// Whether cache refills pick shards by the rseq `mm_cid`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RseqPolicy {
  /// The allocator decides. It does not use `mm_cid` yet: the experiment
  /// has not been qualified against real workloads (docs/platform.md).
  #[default]
  Auto,
  /// Use `mm_cid` where it can be read, per-thread shards elsewhere.
  Prefer,
  /// As `Prefer`, but [`Allocatbelt::set_rseq_policy`] fails, and changes
  /// nothing, where `mm_cid` cannot be read.
  Require,
  /// Per-thread shards only.
  Disable,
}

/// What [`Allocatbelt::rseq_status`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RseqStatus {
  /// The policy set last.
  pub policy: RseqPolicy,
  /// Whether this process can read `mm_cid`, and if not, why.
  pub available: Result<(), RseqUnavailable>,
  /// Whether cache refills pick shards by `mm_cid` now.
  pub active: bool,
}

/// What [`MmCid::probe`] found; probed once.
static PROBE: OnceLock<Result<MmCid, RseqUnavailable>> = OnceLock::new();
/// The [`RseqPolicy`] set last.
static POLICY: AtomicU8 = AtomicU8::new(RseqPolicy::Auto as u8);
/// Whether [`shard_hint`] reads `mm_cid`.
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn probe() -> Result<MmCid, RseqUnavailable> {
  // Allocation-free: a load of glibc's `__rseq_size` and a `getauxval`.
  *PROBE.get_or_init(MmCid::probe)
}

/// The shard the calling thread prefers now (see `Os::shard_hint`).
#[inline]
pub(crate) fn shard_hint() -> Option<usize> {
  if !ACTIVE.load(Ordering::Relaxed) {
    return None;
  }
  let cid = PROBE.get()?.as_ref().ok()?.current()?;
  usize::try_from(cid).ok()
}

impl Allocatbelt {
  /// Selects whether cache refills pick shards by the rseq `mm_cid`
  /// (experimental; see [`RseqPolicy`]), and reports the result. Takes
  /// effect at each thread's next refill; switching back and forth is
  /// safe at any time.
  ///
  /// # Errors
  ///
  /// With [`RseqPolicy::Require`], why `mm_cid` cannot be read.
  pub fn set_rseq_policy(self, policy: RseqPolicy) -> Result<RseqStatus, RseqUnavailable> {
    let available = probe();
    if policy == RseqPolicy::Require {
      available?;
    }
    let active = matches!(policy, RseqPolicy::Prefer | RseqPolicy::Require) && available.is_ok();
    POLICY.store(policy as u8, Ordering::Relaxed);
    ACTIVE.store(active, Ordering::Relaxed);
    Ok(self.rseq_status())
  }

  /// The rseq policy, whether `mm_cid` can be read, and whether it is used.
  #[must_use]
  pub fn rseq_status(self) -> RseqStatus {
    let policy = match POLICY.load(Ordering::Relaxed) {
      p if p == RseqPolicy::Prefer as u8 => RseqPolicy::Prefer,
      p if p == RseqPolicy::Require as u8 => RseqPolicy::Require,
      p if p == RseqPolicy::Disable as u8 => RseqPolicy::Disable,
      _ => RseqPolicy::Auto,
    };
    RseqStatus {
      policy,
      available: probe().map(|_| ()),
      active: ACTIVE.load(Ordering::Relaxed),
    }
  }

  /// The calling thread's `mm_cid`, for diagnostics; `None` where it cannot
  /// be read.
  #[must_use]
  pub fn mm_cid(self) -> Option<u32> {
    probe().ok()?.current()
  }
}
