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

use crate::sys::MmCid;
pub use crate::sys::RseqUnavailable;

use crate::Allocatbelt;
use crate::policy::{self, FeaturePolicy};

/// Whether cache refills pick shards by the rseq `mm_cid`: the `rseq`
/// field of [`crate::Policy`]. `Auto` does not use `mm_cid` yet: the
/// experiment has not been qualified against real workloads
/// (docs/platform.md). `Require` fails, and changes nothing, where `mm_cid`
/// cannot be read.
pub type RseqPolicy = FeaturePolicy;

/// What [`Allocatbelt::rseq_status`] reports.
#[non_exhaustive]
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

fn probe() -> Result<MmCid, RseqUnavailable> {
  // Allocation-free: a load of glibc's `__rseq_size` and a `getauxval`.
  *PROBE.get_or_init(MmCid::probe)
}

/// Whether this process can read `mm_cid`.
pub(crate) fn available() -> Result<(), RseqUnavailable> {
  probe().map(|_| ())
}

/// The shard the calling thread prefers now (see `Os::shard_hint`).
#[inline]
pub(crate) fn shard_hint() -> Option<usize> {
  if !policy::rseq_wanted() {
    return None;
  }
  let cid = probe().ok()?.current()?;
  usize::try_from(cid).ok()
}

impl Allocatbelt {
  /// Sets only the `rseq` policy (see [`Allocatbelt::configure`]) and
  /// reports the result. Takes effect at each thread's next refill;
  /// switching back and forth is safe at any time.
  ///
  /// # Errors
  ///
  /// With [`FeaturePolicy::Require`], why `mm_cid` cannot be read; the
  /// policy is then unchanged.
  pub fn set_rseq_policy(self, policy: RseqPolicy) -> Result<RseqStatus, RseqUnavailable> {
    if policy == FeaturePolicy::Require {
      available()?;
    }
    policy::set_rseq(policy);
    Ok(self.rseq_status())
  }

  /// The rseq policy, whether `mm_cid` can be read, and whether it is used.
  #[must_use]
  pub fn rseq_status(self) -> RseqStatus {
    let available = available();
    RseqStatus {
      policy: policy::current().1.rseq,
      available,
      active: policy::rseq_wanted() && available.is_ok(),
    }
  }

  /// The calling thread's `mm_cid`, for diagnostics; `None` where it cannot
  /// be read.
  #[must_use]
  pub fn mm_cid(self) -> Option<u32> {
    probe().ok()?.current()
  }
}
