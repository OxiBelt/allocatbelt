//! The maintenance thread (feature `maintenance`): runs the heap's
//! housekeeping passes in the background, as `SCHED_BATCH` with the feature
//! `scheduler`, and purging through a restricted io_uring with the feature
//! `io-uring`, as the [`Policy`](crate::Policy) selects. Without the
//! feature the allocating threads run the same passes inline, and the
//! methods below do not exist.

use std::sync::mpsc;

use crate::Allocatbelt;
use crate::global::{HEAP, arena, guarded};
use crate::policy::{self, Policy, PolicyError};
use crate::report::{self, Availability, PurgeBackend};

impl Allocatbelt {
  /// Starts the maintenance thread, which from then on runs the
  /// allocator's housekeeping: budget passes when more than 32 MiB of freed
  /// memory is waiting, decay passes that return memory unused for the
  /// purge delay (also while the program is idle), and requested purges
  /// ([`Allocatbelt::request_purge`]). Allocating threads then only record
  /// the work, which keeps `madvise` off the allocation path; they still
  /// purge themselves if 64 MiB pile up. It is not pinned to a CPU.
  ///
  /// The thread is built from the current [`Policy`], whose `scheduler`
  /// and `io_uring` are frozen from then on: with the feature `scheduler`
  /// it asks for `SCHED_BATCH` unless `scheduler` is `Disable`
  /// ([`Allocatbelt::maintenance_is_batch`], docs/platform.md), and with the
  /// feature `io-uring` it purges in batches through io_uring if `io_uring`
  /// is `Prefer` or `Require` ([`Allocatbelt::purge_backend`]); `madvise`
  /// otherwise.
  ///
  /// Call it from ordinary code (not from inside an allocation). Returns
  /// once the thread has applied the policy, or `Ok(false)` if it is
  /// already running or starting.
  ///
  /// # Errors
  ///
  /// The error of [`std::thread::Builder::spawn`]; an error if the arena
  /// could not be reserved; or, if a `Require`d capability could not be
  /// made effective, an error of kind [`std::io::ErrorKind::Unsupported`]
  /// that wraps the [`PolicyError`] (`err.get_ref()` and `downcast_ref`).
  /// No thread runs after an error, and the policy stays changeable.
  pub fn start_maintenance_thread(self) -> std::io::Result<bool> {
    let Some(policy) = policy::begin_start() else {
      return Ok(false);
    };
    let failed = |e: std::io::Error| {
      policy::set_phase(policy::IDLE);
      Err(e)
    };
    if arena().is_none() {
      return failed(std::io::Error::other("allocatbelt: no arena"));
    }
    // Attached before the thread runs, so that frees record work from now
    // on; the recorded work waits until the thread's first round.
    HEAP.attach_maintenance();
    // The thread says whether it could apply the policy before it starts
    // its rounds. Called from ordinary code, so the channel may allocate.
    let (tx, rx) = mpsc::sync_channel::<Result<(), PolicyError>>(1);
    let spawned = std::thread::Builder::new()
      .name("allocatbelt-mnt".into())
      .spawn(move || match set_up(policy) {
        Ok(purger) => {
          let _ = tx.send(Ok(()));
          run(purger);
        }
        Err(e) => {
          let _ = tx.send(Err(e));
        }
      });
    let applied = match spawned {
      Ok(thread) => match rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
          let _ = thread.join();
          Err(std::io::Error::new(std::io::ErrorKind::Unsupported, e))
        }
        Err(_) => Err(std::io::Error::other(
          "allocatbelt: maintenance thread lost",
        )),
      },
      Err(e) => {
        report::MAINTENANCE.record(Availability::Unavailable {
          step: "spawn",
          errno: e.raw_os_error().unwrap_or(0),
        });
        Err(e)
      }
    };
    match applied {
      Ok(()) => {
        report::MAINTENANCE.record(Availability::Available);
        policy::set_phase(policy::RUNNING);
        Ok(true)
      }
      Err(e) => {
        HEAP.detach_maintenance();
        failed(e)
      }
    }
  }

  /// The former name of [`Allocatbelt::start_maintenance_thread`].
  ///
  /// # Errors
  ///
  /// As [`Allocatbelt::start_maintenance_thread`].
  pub fn start_purge_thread(self) -> std::io::Result<bool> {
    self.start_maintenance_thread()
  }

  /// How the maintenance thread returns memory.
  #[must_use]
  pub fn purge_backend(self) -> PurgeBackend {
    report::purge_backend()
  }

  /// Whether the maintenance thread runs as `SCHED_BATCH`: `false` before
  /// it starts, if the kernel refused (e.g. a seccomp filter), if the
  /// policy disables it, or if the feature `scheduler` is not compiled in.
  #[must_use]
  pub fn maintenance_is_batch(self) -> bool {
    self.effective_profile().scheduler
  }
}

/// On the new thread: applies the scheduler and io_uring policies, and
/// returns the ring to purge with, if any.
fn set_up(policy: Policy) -> Result<Purger, PolicyError> {
  #[cfg(feature = "scheduler")]
  if policy.scheduler != crate::FeaturePolicy::Disable {
    // `Auto` asks too: `SCHED_BATCH` is the qualified default (plan
    // Phase 7), and a refusal only keeps the default policy.
    let r = crate::sys::set_batch_scheduling();
    report::SCHEDULER.record(match r {
      Ok(()) => Availability::Available,
      Err(errno) => Availability::Unavailable {
        step: "sched_setscheduler",
        errno,
      },
    });
    if let Err(errno) = r
      && policy.scheduler == crate::FeaturePolicy::Require
    {
      return Err(PolicyError::Unavailable {
        capability: crate::Capability::Scheduler,
        step: "sched_setscheduler",
        errno,
      });
    }
  }
  #[cfg(feature = "io-uring")]
  return uring::set_up(policy);
  #[cfg(not(feature = "io-uring"))]
  {
    let _ = policy;
    Ok(())
  }
}

#[cfg(feature = "io-uring")]
type Purger = Option<uring::RingPurger>;
#[cfg(not(feature = "io-uring"))]
type Purger = ();

/// The thread's rounds, never returning.
fn run(purger: Purger) -> ! {
  #[cfg(feature = "io-uring")]
  if let Some(purger) = purger {
    uring::run(purger);
  }
  #[cfg(not(feature = "io-uring"))]
  let () = purger;
  report::BACKEND.store(
    report::BACKEND_MADVISE,
    std::sync::atomic::Ordering::Relaxed,
  );
  loop {
    guarded(|| {
      let _ = HEAP.maintain();
    });
  }
}

/// In the child after `fork`: the maintenance thread did not survive it.
pub(crate) fn fork_child() {
  policy::set_phase(policy::IDLE);
  report::fork_child();
}

/// Batched purges through a restricted io_uring (feature `io-uring`).
#[cfg(feature = "io-uring")]
mod uring {
  use std::sync::atomic::Ordering;

  use crate::core::{Os as _, PURGE_BATCH, Purger};
  use crate::global::{HEAP, LinuxOs, guarded};
  use crate::policy::{self, FeaturePolicy, Policy, PolicyError};
  use crate::report::{self, Availability, BACKEND_MADVISE, BACKEND_URING, BACKEND_URING_REWIND};
  use crate::sys::{PurgeRing, RingError};
  use crate::{Allocatbelt, Capability};

  impl Allocatbelt {
    /// Shorthand for setting only the `io_uring` field of the
    /// [`Policy`](crate::Policy): `true` is `Prefer` (use the ring where
    /// it can be set up, `madvise` elsewhere), `false` is `Auto`, which
    /// purges with `madvise` because the ring has not won in measurements
    /// yet (docs/research/benchmarks.md, Phase 8).
    ///
    /// # Errors
    ///
    /// [`PolicyError::Frozen`] once the maintenance thread has started; the
    /// policy is then unchanged. (Before the policy API, this was ignored
    /// silently.)
    pub fn set_io_uring(self, on: bool) -> Result<(), PolicyError> {
      let mut p = policy::current().1;
      p.io_uring = if on {
        FeaturePolicy::Prefer
      } else {
        FeaturePolicy::Auto
      };
      self.configure(p)
    }

    /// Why the maintenance thread has no io_uring: the failed step and
    /// errno, or `step` "turned off" when the policy did not ask for one.
    /// `None` before the thread started, or while it uses the ring.
    #[must_use]
    pub fn io_uring_error(self) -> Option<RingError> {
      match report::IO_URING.get(true) {
        Availability::Unavailable { step, errno } => Some(RingError { step, errno }),
        Availability::NotTried if self.effective_profile().maintenance => Some(RingError {
          step: "turned off",
          errno: 0,
        }),
        _ => None,
      }
    }
  }

  /// Ring slots: the most page runs one `io_uring_enter` carries (a pass
  /// batches at most [`PURGE_BATCH`]).
  const RING_ENTRIES: u32 = PURGE_BATCH as u32;
  /// Kernel workers that run the ring's purges at once. More did not help
  /// (`ring_benchmark`): parallel purges of one address space contend.
  const RING_WORKERS: u32 = 1;

  /// Sets up the ring if the policy asks for one. Created here: the thread
  /// that enables the ring is its only submitter.
  pub(super) fn set_up(policy: Policy) -> Result<Option<RingPurger>, PolicyError> {
    if !policy.io_uring.wanted() {
      return Ok(None);
    }
    match PurgeRing::new(RING_ENTRIES, RING_WORKERS, true) {
      Ok(ring) => {
        report::IO_URING.record(Availability::Available);
        Ok(Some(RingPurger(ring)))
      }
      Err(e) => {
        report::IO_URING.record(Availability::Unavailable {
          step: e.step,
          errno: e.errno,
        });
        if policy.io_uring == FeaturePolicy::Require {
          return Err(PolicyError::Unavailable {
            capability: Capability::IoUring,
            step: e.step,
            errno: e.errno,
          });
        }
        Ok(None)
      }
    }
  }

  /// The rounds with the ring.
  pub(super) fn run(mut purger: RingPurger) -> ! {
    loop {
      purger.publish();
      guarded(|| {
        let _ = HEAP.maintain_with(&mut purger);
      });
    }
  }

  /// The maintenance thread's purger: batches through its own io_uring.
  pub(super) struct RingPurger(PurgeRing);

  impl RingPurger {
    /// Publishes the backend for [`Allocatbelt::purge_backend`].
    fn publish(&self) {
      let b = match (self.0.retired(), self.0.sq_rewind()) {
        (true, _) => BACKEND_MADVISE,
        (false, false) => BACKEND_URING,
        (false, true) => BACKEND_URING_REWIND,
      };
      report::BACKEND.store(b, Ordering::Relaxed);
    }
  }

  impl Purger for RingPurger {
    fn batch_size(&self) -> usize {
      PURGE_BATCH
    }

    fn purge_batch(&mut self, ranges: &[(usize, usize)], purged: &mut [bool]) {
      // SAFETY: the `Purger` contract of the core: the heap has
      // claimed every range, so none holds a live allocation and nothing
      // hands one out until this returns, and `PurgeRing::purge` returns
      // only after every purge has completed.
      #[expect(unsafe_code, reason = "returning unused memory to the kernel")]
      let r = unsafe { self.0.purge(&LinuxOs.arena().user, ranges, purged) };
      if r.is_err() {
        // Purges may still run on pages the heap is about to reuse.
        LinuxOs.fatal("allocatbelt: lost track of io_uring purges");
      }
    }
  }
}
