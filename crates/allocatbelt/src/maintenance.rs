//! The maintenance thread (feature `maintenance`): runs the heap's
//! housekeeping passes in the background, as `SCHED_BATCH` with the feature
//! `scheduler`, and purging through a restricted io_uring with the feature
//! `io-uring`. Without the feature the allocating threads run the same
//! passes inline, and the methods below do not exist.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::Allocatbelt;
use crate::global::{HEAP, arena, guarded};

impl Allocatbelt {
  /// Starts the maintenance thread, which from then on runs the
  /// allocator's housekeeping: budget passes when more than 32 MiB of freed
  /// memory is waiting, decay passes that return memory unused for the
  /// purge delay (also while the program is idle), and requested purges
  /// ([`Allocatbelt::request_purge`]). Allocating threads then only record
  /// the work, which keeps `madvise` off the allocation path; they still
  /// purge themselves if 64 MiB pile up. With the feature `scheduler` the
  /// thread runs as `SCHED_BATCH` ([`Allocatbelt::maintenance_is_batch`],
  /// docs/platform.md); it is not pinned to a CPU. It purges with
  /// `madvise`, or, with the feature `io-uring`, in batches through
  /// io_uring after `Allocatbelt::set_io_uring`
  /// ([`Allocatbelt::purge_backend`]).
  ///
  /// Call it from ordinary code (not from inside an allocation). Returns
  /// `Ok(false)` if the thread is already running.
  ///
  /// # Errors
  ///
  /// Returns the error of [`std::thread::Builder::spawn`], or an error if
  /// the arena could not be reserved.
  pub fn start_maintenance_thread(self) -> std::io::Result<bool> {
    if MAINT_THREAD.swap(true, Ordering::AcqRel) {
      return Ok(false);
    }
    if arena().is_none() {
      MAINT_THREAD.store(false, Ordering::Release);
      return Err(std::io::Error::other("allocatbelt: no arena"));
    }
    // Attached before the thread runs, so that frees record work from now
    // on; the recorded work waits until the thread's first round.
    HEAP.attach_maintenance();
    let spawned = std::thread::Builder::new()
      .name("allocatbelt-mnt".into())
      .spawn(|| {
        #[cfg(feature = "scheduler")]
        SCHED_BATCH.store(crate::sys::set_batch_scheduling(), Ordering::Relaxed);
        // Returns only if the thread has no ring.
        #[cfg(feature = "io-uring")]
        uring::maintain();
        BACKEND.store(BACKEND_MADVISE, Ordering::Relaxed);
        loop {
          guarded(|| {
            let _ = HEAP.maintain();
          });
        }
      });
    match spawned {
      Ok(_) => Ok(true),
      Err(e) => {
        HEAP.detach_maintenance();
        MAINT_THREAD.store(false, Ordering::Release);
        Err(e)
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
    match BACKEND.load(Ordering::Relaxed) {
      BACKEND_MADVISE => PurgeBackend::Madvise,
      BACKEND_URING => PurgeBackend::IoUring { sq_rewind: false },
      BACKEND_URING_REWIND => PurgeBackend::IoUring { sq_rewind: true },
      _ => PurgeBackend::NotStarted,
    }
  }

  /// Whether the maintenance thread runs as `SCHED_BATCH`: `false` before
  /// it starts, if the kernel refused (e.g. a seccomp filter), or if the
  /// feature `scheduler` is not compiled in.
  #[must_use]
  pub fn maintenance_is_batch(self) -> bool {
    SCHED_BATCH.load(Ordering::Relaxed)
  }
}

/// How the maintenance thread returns memory to the kernel.
///
/// `IoUring` exists in every build, so that matching on it does not depend
/// on the features another crate turns on; without the feature `io-uring`
/// it is never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeBackend {
  /// No maintenance thread runs: allocating threads purge with `madvise`.
  NotStarted,
  /// The maintenance thread purges page run by page run with `madvise`:
  /// io_uring was not compiled in, turned off or unavailable
  /// (`Allocatbelt::io_uring_error`), or a submission failed.
  Madvise,
  /// The maintenance thread purges in batches through its io_uring;
  /// `sq_rewind` if the kernel took `IORING_SETUP_SQ_REWIND` (Linux 7.0).
  IoUring {
    /// Whether the ring rewinds its submission queue.
    sq_rewind: bool,
  },
}

const BACKEND_NONE: u8 = 0;
const BACKEND_MADVISE: u8 = 1;
const BACKEND_URING: u8 = 2;
const BACKEND_URING_REWIND: u8 = 3;

/// [`PurgeBackend`] of the running maintenance thread.
static BACKEND: AtomicU8 = AtomicU8::new(BACKEND_NONE);
/// Whether the maintenance thread has been started.
static MAINT_THREAD: AtomicBool = AtomicBool::new(false);
/// Whether the maintenance thread runs as `SCHED_BATCH`.
static SCHED_BATCH: AtomicBool = AtomicBool::new(false);

/// In the child after `fork`: the maintenance thread did not survive it.
pub(crate) fn fork_child() {
  MAINT_THREAD.store(false, Ordering::Release);
  SCHED_BATCH.store(false, Ordering::Relaxed);
  BACKEND.store(BACKEND_NONE, Ordering::Relaxed);
}

/// Batched purges through a restricted io_uring (feature `io-uring`).
#[cfg(feature = "io-uring")]
mod uring {
  use std::sync::OnceLock;
  use std::sync::atomic::{AtomicBool, Ordering};

  use super::{BACKEND, BACKEND_MADVISE, BACKEND_URING, BACKEND_URING_REWIND};
  use crate::Allocatbelt;
  use crate::core::{Os as _, PURGE_BATCH, Purger};
  use crate::global::{HEAP, LinuxOs, guarded};
  use crate::sys::{PurgeRing, RingError};

  impl Allocatbelt {
    /// Whether the maintenance thread purges in batches through a
    /// restricted io_uring (`IORING_OP_MADVISE`), or with one `madvise` per
    /// page run, the default. Takes effect when the thread starts. Off by
    /// default because it has not won yet: on the kernels measured so far
    /// each purge takes a detour through a kernel worker thread
    /// (docs/research/benchmarks.md, Phase 8).
    pub fn set_io_uring(self, on: bool) {
      USE_IO_URING.store(on, Ordering::Relaxed);
    }

    /// Why the maintenance thread has no io_uring (`step` is "turned off"
    /// unless [`Allocatbelt::set_io_uring`] asked for one).
    #[must_use]
    pub fn io_uring_error(self) -> Option<RingError> {
      RING_ERROR.get().copied()
    }
  }

  /// Whether the maintenance thread tries io_uring
  /// ([`Allocatbelt::set_io_uring`]).
  static USE_IO_URING: AtomicBool = AtomicBool::new(false);
  /// Why the maintenance thread has no ring.
  static RING_ERROR: OnceLock<RingError> = OnceLock::new();

  /// Ring slots: the most page runs one `io_uring_enter` carries (a pass
  /// batches at most [`PURGE_BATCH`]).
  const RING_ENTRIES: u32 = PURGE_BATCH as u32;
  /// Kernel workers that run the ring's purges at once. More did not help
  /// (`ring_benchmark`): parallel purges of one address space contend.
  const RING_WORKERS: u32 = 1;

  /// Runs the maintenance loop with a ring if one was asked for and can be
  /// set up; returns (having recorded why) if not.
  pub(super) fn maintain() {
    // Created here: the thread that enables the ring is its only
    // submitter.
    let ring = if USE_IO_URING.load(Ordering::Relaxed) {
      PurgeRing::new(RING_ENTRIES, RING_WORKERS, true)
    } else {
      Err(RingError {
        step: "turned off",
        errno: 0,
      })
    };
    match ring {
      Ok(ring) => {
        let mut purger = RingPurger(ring);
        loop {
          purger.publish();
          guarded(|| {
            let _ = HEAP.maintain_with(&mut purger);
          });
        }
      }
      Err(e) => {
        let _ = RING_ERROR.set(e);
      }
    }
  }

  /// The maintenance thread's purger: batches through its own io_uring.
  struct RingPurger(PurgeRing);

  impl RingPurger {
    /// Publishes the backend for [`Allocatbelt::purge_backend`].
    fn publish(&self) {
      let b = match (self.0.retired(), self.0.sq_rewind()) {
        (true, _) => BACKEND_MADVISE,
        (false, false) => BACKEND_URING,
        (false, true) => BACKEND_URING_REWIND,
      };
      BACKEND.store(b, Ordering::Relaxed);
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
