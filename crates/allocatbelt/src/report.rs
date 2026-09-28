//! Diagnostics of capability resolution (directive §6.3, §7): what a build
//! contains ([`CompiledCapabilities`]), what this process found it can use
//! ([`DetectedCapabilities`]), and what is in use after the policy was
//! applied ([`EffectiveProfile`]), together in a [`Report`].
//!
//! The detection results are kept in atomic words, so recording them never
//! allocates and a forked child can reset them. Reading them is cheap and
//! allocation-free; only formatting a [`Report`] allocates, in the caller.

use core::fmt;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::policy::{self, Policy, RUNNING};
use crate::{Allocatbelt, Capabilities, CompiledCapabilities, CpuFeatures, KernelSet};

/// What this process found about one optional capability.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
  /// This build does not contain it.
  NotCompiled,
  /// Not tried yet: nothing asked for it, or the maintenance thread that
  /// would try it has not started.
  NotTried,
  /// It works here.
  Available,
  /// It does not work here: `step` failed with `errno` (0 when the kernel
  /// reported no error, e.g. a missing feature bit).
  Unavailable {
    /// The operation that failed.
    step: &'static str,
    /// The kernel's error code, or 0.
    errno: i32,
  },
}

impl fmt::Display for Availability {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::NotCompiled => f.write_str("not compiled"),
      Self::NotTried => f.write_str("not tried"),
      Self::Available => f.write_str("available"),
      Self::Unavailable { step, errno: 0 } => write!(f, "unavailable ({step})"),
      Self::Unavailable { step, errno } => write!(f, "unavailable ({step}, errno {errno})"),
    }
  }
}

/// The operations whose failures are recorded, so that a failure fits in
/// one atomic word. `unavailable_steps_are_recorded` checks that every
/// step string of the io_uring ring and the rseq probe is listed.
const STEPS: [&str; 14] = [
  "unknown",
  "spawn",
  "turned off",
  "sched_setscheduler",
  "setup",
  "features",
  "mmap",
  "probe",
  "max workers",
  "restrict",
  "enable",
  "not glibc",
  "not registered",
  "no mm_cid",
];

const NOT_TRIED: u64 = 0;
const AVAILABLE: u64 = 1;
const UNAVAILABLE: u64 = 2;

/// A recorded [`Availability`] (never `NotCompiled`, which is known at
/// compile time): kind in bits 40..48, step index in 32..40, errno below.
pub(crate) struct Detected(AtomicU64);

impl Detected {
  pub(crate) const fn new() -> Self {
    Self(AtomicU64::new(NOT_TRIED))
  }

  pub(crate) fn record(&self, a: Availability) {
    let word = match a {
      Availability::NotCompiled | Availability::NotTried => NOT_TRIED,
      Availability::Available => AVAILABLE << 40,
      Availability::Unavailable { step, errno } => {
        let i = STEPS.iter().position(|s| *s == step).unwrap_or(0) as u64;
        UNAVAILABLE << 40 | i << 32 | u64::from(errno.cast_unsigned())
      }
    };
    self.0.store(word, Ordering::Release);
  }

  pub(crate) fn get(&self, compiled: bool) -> Availability {
    if !compiled {
      return Availability::NotCompiled;
    }
    let word = self.0.load(Ordering::Acquire);
    match word >> 40 {
      AVAILABLE => Availability::Available,
      UNAVAILABLE => Availability::Unavailable {
        step: STEPS[(word >> 32 & 0xff) as usize % STEPS.len()],
        errno: (word as u32).cast_signed(),
      },
      _ => Availability::NotTried,
    }
  }
}

/// Whether the maintenance thread could be spawned.
pub(crate) static MAINTENANCE: Detected = Detected::new();
/// Whether the kernel let the maintenance thread run as `SCHED_BATCH`.
pub(crate) static SCHEDULER: Detected = Detected::new();
/// Whether the maintenance thread could set up its io_uring.
pub(crate) static IO_URING: Detected = Detected::new();

/// How the maintenance thread returns memory to the kernel.
///
/// Every variant exists in every build, so that matching on it does not
/// depend on the features another crate turns on; without the feature
/// `io-uring`, `IoUring` is never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeBackend {
  /// No maintenance thread runs: allocating threads purge with `madvise`.
  NotStarted,
  /// The maintenance thread purges page run by page run with `madvise`:
  /// io_uring was not compiled in, not selected or unavailable, or a
  /// submission failed.
  Madvise,
  /// The maintenance thread purges in batches through its io_uring;
  /// `sq_rewind` if the kernel took `IORING_SETUP_SQ_REWIND` (Linux 7.0).
  IoUring {
    /// Whether the ring rewinds its submission queue.
    sq_rewind: bool,
  },
}

pub(crate) const BACKEND_NONE: u8 = 0;
pub(crate) const BACKEND_MADVISE: u8 = 1;
#[cfg(feature = "io-uring")]
pub(crate) const BACKEND_URING: u8 = 2;
#[cfg(feature = "io-uring")]
pub(crate) const BACKEND_URING_REWIND: u8 = 3;

/// [`PurgeBackend`] of the running maintenance thread.
pub(crate) static BACKEND: AtomicU8 = AtomicU8::new(BACKEND_NONE);

pub(crate) fn purge_backend() -> PurgeBackend {
  match BACKEND.load(Ordering::Relaxed) {
    BACKEND_MADVISE => PurgeBackend::Madvise,
    2 => PurgeBackend::IoUring { sq_rewind: false },
    3 => PurgeBackend::IoUring { sq_rewind: true },
    _ => PurgeBackend::NotStarted,
  }
}

/// In a forked child: the maintenance thread did not survive the fork, and
/// a new one tries its capabilities again.
pub(crate) fn fork_child() {
  BACKEND.store(BACKEND_NONE, Ordering::Relaxed);
  for d in [&MAINTENANCE, &SCHEDULER, &IO_URING] {
    d.record(Availability::NotTried);
  }
}

/// What this process found it can use: the start-up probe, the CPU, and
/// each optional capability that was tried.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedCapabilities {
  /// The mandatory facilities the start-up probe checked, and the kernel
  /// release; `None` if the arena could not be reserved.
  pub platform: Option<Capabilities>,
  /// The ISA extensions this CPU and kernel expose.
  pub cpu_features: CpuFeatures,
  /// Whether the maintenance thread could be spawned.
  pub maintenance: Availability,
  /// Whether the kernel let the maintenance thread run as `SCHED_BATCH`.
  pub scheduler: Availability,
  /// Whether the maintenance thread could set up its restricted io_uring.
  pub io_uring: Availability,
  /// Whether this process can read its rseq `mm_cid` (probed on demand).
  pub rseq: Availability,
  /// Whether the CPU exposes an extension an experimental kernel set is
  /// compiled for (from `cpu_features`).
  pub experimental_isa: Availability,
}

/// What is in use now, after the policy was applied.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveProfile {
  /// The policy set last.
  pub policy: Policy,
  /// Whether `scheduler` and `io_uring` are frozen: the maintenance thread
  /// is starting or running.
  pub frozen: bool,
  /// Whether the maintenance thread runs.
  pub maintenance: bool,
  /// Whether it runs as `SCHED_BATCH`.
  pub scheduler: bool,
  /// How freed memory is returned to the kernel.
  pub purge_backend: PurgeBackend,
  /// Whether cache refills pick shards by `mm_cid`.
  pub rseq: bool,
  /// The architecture kernels in use: [`KernelSet::Baseline`] unless the
  /// `experimental_isa` policy selected an experimental set.
  pub kernel_set: KernelSet,
}

/// Compiled, detected and effective capabilities together; its `Display`
/// renders them for logs and support requests (and allocates, so call it
/// from ordinary code).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
  /// What this build contains.
  pub compiled: CompiledCapabilities,
  /// What this process found.
  pub detected: DetectedCapabilities,
  /// What is in use.
  pub effective: EffectiveProfile,
}

impl Allocatbelt {
  /// What this process found it can use. Initialises the allocator if
  /// nothing has allocated yet. Allocation-free.
  #[must_use]
  pub fn detected_capabilities(self) -> DetectedCapabilities {
    let compiled = CompiledCapabilities::CURRENT;
    DetectedCapabilities {
      platform: self.platform(),
      cpu_features: self.cpu_features(),
      maintenance: MAINTENANCE.get(compiled.maintenance),
      scheduler: SCHEDULER.get(compiled.scheduler),
      io_uring: IO_URING.get(compiled.io_uring),
      rseq: rseq_availability(),
      experimental_isa: isa_availability(),
    }
  }

  /// What is in use now. Allocation-free.
  #[must_use]
  pub fn effective_profile(self) -> EffectiveProfile {
    let (phase, policy) = policy::current();
    let running = phase == RUNNING;
    EffectiveProfile {
      policy,
      frozen: phase != policy::IDLE,
      maintenance: running,
      scheduler: running
        && SCHEDULER.get(CompiledCapabilities::CURRENT.scheduler) == Availability::Available,
      purge_backend: purge_backend(),
      rseq: rseq_effective(),
      kernel_set: self.kernel_set(),
    }
  }

  /// Compiled, detected and effective capabilities; see [`Report`].
  #[must_use]
  pub fn report(self) -> Report {
    Report {
      compiled: self.compiled_capabilities(),
      detected: self.detected_capabilities(),
      effective: self.effective_profile(),
    }
  }
}

fn isa_availability() -> Availability {
  if !crate::arch::EXPERIMENTAL_COMPILED {
    return Availability::NotCompiled;
  }
  match crate::arch::experimental(crate::arch::detected_features()) {
    Some(_) => Availability::Available,
    None => Availability::Unavailable {
      step: policy::ISA_STEP,
      errno: 0,
    },
  }
}

#[cfg(feature = "experimental-rseq")]
fn rseq_availability() -> Availability {
  match crate::rseq::available() {
    Ok(()) => Availability::Available,
    Err(e) => Availability::Unavailable {
      step: e.step(),
      errno: 0,
    },
  }
}

#[cfg(not(feature = "experimental-rseq"))]
fn rseq_availability() -> Availability {
  Availability::NotCompiled
}

#[cfg(feature = "experimental-rseq")]
fn rseq_effective() -> bool {
  policy::rseq_wanted() && crate::rseq::available().is_ok()
}

#[cfg(not(feature = "experimental-rseq"))]
fn rseq_effective() -> bool {
  false
}

impl fmt::Display for Report {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (c, d, e) = (&self.compiled, &self.detected, &self.effective);
    writeln!(f, "allocator: allocatbelt {}", env!("CARGO_PKG_VERSION"))?;
    match d.platform {
      Some(p) => {
        match p.kernel {
          Some(k) => writeln!(f, "kernel: {}.{}.{}", k.major, k.minor, k.patch)?,
          None => writeln!(f, "kernel: unknown")?,
        }
        writeln!(
          f,
          "guard_markers: {}, getrandom: {}",
          p.guard_markers, p.getrandom
        )?;
      }
      None => writeln!(f, "platform: no arena")?,
    }
    writeln!(f, "cpu_features: {:?}", d.cpu_features)?;
    writeln!(f, "kernel_set: {:?}", e.kernel_set)?;
    writeln!(f, "policy_frozen: {}", e.frozen)?;
    let rows = [
      (
        "maintenance",
        c.maintenance,
        None,
        d.maintenance,
        e.maintenance,
      ),
      (
        "scheduler",
        c.scheduler,
        Some(e.policy.scheduler),
        d.scheduler,
        e.scheduler,
      ),
      (
        "io_uring",
        c.io_uring,
        Some(e.policy.io_uring),
        d.io_uring,
        matches!(e.purge_backend, PurgeBackend::IoUring { .. }),
      ),
      ("rseq", c.rseq, Some(e.policy.rseq), d.rseq, e.rseq),
      (
        "experimental_isa",
        c.experimental_aarch64_sve || c.experimental_riscv_rvv,
        Some(e.policy.experimental_isa),
        d.experimental_isa,
        e.kernel_set != KernelSet::Baseline,
      ),
    ];
    for (name, compiled, policy, detected, effective) in rows {
      write!(f, "{name}: compiled={compiled}")?;
      if let Some(p) = policy {
        write!(f, " policy={p}")?;
      }
      writeln!(f, " detected={detected} effective={effective}")?;
    }
    write!(f, "purge_backend: {:?}", e.purge_backend)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn availability_round_trips_through_the_word() {
    let d = Detected::new();
    assert_eq!(d.get(false), Availability::NotCompiled);
    assert_eq!(d.get(true), Availability::NotTried);
    for a in [
      Availability::Available,
      Availability::Unavailable {
        step: "setup",
        errno: 1,
      },
      Availability::Unavailable {
        step: "no mm_cid",
        errno: 0,
      },
      Availability::Unavailable {
        step: "sched_setscheduler",
        errno: -5,
      },
      Availability::NotTried,
    ] {
      d.record(a);
      assert_eq!(d.get(true), a);
    }
    d.record(Availability::Unavailable {
      step: "not a step",
      errno: 7,
    });
    assert_eq!(
      d.get(true),
      Availability::Unavailable {
        step: "unknown",
        errno: 7
      }
    );
  }

  /// Every failure step the ring and the rseq probe report is one
  /// [`Detected`] can record.
  #[test]
  fn unavailable_steps_are_recorded() {
    let sources = [
      include_str!("sys/ring.rs"),
      include_str!("sys/rseq.rs"),
      include_str!("maintenance.rs"),
    ];
    let mut found = 0;
    for src in sources {
      for pat in ["RingError::new(\"", "step: \"", "=> \""] {
        for (i, _) in src.match_indices(pat) {
          let rest = &src[i + pat.len()..];
          let step = &rest[..rest.find('"').unwrap_or(0)];
          if pat == "=> \""
            && !src[..i].ends_with("Self::NoMmCid ")
            && !src[..i].ends_with("Self::NotGlibc ")
            && !src[..i].ends_with("Self::NotRegistered ")
          {
            continue;
          }
          assert!(STEPS.contains(&step), "step {step:?} is not in STEPS");
          found += 1;
        }
      }
    }
    assert!(found >= 10, "found only {found} steps");
  }
}
