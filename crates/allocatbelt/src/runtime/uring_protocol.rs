//! Slot lifecycle shared by the runtime io_uring service and its Loom models.
//!
//! The production service serializes these transitions with its ledger mutex.
//! The model tests exercise detach/publication/completion races in this exact
//! helper; they do not model kernel submission or prove the syscall boundary.

#![cfg_attr(loom, allow(dead_code))]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
  Vacant,
  Queued,
  Publishing,
  Published,
  Completing,
  Completed,
  Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Detach {
  Stale,
  CancelQueued,
  MarkDetached,
  DropCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NotPublished {
  Requeue,
  Cancel,
  Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Completion {
  PublishResult,
  DropDetached,
  FatalStale,
}

/// State for one fixed public-operation slot. Generations never wrap: after
/// the last representable value has been used, the next reservation retires
/// the slot permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SlotProtocol {
  generation: u32,
  phase: Phase,
  detached: bool,
}

impl SlotProtocol {
  pub(super) const fn new() -> Self {
    Self {
      generation: 0,
      phase: Phase::Vacant,
      detached: false,
    }
  }

  pub(super) fn reserve(&mut self) -> Option<u32> {
    if self.phase != Phase::Vacant {
      return None;
    }
    let Some(generation) = self.generation.checked_add(1) else {
      self.phase = Phase::Retired;
      return None;
    };
    self.generation = generation;
    self.phase = Phase::Queued;
    self.detached = false;
    Some(generation)
  }

  pub(super) const fn generation(&self) -> u32 {
    self.generation
  }

  pub(super) const fn phase(&self) -> Phase {
    self.phase
  }

  pub(super) fn matches(&self, generation: u32) -> bool {
    self.generation == generation && self.phase != Phase::Vacant && self.phase != Phase::Retired
  }

  #[cfg(test)]
  pub(super) const fn detached(&self) -> bool {
    self.detached
  }

  pub(super) fn claim(&mut self, generation: u32) -> bool {
    if !self.matches(generation) || self.phase != Phase::Queued {
      return false;
    }
    self.phase = Phase::Publishing;
    true
  }

  pub(super) fn published(&mut self, generation: u32) -> bool {
    if !self.matches(generation) || self.phase != Phase::Publishing {
      return false;
    }
    self.phase = Phase::Published;
    true
  }

  /// Resolves a backend response that guarantees the operation never became
  /// kernel-visible. Detached work is reclaimed; attached work returns to the
  /// FIFO queue for a retry (for example, a full submission ring).
  pub(super) fn not_published(&mut self, generation: u32) -> NotPublished {
    if !self.matches(generation) || self.phase != Phase::Publishing {
      return NotPublished::Stale;
    }
    if self.detached {
      self.phase = Phase::Vacant;
      NotPublished::Cancel
    } else {
      self.phase = Phase::Queued;
      NotPublished::Requeue
    }
  }

  /// Resolves a definite prepublication I/O failure. `None` means the
  /// caller supplied a stale transition; `Some(true)` means the request was
  /// detached at this transition. Final publication is separate so the
  /// service can release its permit first.
  pub(super) fn fail_unpublished(&mut self, generation: u32) -> Option<bool> {
    if !self.matches(generation) || self.phase != Phase::Publishing {
      return None;
    }
    self.phase = Phase::Completing;
    Some(self.detached)
  }

  /// Completes a zero-length operation without exposing any memory to the
  /// backend or submitting an SQE.
  pub(super) fn local_complete(&mut self, generation: u32) -> Option<bool> {
    if !self.matches(generation) || self.phase != Phase::Publishing {
      return None;
    }
    self.phase = Phase::Completing;
    Some(self.detached)
  }

  /// Marks the observed kernel CQE while keeping user-visible completion
  /// pending until out-of-lock permit release has finished.
  pub(super) fn begin_kernel_completion(&mut self, generation: u32) -> bool {
    if !self.matches(generation) || self.phase != Phase::Published {
      return false;
    }
    self.phase = Phase::Completing;
    true
  }

  /// Publishes a result only after post-CQE ownership accounting is done.
  pub(super) fn finish_completion(&mut self, generation: u32) -> Completion {
    if !self.matches(generation) || self.phase != Phase::Completing {
      return Completion::FatalStale;
    }
    if self.detached {
      self.phase = Phase::Vacant;
      Completion::DropDetached
    } else {
      self.phase = Phase::Completed;
      Completion::PublishResult
    }
  }

  pub(super) fn detach(&mut self, generation: u32) -> Detach {
    if !self.matches(generation) {
      return Detach::Stale;
    }
    match self.phase {
      Phase::Queued => {
        self.phase = Phase::Vacant;
        self.detached = true;
        Detach::CancelQueued
      }
      Phase::Publishing | Phase::Published | Phase::Completing => {
        self.detached = true;
        Detach::MarkDetached
      }
      Phase::Completed => {
        self.phase = Phase::Vacant;
        self.detached = true;
        Detach::DropCompleted
      }
      Phase::Vacant | Phase::Retired => Detach::Stale,
    }
  }

  /// Accepts only a CQE for the currently published generation. Unknown,
  /// stale, duplicate, or early CQEs indicate a broken backend contract and
  /// must fail-stop in the service before owners can be released.
  #[cfg(test)]
  pub(super) fn complete(&mut self, generation: u32) -> Completion {
    if !self.begin_kernel_completion(generation) {
      return Completion::FatalStale;
    }
    self.finish_completion(generation)
  }

  pub(super) fn consume(&mut self, generation: u32) -> bool {
    if !self.matches(generation) || self.phase != Phase::Completed {
      return false;
    }
    self.phase = Phase::Vacant;
    true
  }

  #[cfg(test)]
  pub(super) fn with_generation_for_test(generation: u32) -> Self {
    Self {
      generation,
      phase: Phase::Vacant,
      detached: false,
    }
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::{Completion, Detach, NotPublished, Phase, SlotProtocol};
  use loom::sync::{Arc, Mutex};
  use loom::thread;

  #[test]
  fn detach_racing_claim_has_one_cancellation_boundary() {
    loom::model(|| {
      let slot = Arc::new(Mutex::new(SlotProtocol::new()));
      let generation = slot.lock().unwrap().reserve().unwrap();
      let claim_slot = Arc::clone(&slot);
      let claim = thread::spawn(move || {
        let mut slot = claim_slot.lock().unwrap();
        slot.claim(generation)
      });
      let detach_slot = Arc::clone(&slot);
      let detach = thread::spawn(move || {
        let mut slot = detach_slot.lock().unwrap();
        slot.detach(generation)
      });
      let claimed = claim.join().unwrap();
      let detached = detach.join().unwrap();
      match (claimed, detached) {
        (false, Detach::CancelQueued) => assert_eq!(slot.lock().unwrap().phase(), Phase::Vacant),
        (true, Detach::MarkDetached) => {
          let mut slot = slot.lock().unwrap();
          assert!(slot.published(generation));
          assert_eq!(slot.complete(generation), Completion::DropDetached);
          assert_eq!(slot.phase(), Phase::Vacant);
        }
        other => panic!("impossible detach/claim result: {other:?}"),
      }
    });
  }

  #[test]
  fn detach_racing_real_completion_releases_one_generation() {
    loom::model(|| {
      let slot = Arc::new(Mutex::new(SlotProtocol::new()));
      let generation = {
        let mut slot = slot.lock().unwrap();
        let generation = slot.reserve().unwrap();
        assert!(slot.claim(generation));
        assert!(slot.published(generation));
        generation
      };
      let complete_slot = Arc::clone(&slot);
      let completion = thread::spawn(move || complete_slot.lock().unwrap().complete(generation));
      let detach_slot = Arc::clone(&slot);
      let detach = thread::spawn(move || detach_slot.lock().unwrap().detach(generation));
      match (completion.join().unwrap(), detach.join().unwrap()) {
        (Completion::PublishResult, Detach::DropCompleted) => {
          assert_eq!(slot.lock().unwrap().phase(), Phase::Vacant);
        }
        (Completion::DropDetached, Detach::MarkDetached) => {
          assert_eq!(slot.lock().unwrap().phase(), Phase::Vacant);
        }
        other => panic!("impossible completion/detach result: {other:?}"),
      }
    });
  }

  #[test]
  fn definite_nonpublication_requeues_or_cancels_without_stale_owner() {
    loom::model(|| {
      let slot = Arc::new(Mutex::new(SlotProtocol::new()));
      let generation = {
        let mut slot = slot.lock().unwrap();
        let generation = slot.reserve().unwrap();
        assert!(slot.claim(generation));
        generation
      };
      let cancel_slot = Arc::clone(&slot);
      let cancel = thread::spawn(move || cancel_slot.lock().unwrap().detach(generation));
      let response_slot = Arc::clone(&slot);
      let response = thread::spawn(move || response_slot.lock().unwrap().not_published(generation));
      match (cancel.join().unwrap(), response.join().unwrap()) {
        (Detach::MarkDetached, NotPublished::Cancel) => {
          assert_eq!(slot.lock().unwrap().phase(), Phase::Vacant);
        }
        (Detach::CancelQueued, NotPublished::Requeue) => {
          // The issuer linearized a definitely-unpublished retry before the
          // future detached, so the serialized detach cancels that queue.
          let slot = slot.lock().unwrap();
          assert_eq!(slot.phase(), Phase::Vacant);
        }
        other => panic!("impossible definite-not-published result: {other:?}"),
      }
    });
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{Completion, Detach, NotPublished, Phase, SlotProtocol};

  #[test]
  fn completion_consumption_and_detach_have_one_terminal_owner() {
    let mut slot = SlotProtocol::new();
    let generation = slot.reserve().unwrap();
    assert!(slot.claim(generation));
    assert!(slot.published(generation));
    assert_eq!(slot.complete(generation), Completion::PublishResult);
    assert_eq!(slot.detach(generation), Detach::DropCompleted);
    assert_eq!(slot.phase(), Phase::Vacant);
    assert!(!slot.consume(generation));
  }

  #[test]
  fn published_detach_releases_only_after_cqe() {
    let mut slot = SlotProtocol::new();
    let generation = slot.reserve().unwrap();
    assert!(slot.claim(generation));
    assert!(slot.published(generation));
    assert_eq!(slot.detach(generation), Detach::MarkDetached);
    assert!(slot.detached());
    assert_eq!(slot.phase(), Phase::Published);
    assert_eq!(slot.complete(generation), Completion::DropDetached);
    assert_eq!(slot.phase(), Phase::Vacant);
  }

  #[test]
  fn checked_generation_retires_instead_of_wrapping() {
    let mut slot = SlotProtocol::with_generation_for_test(u32::MAX);
    assert_eq!(slot.reserve(), None);
    assert_eq!(slot.phase(), Phase::Retired);
  }

  #[test]
  fn definitely_unpublished_retry_keeps_same_generation() {
    let mut slot = SlotProtocol::new();
    let generation = slot.reserve().unwrap();
    assert!(slot.claim(generation));
    assert_eq!(slot.not_published(generation), NotPublished::Requeue);
    assert!(slot.matches(generation));
    assert!(slot.claim(generation));
  }

  #[test]
  fn completion_stays_private_until_out_of_lock_cleanup_finishes() {
    let mut slot = SlotProtocol::new();
    let generation = slot.reserve().unwrap();
    assert!(slot.claim(generation));
    assert!(slot.published(generation));
    assert!(slot.begin_kernel_completion(generation));
    assert_eq!(slot.phase(), Phase::Completing);
    assert_eq!(slot.detach(generation), Detach::MarkDetached);
    assert_eq!(slot.finish_completion(generation), Completion::DropDetached);
    assert_eq!(slot.phase(), Phase::Vacant);
  }

  #[test]
  fn local_and_prepublication_failures_follow_the_same_cleanup_gate() {
    let mut local = SlotProtocol::new();
    let generation = local.reserve().unwrap();
    assert!(local.claim(generation));
    assert_eq!(local.local_complete(generation), Some(false));
    assert_eq!(local.phase(), Phase::Completing);
    assert_eq!(
      local.finish_completion(generation),
      Completion::PublishResult
    );
    assert!(local.consume(generation));

    let mut failed = SlotProtocol::new();
    let generation = failed.reserve().unwrap();
    assert!(failed.claim(generation));
    assert_eq!(failed.fail_unpublished(generation), Some(false));
    assert_eq!(failed.phase(), Phase::Completing);
    assert_eq!(
      failed.finish_completion(generation),
      Completion::PublishResult
    );
  }
}
