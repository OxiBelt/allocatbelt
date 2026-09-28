//! `fork` support. A forked child has only the thread that called `fork`; a
//! heap lock that another thread held at that moment would stay held in the
//! child forever. The embedder registers these three calls as
//! `pthread_atfork` handlers so that the forking thread holds every lock
//! across the fork.
//!
//! Blocks cached by the parent's other threads are lost in the child (they
//! stay allocated). That is bounded by a few bitmap words per size class
//! and thread.

use super::*;

impl<O: Os> Heap<O> {
  /// Takes every heap lock, for a `pthread_atfork` *prepare* handler. Must
  /// be followed by [`Heap::fork_parent`] or [`Heap::fork_child`].
  ///
  /// The order (purge, shards, segments) is the order in which the heap
  /// nests them; the heap only ever `try_lock`s against it, so this cannot
  /// deadlock with a thread in the middle of an operation.
  pub fn fork_prepare(&self) {
    self.purge_lock.acquire(|| self.os.yield_now());
    for sh in &self.shards {
      sh.lock.acquire(|| self.os.yield_now());
    }
    self.seg_lock.acquire(|| self.os.yield_now());
  }

  /// Releases the locks [`Heap::fork_prepare`] took, in the parent.
  pub fn fork_parent(&self) {
    self.release_fork_locks();
  }

  /// Releases the locks [`Heap::fork_prepare`] took, in the child, and
  /// turns automatic decay back on: a background purge thread does not
  /// survive the fork.
  pub fn fork_child(&self) {
    self.release_fork_locks();
    self.set_auto_decay(true);
  }

  fn release_fork_locks(&self) {
    self.seg_lock.release();
    for sh in self.shards.iter().rev() {
      sh.lock.release();
    }
    self.purge_lock.release();
  }
}
