//! The allocatbelt hooks a worker runs: one shard per worker, and its
//! thread cache returned before it parks and before it exits. Both are
//! called outside the scheduler lock. Without allocatbelt as the global
//! allocator they only touch caches that stay empty.

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
  /// The last shard this thread asked for and its flushes, for the tests.
  pub(crate) static SHARD: Cell<Option<usize>> = const { Cell::new(None) };
  pub(crate) static FLUSHES: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn set_shard(index: usize) {
  #[cfg(not(loom))]
  crate::Allocatbelt.set_thread_shard(index);
  #[cfg(test)]
  SHARD.set(Some(index));
  #[cfg(all(loom, not(test)))]
  let _ = index;
}

pub(crate) fn flush() {
  #[cfg(not(loom))]
  crate::Allocatbelt.flush_thread_cache();
  #[cfg(test)]
  FLUSHES.set(FLUSHES.get() + 1);
}
