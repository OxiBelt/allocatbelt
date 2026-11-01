//! Counts task-owned allocation constructors, without replacing the allocator.
//! Runtime setup, user allocations, and panic machinery are outside this count.

use std::cell::Cell;

thread_local! {
  static CONSTRUCTORS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record() {
  CONSTRUCTORS.with(|count| count.set(count.get() + 1));
}

pub(super) fn count() -> usize {
  CONSTRUCTORS.with(Cell::get)
}
