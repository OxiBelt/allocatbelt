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

#[test]
fn spawn_allocates_only_merged_state_and_driver() {
  use super::{AsyncConfig, AsyncRuntime, AsyncShutdown};
  use std::future::Future;
  use std::pin::Pin;

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let handle = runtime.handle();
  let before = count();
  let inline = handle.spawn(std::future::ready(7usize)).unwrap();
  assert_eq!(count() - before, 2);
  // Construct the caller's box before measuring runtime constructors.
  let boxed: Pin<Box<dyn Future<Output = usize> + Send>> = Box::pin(async { 9 });
  let before = count();
  let boxed = handle.spawn(boxed).unwrap();
  assert_eq!(count() - before, 2);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  assert!(inline.is_finished());
  assert!(boxed.is_finished());
}
