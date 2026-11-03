//! Counts heap allocations with a wrapping global allocator while native
//! async tasks are spawned: each spawn makes exactly one allocation, which
//! holds the user future inline. Not built under `--cfg loom`.

#![cfg(not(loom))]
#![allow(unsafe_code, reason = "a counting `GlobalAlloc` wrapper")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};

/// Records the sizes of this thread's allocations while enabled.
struct Counting;

const RECORDED: usize = 8;

thread_local! {
  static RECORDING: Cell<bool> = const { Cell::new(false) };
  static COUNT: Cell<usize> = const { Cell::new(0) };
  static SIZES: Cell<[usize; RECORDED]> = const { Cell::new([0; RECORDED]) };
}

fn record(layout: Layout) {
  if !RECORDING.with(Cell::get) {
    return;
  }
  let index = COUNT.with(|count| {
    let index = count.get();
    count.set(index + 1);
    index
  });
  if index < RECORDED {
    SIZES.with(|sizes| {
      let mut recorded = sizes.get();
      recorded[index] = layout.size();
      sizes.set(recorded);
    });
  }
}

// SAFETY: every method forwards to `System` with the layout it was given,
// so the wrapper allocates and frees exactly like `System` does.
unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    record(layout);
    // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract for `layout`.
    unsafe { System.alloc(layout) }
  }

  unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
    // SAFETY: `pointer` came from `System` with this `layout`.
    unsafe { System.dealloc(pointer, layout) }
  }

  unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    record(Layout::from_size_align(new_size, layout.align()).unwrap_or(layout));
    // SAFETY: `pointer` came from `System` with this `layout`, and the
    // caller upholds `GlobalAlloc::realloc`'s contract for `new_size`.
    unsafe { System.realloc(pointer, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Runs `spawn` with recording on and returns this thread's allocation
/// count and the recorded sizes.
fn measure<T>(spawn: impl FnOnce() -> T) -> (T, usize, [usize; RECORDED]) {
  COUNT.with(|count| count.set(0));
  SIZES.with(|sizes| sizes.set([0; RECORDED]));
  RECORDING.with(|recording| recording.set(true));
  let value = spawn();
  RECORDING.with(|recording| recording.set(false));
  (value, COUNT.with(Cell::get), SIZES.with(Cell::get))
}

fn runtime() -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 8,
    max_scopes: 1,
  })
  .unwrap()
}

#[test]
fn each_spawn_makes_one_allocation_that_stores_the_future_inline() {
  let runtime = runtime();
  let handle = runtime.handle();
  // A warm-up spawn, outside the measurement, so that any lazily sized
  // scheduler state is in place.
  let warm = handle.spawn(std::future::ready(0usize)).unwrap();

  // A zero-sized future: the allocation is the bookkeeping alone.
  let (small, count, sizes) = measure(|| {
    handle
      .spawn(std::future::poll_fn(|_| std::task::Poll::Ready(7usize)))
      .unwrap()
  });
  assert_eq!(
    count, 1,
    "allocations while spawning a small future: {sizes:?}"
  );
  let small_bytes = sizes[0];

  // The same output type with 4 KiB of future state: still one allocation,
  // larger by at least that state, so the future is stored inline.
  let state = [1u8; 4096];
  let (large, count, sizes) = measure(|| {
    handle
      .spawn(async move { state.iter().map(|byte| usize::from(*byte)).sum::<usize>() })
      .unwrap()
  });
  assert_eq!(
    count, 1,
    "allocations while spawning a large future: {sizes:?}"
  );
  assert!(
    sizes[0] >= small_bytes + 4096,
    "the large future was not stored inline: {} bytes against {small_bytes}",
    sizes[0]
  );

  // A caller's own box is moved in, not boxed again: one allocation whose
  // size is that of a task around a boxed `Pin<Box<dyn Future>>` handle.
  let boxed: Pin<Box<dyn Future<Output = usize> + Send>> = Box::pin(async { 9 });
  let (boxed, count, sizes) = measure(|| handle.spawn(boxed).unwrap());
  assert_eq!(
    count, 1,
    "allocations while spawning a boxed future: {sizes:?}"
  );
  assert!(sizes[0] < small_bytes + 4096);

  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  assert!(warm.is_finished());
  assert!(small.is_finished());
  assert!(large.is_finished());
  assert!(boxed.is_finished());
}
