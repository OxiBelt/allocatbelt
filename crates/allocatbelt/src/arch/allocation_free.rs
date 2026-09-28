//! `initialize_dispatch` must not allocate: a global allocator can reach it
//! before `main`, and allocating there would re-enter the allocator.
//!
//! The counting allocator below is the global allocator of the whole unit
//! test binary of this package; it only forwards to `System`, and counts
//! nothing on threads that did not ask it to.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::{KernelSet, detected_features, initialize_dispatch, kernel_set};

/// Counts the allocations the current thread makes while `TRACKING` is set.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

std::thread_local! {
  static TRACKING: Cell<bool> = const { Cell::new(false) };
}

fn note() {
  if TRACKING.with(Cell::get) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
  }
}

// SAFETY: forwards every call to `System` unchanged.
#[expect(unsafe_code, reason = "GlobalAlloc is an unsafe trait")]
unsafe impl GlobalAlloc for Counting {
  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    note();
    // SAFETY: forwarded caller contract.
    #[expect(unsafe_code, reason = "forwarding to System")]
    unsafe {
      System.alloc(layout)
    }
  }

  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: forwarded caller contract.
    #[expect(unsafe_code, reason = "forwarding to System")]
    unsafe {
      System.dealloc(ptr, layout);
    }
  }

  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    note();
    // SAFETY: forwarded caller contract.
    #[expect(unsafe_code, reason = "forwarding to System")]
    unsafe {
      System.realloc(ptr, layout, new_size)
    }
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn initialization_does_not_allocate() {
  assert_eq!(kernel_set(), KernelSet::Baseline);
  TRACKING.with(|t| t.set(true));
  let set = initialize_dispatch();
  let features = detected_features();
  TRACKING.with(|t| t.set(false));
  assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0, "{features:?}");
  assert_eq!(set, KernelSet::Baseline);
  assert_eq!(kernel_set(), KernelSet::Baseline);
}
