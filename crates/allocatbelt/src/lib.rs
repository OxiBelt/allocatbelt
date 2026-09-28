//! `GlobalAlloc` adapter for allocatbelt.
//!
//! ```ignore
//! #[global_allocator]
//! static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;
//! ```
//!
//! The allocation logic lives in `allocatbelt-core` (`#![forbid(unsafe_code)]`)
//! and works on offsets. This crate turns offsets into pointers through
//! `allocatbelt-sys` and contains the `unsafe` that the `GlobalAlloc` contract
//! itself requires: the trait impl, zero-filling and the `realloc` copy.

#![cfg(target_os = "linux")]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::alloc::{GlobalAlloc, Layout};
use std::io::Write as _;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;

use allocatbelt_core::{
  ARENA_SIZE, Block, Heap, MAX_SEGMENTS, META_WORDS, Os, SEGMENT_SIZE, ThreadCache,
};
use allocatbelt_sys::{MetaArena, Region};

struct Arena {
  user: Region,
  meta: MetaArena<MAX_SEGMENTS>,
}

/// Initialised on the first allocation. `OnceLock` blocks on a futex and
/// never allocates; the initialiser only issues `mmap`.
static ARENA: OnceLock<Option<Arena>> = OnceLock::new();

fn arena() -> Option<&'static Arena> {
  ARENA
    .get_or_init(|| {
      Some(Arena {
        user: Region::reserve(ARENA_SIZE, SEGMENT_SIZE)?,
        meta: MetaArena::reserve(META_WORDS)?,
      })
    })
    .as_ref()
}

/// The [`Os`] of the global heap. It is only reached after [`arena`]
/// succeeded, because the heap is only entered with an arena offset or on an
/// allocation that initialised the arena first.
struct LinuxOs;

impl LinuxOs {
  fn arena(&self) -> &'static Arena {
    match ARENA.get() {
      Some(Some(a)) => a,
      _ => self.fatal("allocatbelt: heap used before the arena was reserved"),
    }
  }
}

impl Os for LinuxOs {
  fn commit(&self, offset: usize, len: usize) -> bool {
    self.arena().user.commit(offset, len)
  }

  fn decommit(&self, offset: usize, len: usize) -> bool {
    // SAFETY: the `Os` contract of allocatbelt-core guarantees the heap
    // only decommits ranges holding no live allocation, so no pointer we
    // handed out refers into the range.
    #[expect(unsafe_code, reason = "returning unused memory to the kernel")]
    unsafe {
      self.arena().user.decommit(offset, len)
    }
  }

  fn purge(&self, offset: usize, len: usize) -> bool {
    // SAFETY: as for `decommit`, the range holds no live allocation.
    #[expect(unsafe_code, reason = "returning unused memory to the kernel")]
    unsafe {
      self.arena().user.purge(offset, len)
    }
  }

  fn commit_meta(&self, segment: usize) -> Option<&[AtomicU64]> {
    self.arena().meta.commit(segment)
  }

  fn meta(&self, segment: usize) -> Option<&[AtomicU64]> {
    self.arena().meta.get(segment)
  }

  fn yield_now(&self) {
    allocatbelt_sys::yield_now();
  }

  fn fatal(&self, msg: &'static str) -> ! {
    // `Stderr` is unbuffered; writing a `&str` does not allocate.
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    std::process::abort()
  }
}

static HEAP: Heap<LinuxOs> = Heap::new(LinuxOs);

std::thread_local! {
    // `const`-initialised and without `Drop`: no lazy init and no destructor
    // registration, so touching it never allocates or re-enters us, and it
    // stays usable while other thread-local destructors run.
    static CACHE: ThreadCache = const { ThreadCache::new() };
    // Zero-sized, with a `Drop` that hands the cache back at thread exit.
    // Touched once per thread, when the cache is attached.
    static RETIRE: Retire = const { Retire };
}

struct Retire;

impl Drop for Retire {
  fn drop(&mut self) {
    let _ = CACHE.try_with(|tc| guarded(|| HEAP.retire(tc)));
  }
}

/// Runs `f` with the calling thread's cache, attaching it first if needed.
/// Falls back to a detached cache (the uncached paths) if the thread-local
/// is unavailable.
#[inline]
fn with_cache<R>(f: impl FnOnce(&ThreadCache) -> R) -> R {
  let mut f = Some(f);
  let r = CACHE.try_with(|tc| {
    if tc.is_detached() {
      attach(tc);
    }
    f.take().map(|f| f(tc))
  });
  match r {
    Ok(Some(r)) => r,
    _ => match f {
      Some(f) => f(&ThreadCache::new()),
      None => LinuxOs.fatal("allocatbelt: cache callback lost"),
    },
  }
}

#[cold]
fn attach(tc: &ThreadCache) {
  // Registering the destructor may allocate (it does not go through us on
  // glibc, but nothing guarantees that); until `attach` returns, such
  // allocations take the uncached paths.
  tc.begin_attach();
  if RETIRE.try_with(|_| ()).is_ok() {
    HEAP.attach(tc);
  }
}

/// Aborts the process if dropped during unwinding: unwinding out of a
/// `GlobalAlloc` method is undefined behaviour, and a panic in the heap can
/// only mean a bug in it.
struct AbortOnUnwind;

impl Drop for AbortOnUnwind {
  fn drop(&mut self) {
    LinuxOs.fatal("allocatbelt: internal panic");
  }
}

fn guarded<R>(f: impl FnOnce() -> R) -> R {
  let bomb = AbortOnUnwind;
  let r = f();
  std::mem::forget(bomb);
  r
}

/// The allocatbelt global allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct Allocatbelt;

impl Allocatbelt {
  /// Allocates memory for `layout`, or returns `None` when out of memory.
  /// Safe: it only hands out fresh memory.
  #[must_use]
  pub fn allocate(self, layout: Layout) -> Option<NonNull<u8>> {
    self.allocate_block(layout).map(|(p, _)| p)
  }

  /// As [`Allocatbelt::allocate`], also reporting whether the block is
  /// already known to read as zero.
  fn allocate_block(self, layout: Layout) -> Option<(NonNull<u8>, bool)> {
    guarded(|| {
      let a = arena()?;
      let Block { offset, zeroed } =
        with_cache(|tc| HEAP.alloc_cached(tc, layout.size(), layout.align()))?;
      Some((a.user.ptr(offset)?, zeroed))
    })
  }

  /// Usable size of a live allocation made by this allocator.
  #[must_use]
  pub fn usable_size(self, ptr: NonNull<u8>) -> usize {
    guarded(|| HEAP.usable_size(offset_of(ptr.as_ptr())))
  }

  /// Returns all freed-but-unpurged memory to the OS. Purging also happens
  /// automatically once the dirty budget is exceeded; call this from a
  /// maintenance task to shrink RSS promptly after load drops.
  ///
  /// Blocks cached by the calling thread are returned first; other
  /// threads' caches (a few words per size class each) are not touched.
  pub fn purge(self) {
    if arena().is_some() {
      guarded(|| {
        let _ = CACHE.try_with(|tc| HEAP.flush(tc));
        HEAP.purge();
      });
    }
  }

  /// Segments (4 MiB) currently taken from the arena, for diagnostics.
  #[must_use]
  pub fn segments_in_use(self) -> usize {
    HEAP.segments_in_use()
  }
}

fn offset_of(ptr: *const u8) -> usize {
  match arena().and_then(|a| a.user.offset_of(ptr)) {
    Some(o) => o,
    None => LinuxOs.fatal("allocatbelt: pointer was not allocated by allocatbelt"),
  }
}

// SAFETY: every method upholds the `GlobalAlloc` contract: returned blocks
// are fresh (the heap never hands out a live block twice), sized and aligned
// for the layout (checked by allocatbelt-core's model tests), and never
// unwind (`guarded`). Deallocation trusts the caller's contract that `ptr`
// came from this allocator, and additionally aborts on invalid/double frees.
#[expect(unsafe_code, reason = "GlobalAlloc is an unsafe trait")]
unsafe impl GlobalAlloc for Allocatbelt {
  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    self
      .allocate(layout)
      .map_or(ptr::null_mut(), NonNull::as_ptr)
  }

  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    let Some((p, zeroed)) = self.allocate_block(layout) else {
      return ptr::null_mut();
    };
    // Fresh or purged memory already reads as zero; skipping the memset
    // also keeps untouched pages of a large `calloc` out of RSS.
    if zeroed {
      return p.as_ptr();
    }
    // SAFETY: `p` is a fresh allocation valid for `layout.size()` bytes
    // that nothing else references yet.
    #[expect(unsafe_code, reason = "zero-fill of a fresh block")]
    unsafe {
      p.as_ptr().write_bytes(0, layout.size());
    }
    p.as_ptr()
  }

  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
    guarded(|| {
      let off = offset_of(ptr);
      with_cache(|tc| HEAP.dealloc_cached(tc, off));
    });
  }

  #[expect(unsafe_code, reason = "GlobalAlloc method")]
  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let off = offset_of(ptr);
    // Keeps a block that still fits, and grows or trims page and segment
    // runs where they are.
    if guarded(|| HEAP.resize_in_place(off, new_size)) {
      return ptr;
    }
    // The caller guarantees `new_size` rounded to `layout.align()` does
    // not overflow `isize`, so this layout is valid.
    let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
      return ptr::null_mut();
    };
    let Some(new) = self.allocate(new_layout) else {
      return ptr::null_mut();
    };
    // SAFETY: `ptr` is live for `layout.size()` bytes (caller contract),
    // `new` is a fresh, distinct block of at least `new_size` bytes, so
    // the regions do not overlap and both are valid for the copy length.
    #[expect(unsafe_code, reason = "moving the contents to the new block")]
    unsafe {
      ptr::copy_nonoverlapping(ptr, new.as_ptr(), layout.size().min(new_size));
    }
    guarded(|| with_cache(|tc| HEAP.dealloc_cached(tc, off)));
    new.as_ptr()
  }
}
