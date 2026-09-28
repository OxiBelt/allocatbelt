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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use allocatbelt_core::{
  ARENA_SIZE, Block, Heap, MAX_SEGMENTS, META_WORDS, Os, PAGE_SIZE, SEGMENT_SIZE, ThreadCache,
};
use allocatbelt_sys::{MetaArena, Region};

struct Arena {
  user: Region,
  meta: MetaArena<MAX_SEGMENTS>,
  /// Origin of the heap's clock (see `Os::now_ms`).
  start: Instant,
}

/// Initialised on the first allocation. `OnceLock` blocks on a futex and
/// never allocates; the initialiser only issues `mmap`.
static ARENA: OnceLock<Option<Arena>> = OnceLock::new();

fn arena() -> Option<&'static Arena> {
  ARENA
    .get_or_init(|| {
      let arena = Arena {
        user: Region::reserve(ARENA_SIZE, SEGMENT_SIZE)?,
        meta: MetaArena::reserve(META_WORDS)?,
        start: Instant::now(),
      };
      // Before any allocation: every heap call goes through `arena` first.
      HEAP.set_seed(seed());
      // glibc's `pthread_atfork` allocates with its own `malloc`, not
      // through us, so registering here does not re-enter the allocator.
      let _ = allocatbelt_sys::register_atfork(fork_prepare, fork_parent, fork_child);
      Some(arena)
    })
    .as_ref()
}

/// `fork` handlers: the forking thread takes every heap lock, so that no
/// lock is held by a thread that does not exist in the child.
extern "C" fn fork_prepare() {
  // A fork while another thread is still reserving the arena would leave
  // the child waiting for that thread forever.
  let _ = ARENA.wait();
  HEAP.fork_prepare();
}

extern "C" fn fork_parent() {
  HEAP.fork_parent();
}

extern "C" fn fork_child() {
  HEAP.fork_child();
  // The purge thread (if any) did not survive the fork, and the child
  // should not share the parent's placement secret.
  PURGE_THREAD.store(false, Ordering::Release);
  HEAP.set_seed(seed());
}

/// A secret for randomized placement: from the kernel CSPRNG, or, if its
/// pool is not ready yet (early boot), from ASLR and the time.
fn seed() -> u64 {
  if let Some(s) = allocatbelt_sys::random_u64()
    && s != 0
  {
    return s;
  }
  let local = 0u8;
  let aslr =
    (&raw const local).addr() as u64 ^ (seed as fn() -> u64 as usize as u64).rotate_left(32);
  let time = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |d| d.as_nanos() as u64);
  (aslr ^ time.rotate_left(17)) | 1
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

  fn guard(&self, offset: usize, len: usize) -> bool {
    // SAFETY: the `Os` contract of allocatbelt-core: the heap only guards
    // ranges holding no live allocation and hands nothing out of them
    // until it has unguarded and committed them again.
    #[expect(unsafe_code, reason = "installing a guard page")]
    unsafe {
      self.arena().user.guard(offset, len)
    }
  }

  fn unguard(&self, offset: usize, len: usize) {
    self.arena().user.unguard(offset, len);
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

  fn now_ms(&self) -> u64 {
    // `Instant::now` reads the vDSO clock and does not allocate.
    u64::try_from(self.arena().start.elapsed().as_millis()).unwrap_or(u64::MAX)
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

  /// Bytes of freed pages still resident, waiting for a purge, for
  /// diagnostics.
  #[must_use]
  pub fn dirty_bytes(self) -> usize {
    HEAP.dirty_pages() * PAGE_SIZE
  }

  /// Sets how long freed memory stays resident before it is returned to the
  /// OS (1 s by default). Memory is also returned early once 32 MiB of it
  /// is waiting.
  pub fn set_purge_delay(self, delay: Duration) {
    HEAP.set_purge_delay_ms(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX));
  }

  /// Starts a background thread that returns freed memory to the OS once it
  /// has been unused for the purge delay, even while the program is idle.
  /// Allocating threads then no longer run these passes themselves, which
  /// keeps them off the allocation path.
  ///
  /// Call it from ordinary code (not from inside an allocation). Returns
  /// `Ok(false)` if the thread is already running.
  ///
  /// # Errors
  ///
  /// Returns the error of [`std::thread::Builder::spawn`].
  pub fn start_purge_thread(self) -> std::io::Result<bool> {
    if PURGE_THREAD.swap(true, Ordering::AcqRel) {
      return Ok(false);
    }
    let spawned = std::thread::Builder::new()
      .name("allocatbelt-purge".into())
      .spawn(|| {
        loop {
          std::thread::sleep(Duration::from_millis(HEAP.decay_interval_ms()));
          if arena().is_some() {
            guarded(|| HEAP.decay());
          }
        }
      });
    match spawned {
      Ok(_) => {
        HEAP.set_auto_decay(false);
        Ok(true)
      }
      Err(e) => {
        PURGE_THREAD.store(false, Ordering::Release);
        Err(e)
      }
    }
  }
}

/// Whether the background purge thread has been started.
static PURGE_THREAD: AtomicBool = AtomicBool::new(false);

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
