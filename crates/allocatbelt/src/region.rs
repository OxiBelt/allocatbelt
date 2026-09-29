//! Explicit-lifetime regions (theory-driven plan, Stage E): an opt-in
//! application API for many short-lived values that die together, such as
//! the temporary data of one request or task.
//!
//! A [`Region`] takes *chunks* from the allocatbelt heap and hands out
//! consecutive pieces of them (bump allocation). Pieces are never freed one
//! by one: [`Region::reset`] forgets all of them at once and keeps some
//! chunks for reuse, and dropping the region returns every chunk to the
//! heap. The global allocator is unaffected: nothing is ever placed in a
//! region implicitly.
//!
//! Soundness rests on the borrow checker, not on run-time checks:
//!
//! * pieces are borrowed from the region (`&self`), so any number can be
//!   live at once, and resetting, releasing or dropping the region needs
//!   `&mut self` or ownership, which no borrow can outlive;
//! * the region is `Send` (it owns its chunks) and not `Sync` (it bumps
//!   through `Cell`s), so a piece can never be used from another thread
//!   while the region allocates or resets;
//! * only initialized values of `Copy` types are handed out, so no memory
//!   is ever read uninitialized and no destructor can be skipped: types with
//!   drop glue are rejected at compile time;
//! * chunk descriptors live in a `Vec` of their own, never inside a chunk,
//!   so the payload the caller writes cannot corrupt them.
//!
//! The arithmetic (alignment, fitting, chunk sizing, retention, the limit)
//! is the safe core's `core::region`; this module owns the chunks and turns
//! addresses into pointers. Its `unsafe` sites are listed in
//! `docs/unsafe-boundary.md`.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::{Cell, RefCell};
use core::fmt;
use core::ptr::{self, NonNull};
use std::vec::Vec;

use crate::core::MAX_ALIGN;
use crate::core::region::{
  DEFAULT_CHUNK, DEFAULT_RETAIN, MIN_CHUNK_ALIGN, bump, fits_standard, keep_on_reset, own_chunk,
  standard_chunk, within_limit,
};
use crate::global::Allocatbelt;

/// Why a region could not hand out a piece.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionError {
  /// The request cannot be laid out: its size overflows, is larger than
  /// `isize::MAX`, or its alignment is above the heap's largest (4 MiB).
  Layout,
  /// A new chunk would take the region's chunks past its limit
  /// ([`RegionOptions::with_limit_bytes`]).
  Limit,
  /// The heap had no memory for a new chunk.
  OutOfMemory,
}

impl fmt::Display for RegionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Layout => "region request cannot be laid out",
      Self::Limit => "region limit reached",
      Self::OutOfMemory => "out of memory for a region chunk",
    })
  }
}

impl std::error::Error for RegionError {}

/// How a [`Region`] takes and keeps chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionOptions {
  chunk: usize,
  retain: usize,
  limit: usize,
}

impl RegionOptions {
  /// 64 KiB standard chunks, 1 MiB kept by a reset, no limit.
  pub const DEFAULT: Self = Self {
    chunk: DEFAULT_CHUNK,
    retain: DEFAULT_RETAIN,
    limit: usize::MAX,
  };

  /// The defaults ([`RegionOptions::DEFAULT`]).
  #[must_use]
  pub const fn new() -> Self {
    Self::DEFAULT
  }

  /// Size of standard chunks, clamped to 256 bytes..=4 MiB and rounded up
  /// to 16 bytes. Requests that do not fit an empty standard chunk get a
  /// chunk of their own.
  #[must_use]
  pub const fn with_chunk_size(self, bytes: usize) -> Self {
    Self {
      chunk: standard_chunk(bytes),
      ..self
    }
  }

  /// Capacity of standard chunks a reset keeps for reuse (the first ones,
  /// in the order they were taken, while they fit). Chunks of their own
  /// are never kept. 0 returns every chunk at each reset.
  #[must_use]
  pub const fn with_retain_bytes(self, bytes: usize) -> Self {
    Self {
      retain: bytes,
      ..self
    }
  }

  /// Most bytes of chunks the region holds at once; a request that needs a
  /// chunk past it fails with [`RegionError::Limit`].
  #[must_use]
  pub const fn with_limit_bytes(self, bytes: usize) -> Self {
    Self {
      limit: bytes,
      ..self
    }
  }

  /// The standard chunk size in bytes.
  #[must_use]
  pub const fn chunk_size(self) -> usize {
    self.chunk
  }

  /// The capacity a reset keeps, in bytes.
  #[must_use]
  pub const fn retain_bytes(self) -> usize {
    self.retain
  }

  /// The limit on held chunks, in bytes.
  #[must_use]
  pub const fn limit_bytes(self) -> usize {
    self.limit
  }
}

impl Default for RegionOptions {
  fn default() -> Self {
    Self::DEFAULT
  }
}

/// What a [`Region`] holds, from [`Region::stats`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegionStats {
  /// Chunks held: standard ones and chunks of their own.
  pub chunks: usize,
  /// Of those, chunks of their own (requests larger than a standard
  /// chunk).
  pub own_chunks: usize,
  /// Bytes of all chunks held.
  pub capacity: usize,
  /// Bytes handed out since the last reset, alignment padding included,
  /// and standard-chunk tails skipped when a request moved to the next
  /// chunk.
  pub used: usize,
  /// Resets so far.
  pub resets: u64,
}

/// Where a region's chunks come from and go back to.
pub(crate) trait ChunkSource {
  /// A fresh allocation for `layout` (non-zero size), or `None`.
  fn allocate(&self, layout: Layout) -> Option<NonNull<u8>>;

  /// Returns a chunk.
  ///
  /// # Safety
  ///
  /// `ptr` was returned by `allocate` of this source for `layout`, and is
  /// not used afterwards.
  #[expect(unsafe_code, reason = "releasing a chunk requires its origin")]
  unsafe fn release(&self, ptr: NonNull<u8>, layout: Layout);
}

/// The allocatbelt heap, whatever the process's global allocator is.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HeapChunks;

impl ChunkSource for HeapChunks {
  fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
    Allocatbelt.allocate(layout)
  }

  #[expect(unsafe_code, reason = "returning a chunk to the heap")]
  unsafe fn release(&self, ptr: NonNull<u8>, layout: Layout) {
    // SAFETY: `ptr` came from `Allocatbelt::allocate` for `layout` and is
    // not used afterwards (this function's contract), which is what
    // `GlobalAlloc::dealloc` requires.
    unsafe { Allocatbelt.dealloc(ptr.as_ptr(), layout) }
  }
}

/// A chunk a region owns: an allocation of `layout` at `ptr`.
#[derive(Debug)]
struct Chunk {
  ptr: NonNull<u8>,
  layout: Layout,
}

impl Chunk {
  fn base(&self) -> usize {
    self.ptr.as_ptr().addr()
  }

  /// Pointer to the byte at address `addr`, with the chunk's provenance.
  /// Only computed for addresses the core's arithmetic placed inside the
  /// chunk (or one past its end, for zero-sized pieces).
  fn at(&self, addr: usize) -> NonNull<u8> {
    let p = self.ptr.as_ptr().wrapping_add(addr - self.base());
    NonNull::new(p).unwrap_or(self.ptr)
  }
}

// SAFETY: a `Chunk` owns its allocation exclusively, like a `Box<[u8]>`:
// no other value refers to it, it holds no thread-local state, and both
// chunk sources accept a release from any thread (the heap handles frees
// from other threads). Moving it to another thread moves that ownership.
#[expect(unsafe_code, reason = "a chunk owns its allocation like a Box")]
unsafe impl Send for Chunk {}

/// The region over any chunk source (tests use the system allocator, which
/// Miri can run).
struct RawRegion<S: ChunkSource> {
  source: S,
  options: RegionOptions,
  /// Standard chunks, in the order taken.
  standard: RefCell<Vec<Chunk>>,
  /// Chunks of their own.
  own: RefCell<Vec<Chunk>>,
  /// Index + 1 in `standard` of the chunk being bumped; 0 for none.
  current: Cell<usize>,
  /// Next free address and end of the current chunk (0 and 0 for none).
  cursor: Cell<usize>,
  end: Cell<usize>,
  /// Bytes of all chunks held.
  held: Cell<usize>,
  used: Cell<usize>,
  resets: Cell<u64>,
}

impl<S: ChunkSource> RawRegion<S> {
  const fn new(source: S, options: RegionOptions) -> Self {
    Self {
      source,
      options,
      standard: RefCell::new(Vec::new()),
      own: RefCell::new(Vec::new()),
      current: Cell::new(0),
      cursor: Cell::new(0),
      end: Cell::new(0),
      held: Cell::new(0),
      used: Cell::new(0),
      resets: Cell::new(0),
    }
  }

  /// A new chunk for `layout`, within the limit.
  fn take(&self, layout: Layout) -> Result<Chunk, RegionError> {
    if !within_limit(self.held.get(), layout.size(), self.options.limit) {
      return Err(RegionError::Limit);
    }
    let ptr = self
      .source
      .allocate(layout)
      .ok_or(RegionError::OutOfMemory)?;
    self.held.set(self.held.get() + layout.size());
    Ok(Chunk { ptr, layout })
  }

  /// Returns a chunk to the source.
  fn give_back(&self, chunk: &Chunk) {
    // SAFETY: the chunk came from `self.source.allocate` for its layout,
    // and the caller removes it from the region, which hands out no piece
    // of it afterwards; no borrow of a piece is live, because every caller
    // holds the region mutably or by value.
    #[expect(unsafe_code, reason = "returning a chunk")]
    unsafe {
      self.source.release(chunk.ptr, chunk.layout);
    }
    self.held.set(self.held.get() - chunk.layout.size());
  }

  /// Makes standard chunk `index` the current one.
  fn enter(&self, standard: &[Chunk], index: usize) {
    let c = &standard[index];
    self.current.set(index + 1);
    self.cursor.set(c.base());
    self.end.set(c.base() + c.layout.size());
  }

  /// A piece of `size` bytes aligned to `align`, uninitialized.
  fn piece(&self, size: usize, align: usize) -> Result<NonNull<u8>, RegionError> {
    if !align.is_power_of_two() || align > MAX_ALIGN || size > isize::MAX as usize {
      return Err(RegionError::Layout);
    }
    if size == 0 {
      // A zero-sized piece needs no memory, only a non-null aligned
      // address.
      return NonNull::new(ptr::without_provenance_mut(align)).ok_or(RegionError::Layout);
    }
    let cur = self.current.get();
    if cur != 0
      && let Some((start, next)) = bump(self.cursor.get(), self.end.get(), size, align)
    {
      self.used.set(self.used.get() + (next - self.cursor.get()));
      self.cursor.set(next);
      return Ok(self.standard.borrow()[cur - 1].at(start));
    }
    if fits_standard(size, align, self.options.chunk) {
      let mut standard = self.standard.borrow_mut();
      if cur >= standard.len() {
        let layout = Layout::from_size_align(self.options.chunk, MIN_CHUNK_ALIGN)
          .map_err(|_| RegionError::Layout)?;
        let chunk = self.take(layout)?;
        standard.push(chunk);
      }
      // The rest of the current chunk counts as used until the reset.
      self
        .used
        .set(self.used.get() + (self.end.get() - self.cursor.get()));
      // A retained chunk (after a reset) or the one just taken.
      self.enter(&standard, cur);
      let (start, next) =
        bump(self.cursor.get(), self.end.get(), size, align).ok_or(RegionError::Layout)?;
      self.used.set(self.used.get() + (next - self.cursor.get()));
      self.cursor.set(next);
      return Ok(standard[cur].at(start));
    }
    let (cap, chunk_align) = own_chunk(size, align).ok_or(RegionError::Layout)?;
    let layout = Layout::from_size_align(cap, chunk_align).map_err(|_| RegionError::Layout)?;
    let chunk = self.take(layout)?;
    let p = chunk.ptr;
    self.own.borrow_mut().push(chunk);
    self.used.set(self.used.get() + size);
    Ok(p)
  }

  /// A piece for `len` values of `T`, uninitialized.
  fn array<T>(&self, len: usize) -> Result<NonNull<T>, RegionError> {
    let size = size_of::<T>().checked_mul(len).ok_or(RegionError::Layout)?;
    Ok(self.piece(size, align_of::<T>())?.cast())
  }

  #[expect(
    clippy::mut_from_ref,
    reason = "each piece is fresh and handed out once; the region never refers to it again"
  )]
  fn alloc_copy<T: Copy>(&self, value: T) -> Result<&mut T, RegionError> {
    let p = self.array::<T>(1)?;
    // SAFETY: `p` is aligned for `T`, valid for writing one `T` (a fresh
    // piece of a chunk this region holds, or a dangling aligned address if
    // `T` is zero-sized), and no other reference to it exists.
    #[expect(unsafe_code, reason = "initializing a fresh piece")]
    unsafe {
      p.as_ptr().write(value);
    }
    // SAFETY: the piece now holds an initialized `T`; it is handed out
    // once, and lives until the region is reset, released or dropped,
    // which the returned borrow of the region outlasts.
    #[expect(unsafe_code, reason = "a reference to the initialized piece")]
    Ok(unsafe { &mut *p.as_ptr() })
  }

  #[expect(
    clippy::mut_from_ref,
    reason = "each piece is fresh and handed out once; the region never refers to it again"
  )]
  fn alloc_slice_fill<T: Copy>(&self, len: usize, value: T) -> Result<&mut [T], RegionError> {
    let p = self.array::<T>(len)?;
    // Zero-sized values need no writes (and `len` may be huge).
    let writes = if size_of::<T>() == 0 { 0 } else { len };
    for i in 0..writes {
      // SAFETY: `i < len` and the piece is valid for writing `len` values
      // of `T` (as in `alloc_copy`), so the element pointer is in bounds
      // and aligned.
      #[expect(unsafe_code, reason = "initializing a fresh piece")]
      unsafe {
        p.as_ptr().wrapping_add(i).write(value);
      }
    }
    // SAFETY: every one of the `len` elements was initialized above; as in
    // `alloc_copy` for the rest.
    #[expect(unsafe_code, reason = "a slice over the initialized piece")]
    Ok(unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), len) })
  }

  #[expect(
    clippy::mut_from_ref,
    reason = "each piece is fresh and handed out once; the region never refers to it again"
  )]
  fn alloc_slice_copy<T: Copy>(&self, src: &[T]) -> Result<&mut [T], RegionError> {
    let p = self.array::<T>(src.len())?;
    // SAFETY: `src` is valid for reading `src.len()` values; the piece is
    // valid for writing as many (as in `alloc_copy`) and is fresh, so the
    // two do not overlap.
    #[expect(unsafe_code, reason = "initializing a fresh piece")]
    unsafe {
      ptr::copy_nonoverlapping(src.as_ptr(), p.as_ptr(), src.len());
    }
    // SAFETY: every element was initialized by the copy; as in
    // `alloc_copy` for the rest.
    #[expect(unsafe_code, reason = "a slice over the initialized piece")]
    Ok(unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), src.len()) })
  }

  fn alloc_zeroed_bytes(&self, len: usize) -> Result<&mut [u8], RegionError> {
    self.alloc_slice_fill(len, 0u8)
  }

  fn alloc_str(&self, s: &str) -> Result<&mut str, RegionError> {
    let bytes = self.alloc_slice_copy(s.as_bytes())?;
    // A copy of valid UTF-8; the check cannot fail.
    core::str::from_utf8_mut(bytes).map_err(|_| RegionError::Layout)
  }

  fn reset(&mut self) {
    let mut kept = 0;
    let retain = self.options.retain;
    let mut standard = core::mem::take(self.standard.get_mut());
    standard.retain(|c| {
      let keep = keep_on_reset(true, c.layout.size(), kept, retain);
      if keep {
        kept += c.layout.size();
      } else {
        self.give_back(c);
      }
      keep
    });
    for c in core::mem::take(self.own.get_mut()) {
      self.give_back(&c);
    }
    if standard.is_empty() {
      self.current.set(0);
      self.cursor.set(0);
      self.end.set(0);
    } else {
      self.enter(&standard, 0);
    }
    *self.standard.get_mut() = standard;
    self.used.set(0);
    self.resets.set(self.resets.get() + 1);
  }

  fn release(&mut self) {
    for c in core::mem::take(self.standard.get_mut()) {
      self.give_back(&c);
    }
    for c in core::mem::take(self.own.get_mut()) {
      self.give_back(&c);
    }
    self.current.set(0);
    self.cursor.set(0);
    self.end.set(0);
    self.used.set(0);
  }

  fn stats(&self) -> RegionStats {
    let (standard, own) = (self.standard.borrow().len(), self.own.borrow().len());
    RegionStats {
      chunks: standard + own,
      own_chunks: own,
      capacity: self.held.get(),
      used: self.used.get(),
      resets: self.resets.get(),
    }
  }
}

impl<S: ChunkSource> Drop for RawRegion<S> {
  fn drop(&mut self) {
    self.release();
  }
}

/// An explicit-lifetime region: many values that die together, allocated
/// by bumping through chunks of the allocatbelt heap and freed all at once.
///
/// Values are borrowed from the region, so the borrow checker keeps every
/// one of them from outliving a [`reset`](Region::reset), a
/// [`release`](Region::release) or the region itself. Only `Copy` values,
/// byte slices and strings can be allocated, always initialized: a type
/// with a destructor is rejected, since the region runs none.
///
/// ```
/// use allocatbelt::Region;
///
/// let mut region = Region::new();
/// for request in ["GET /a", "POST /b"] {
///   let words: Vec<&str> = request.split(' ').collect();
///   let method = region.alloc_str(words[0])?;
///   let counts = region.alloc_slice_fill(4, 0u32)?;
///   counts[0] += 1;
///   assert_eq!((&*method, counts[0]), (words[0], 1));
///   // Everything the request allocated goes at once; the first chunk
///   // stays for the next request.
///   region.reset();
/// }
/// # Ok::<(), allocatbelt::RegionError>(())
/// ```
///
/// Differences from the global allocator, by design:
///
/// * pieces are consecutive in a chunk, not randomized, and are never freed
///   one by one, so there is no double-free check (there is no free);
/// * a piece overflowing its end runs into the next piece of the region, not
///   into a guard page (chunks come from the heap, so the heap's segment
///   guard pages still separate them from other segments);
/// * memory is reused only after a reset, so a long-lived region that keeps
///   allocating grows until it is reset or reaches its limit.
///
/// A region is `Send` and not `Sync`: a task or thread may own it and move
/// it (an async task that holds a borrow of it across an `.await` is not
/// `Send`, as the compiler reports), and it holds no thread-local state.
///
/// The borrow rules, checked at compile time:
///
/// ```compile_fail,E0502
/// let mut region = allocatbelt::Region::new();
/// let x = region.alloc_copy(1u32).unwrap();
/// region.reset(); // `x` is still borrowed
/// *x += 1;
/// ```
///
/// ```compile_fail,E0505
/// let region = allocatbelt::Region::new();
/// let x = region.alloc_copy(1u32).unwrap();
/// drop(region); // `x` is still borrowed
/// *x += 1;
/// ```
///
/// ```compile_fail
/// let mut region = allocatbelt::Region::new();
/// // A piece cannot leave the scope that resets the region.
/// let x = region.scope(|r| r.alloc_copy(1u32).unwrap());
/// ```
///
/// ```compile_fail,E0277
/// // Only `Copy` values: the region runs no destructor.
/// let region = allocatbelt::Region::new();
/// let s = region.alloc_copy(String::from("owned"));
/// ```
///
/// ```compile_fail,E0277
/// // Not `Sync`: another thread cannot allocate from a shared region.
/// let region = allocatbelt::Region::new();
/// std::thread::scope(|s| {
///   s.spawn(|| region.alloc_copy(1u32).map(|x| *x));
/// });
/// ```
pub struct Region {
  raw: RawRegion<HeapChunks>,
}

impl Region {
  /// An empty region with the default options; takes no memory until the
  /// first allocation.
  #[must_use]
  pub const fn new() -> Self {
    Self::with_options(RegionOptions::DEFAULT)
  }

  /// An empty region with `options`.
  #[must_use]
  pub const fn with_options(options: RegionOptions) -> Self {
    Self {
      raw: RawRegion::new(HeapChunks, options),
    }
  }

  /// The options the region was made with.
  #[must_use]
  pub const fn options(&self) -> RegionOptions {
    self.raw.options
  }

  /// Allocates `value` in the region.
  ///
  /// # Errors
  ///
  /// [`RegionError`] if a chunk was needed and could not be taken; the
  /// region and its other pieces are unchanged.
  pub fn alloc_copy<T: Copy>(&self, value: T) -> Result<&mut T, RegionError> {
    self.raw.alloc_copy(value)
  }

  /// Allocates `len` copies of `value`.
  ///
  /// # Errors
  ///
  /// As [`Region::alloc_copy`]; also [`RegionError::Layout`] if `len`
  /// values of `T` do not fit `isize::MAX` bytes.
  pub fn alloc_slice_fill<T: Copy>(&self, len: usize, value: T) -> Result<&mut [T], RegionError> {
    self.raw.alloc_slice_fill(len, value)
  }

  /// Allocates a copy of `src`.
  ///
  /// # Errors
  ///
  /// As [`Region::alloc_slice_fill`].
  pub fn alloc_slice_copy<T: Copy>(&self, src: &[T]) -> Result<&mut [T], RegionError> {
    self.raw.alloc_slice_copy(src)
  }

  /// Allocates `len` zero bytes.
  ///
  /// # Errors
  ///
  /// As [`Region::alloc_slice_fill`].
  pub fn alloc_zeroed_bytes(&self, len: usize) -> Result<&mut [u8], RegionError> {
    self.raw.alloc_zeroed_bytes(len)
  }

  /// Allocates a copy of `s`.
  ///
  /// # Errors
  ///
  /// As [`Region::alloc_slice_fill`].
  pub fn alloc_str(&self, s: &str) -> Result<&mut str, RegionError> {
    self.raw.alloc_str(s)
  }

  /// Forgets every piece and keeps standard chunks up to
  /// [`RegionOptions::retain_bytes`] for reuse, returning the rest (and
  /// every chunk of its own) to the heap. Costs one step per chunk held;
  /// no value is dropped (only `Copy` values are held).
  pub fn reset(&mut self) {
    self.raw.reset();
  }

  /// Forgets every piece and returns every chunk to the heap, as dropping
  /// the region does, but keeps the region for further use.
  pub fn release(&mut self) {
    self.raw.release();
  }

  /// Runs `f` with the region, then resets it. Pieces cannot leave `f`. If
  /// `f` panics, the region is not reset here, and stays usable.
  pub fn scope<R>(&mut self, f: impl FnOnce(&Self) -> R) -> R {
    let r = f(self);
    self.reset();
    r
  }

  /// What the region holds.
  #[must_use]
  pub fn stats(&self) -> RegionStats {
    self.raw.stats()
  }
}

impl Default for Region {
  fn default() -> Self {
    Self::new()
  }
}

impl fmt::Debug for Region {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Region")
      .field("options", &self.raw.options)
      .field("stats", &self.stats())
      .finish()
  }
}

#[cfg(test)]
mod tests;
