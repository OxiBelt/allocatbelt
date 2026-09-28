//! The only place where allocatbelt talks to the kernel or creates references
//! from raw memory.
//!
//! Everything here is a thin, bounds-checked wrapper over one syscall or one
//! raw-memory conversion. Each `unsafe` block performs a single operation and
//! states why its preconditions hold. Functions that can invalidate memory a
//! caller might still use ([`Region::purge`], [`Region::decommit`]) are
//! `unsafe fn` and document the contract the caller (the heap) must uphold.
//!
//! Nothing in this crate allocates, panics on the hot path, or unwinds.

#![no_std]
#![cfg(target_os = "linux")]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use rustix::mm::{self, Advice, MapFlags, MprotectFlags, ProtFlags};

/// A reserved, never-unmapped range of virtual address space.
///
/// Reservation maps the range `PROT_NONE` with `MAP_NORESERVE`, so it costs
/// neither physical memory nor commit charge until [`Region::commit`].
#[derive(Debug)]
pub struct Region {
  base: NonNull<u8>,
  len: usize,
}

// SAFETY: `Region` is an address-range handle. It exposes no references to
// the memory it covers; all mutation goes through syscalls on the kernel's
// page tables, which are thread-safe, so sharing the handle is sound.
#[expect(unsafe_code, reason = "raw pointer field opts out of Send")]
unsafe impl Send for Region {}
// SAFETY: see the `Send` impl above.
#[expect(unsafe_code, reason = "raw pointer field opts out of Sync")]
unsafe impl Sync for Region {}

impl Region {
  /// Reserves `len` bytes aligned to `align` (a power of two, at least
  /// [`GRANULE`]). `len` must be a multiple of [`GRANULE`]. Returns `None` if the kernel refuses the mapping.
  #[must_use]
  pub fn reserve(len: usize, align: usize) -> Option<Self> {
    if len == 0
      || !len.is_multiple_of(GRANULE)
      || !align.is_power_of_two()
      || !align.is_multiple_of(GRANULE)
    {
      return None;
    }
    let total = len.checked_add(align)?;
    let flags = MapFlags::PRIVATE | MapFlags::NORESERVE;
    // SAFETY: a null hint without MAP_FIXED makes the kernel pick a fresh,
    // unused range, so the new mapping cannot alias any existing memory.
    #[expect(unsafe_code, reason = "mmap syscall")]
    let raw =
      unsafe { mm::mmap_anonymous(core::ptr::null_mut(), total, ProtFlags::empty(), flags) }
        .ok()?
        .cast::<u8>();
    // The kernel returns page-aligned addresses, so `head` and `tail` are
    // page multiples even though they need not be GRANULE multiples.
    let head = raw.addr().next_multiple_of(align) - raw.addr();
    let base = raw.wrapping_add(head);
    let tail = total - head - len;
    if head > 0 {
      // SAFETY: `raw..raw + head` is the page-aligned start of the
      // mapping created above; nothing has been handed out from it.
      #[expect(unsafe_code, reason = "munmap syscall")]
      let _ = unsafe { mm::munmap(raw.cast(), head) };
    }
    if tail > 0 {
      // SAFETY: `base + len..base + len + tail` is the page-aligned end
      // of the same fresh mapping; nothing has been handed out from it.
      #[expect(unsafe_code, reason = "munmap syscall")]
      let _ = unsafe { mm::munmap(base.wrapping_add(len).cast(), tail) };
    }
    Some(Self {
      base: NonNull::new(base)?,
      len,
    })
  }

  /// Length of the region in bytes.
  #[must_use]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether the region is empty (never true for a reserved region).
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Pointer to `offset` inside the region, carrying the region's
  /// provenance. Creating the pointer is always safe; using it requires the
  /// range to be committed.
  #[must_use]
  pub fn ptr(&self, offset: usize) -> Option<NonNull<u8>> {
    if offset >= self.len {
      return None;
    }
    NonNull::new(self.base.as_ptr().wrapping_add(offset))
  }

  /// Offset of `ptr` inside the region, or `None` if it is outside.
  #[must_use]
  pub fn offset_of(&self, ptr: *const u8) -> Option<usize> {
    ptr
      .addr()
      .checked_sub(self.base.addr().get())
      .filter(|&o| o < self.len)
  }

  fn range(&self, offset: usize, len: usize) -> Option<*mut c_void> {
    let end = offset.checked_add(len)?;
    if len == 0 || end > self.len || !offset.is_multiple_of(GRANULE) || !len.is_multiple_of(GRANULE)
    {
      return None;
    }
    Some(self.base.as_ptr().wrapping_add(offset).cast())
  }

  /// Makes `offset..offset + len` readable and writable. Only adds
  /// permissions, so it can never invalidate memory in use.
  #[must_use]
  pub fn commit(&self, offset: usize, len: usize) -> bool {
    let Some(p) = self.range(offset, len) else {
      return false;
    };
    // SAFETY: `range` checked that the page-aligned span lies inside our
    // own mapping; upgrading it to read/write cannot break any existing
    // reference (at worst it is already read/write).
    #[expect(unsafe_code, reason = "mprotect syscall")]
    let r = unsafe { mm::mprotect(p, len, MprotectFlags::READ | MprotectFlags::WRITE) };
    r.is_ok()
  }

  /// Returns the physical pages of the range to the kernel. The range stays
  /// accessible. Returns `true` if it now reads back as zeroes; `false` if
  /// the kernel refused (e.g. `EINVAL` for `mlock`ed pages), in which case
  /// the contents are unchanged.
  ///
  /// # Safety
  ///
  /// No reference to, and no concurrent access of, any byte of
  /// `offset..offset + len` may exist: its contents are discarded.
  #[expect(unsafe_code, reason = "contract: caller owns the range")]
  pub unsafe fn purge(&self, offset: usize, len: usize) -> bool {
    let Some(p) = self.range(offset, len) else {
      return false;
    };
    // SAFETY: the span is inside our mapping (checked by `range`) and the
    // caller guarantees nothing observes its contents being zeroed.
    #[expect(unsafe_code, reason = "madvise syscall")]
    let r = unsafe { mm::madvise(p, len, Advice::LinuxDontNeed) };
    r.is_ok()
  }

  /// Returns the physical pages of the range and makes it inaccessible.
  /// Returns `true` if the range will read as zeroes once committed again.
  ///
  /// # Safety
  ///
  /// As for [`Region::purge`]; additionally nothing may access the range
  /// until it is committed again.
  #[expect(unsafe_code, reason = "contract: caller owns the range")]
  pub unsafe fn decommit(&self, offset: usize, len: usize) -> bool {
    let Some(p) = self.range(offset, len) else {
      return false;
    };
    // SAFETY: forwarded caller contract; the span is inside our mapping.
    #[expect(unsafe_code, reason = "purge contract is identical")]
    let zeroed = unsafe { self.purge(offset, len) };
    // SAFETY: the span is inside our mapping and, per the caller
    // contract, unused, so revoking access cannot fault a live user.
    #[expect(unsafe_code, reason = "mprotect syscall")]
    let _ = unsafe { mm::mprotect(p, len, MprotectFlags::empty()) };
    zeroed
  }

  /// Makes the range fault on any access, discarding its contents. Uses
  /// guard markers (`MADV_GUARD_INSTALL`, Linux 6.13+), which do not split
  /// the mapping into more VMAs; on older kernels falls back to
  /// `mprotect(PROT_NONE)`. Returns `false` if neither worked.
  /// [`Region::unguard`] removes the markers, and [`Region::commit`]
  /// restores access after the fallback.
  ///
  /// # Safety
  ///
  /// As for [`Region::decommit`].
  #[expect(unsafe_code, reason = "contract: caller owns the range")]
  pub unsafe fn guard(&self, offset: usize, len: usize) -> bool {
    let Some(p) = self.range(offset, len) else {
      return false;
    };
    // SAFETY: the span is inside our mapping (checked by `range`), and the
    // caller guarantees nothing uses its contents, which the markers
    // discard.
    #[expect(unsafe_code, reason = "madvise syscall")]
    let r = unsafe { libc::madvise(p, len, MADV_GUARD_INSTALL) };
    if r == 0 {
      // Emulators (qemu-user) and some sandboxes accept advice they do not
      // implement. Populating a real guard region fails with `EFAULT`.
      // SAFETY: the span is inside our mapping; populating only faults in
      // pages for reading and changes no contents.
      #[expect(unsafe_code, reason = "madvise syscall")]
      let probe = unsafe { mm::madvise(p, len, Advice::LinuxPopulateRead) };
      if probe == Err(rustix::io::Errno::FAULT) {
        return true;
      }
      self.unguard(offset, len);
    }
    // SAFETY: as above; revoking access cannot fault a live user.
    #[expect(unsafe_code, reason = "mprotect syscall")]
    let r = unsafe { mm::mprotect(p, len, MprotectFlags::empty()) };
    r.is_ok()
  }

  /// Removes guard markers installed by [`Region::guard`]; a no-op for a
  /// range without any, and on kernels without guard markers.
  pub fn unguard(&self, offset: usize, len: usize) {
    let Some(p) = self.range(offset, len) else {
      return;
    };
    // SAFETY: the span is inside our mapping. Removing guard markers turns
    // faulting pages into zero-fill-on-demand pages and leaves other pages
    // alone, so it cannot invalidate memory in use.
    #[expect(unsafe_code, reason = "madvise syscall")]
    let _ = unsafe { libc::madvise(p, len, MADV_GUARD_REMOVE) };
  }
}

/// `madvise` advice for guard markers (Linux 6.13+,
/// `include/uapi/asm-generic/mman-common.h`); not yet in the `libc` crate.
const MADV_GUARD_INSTALL: libc::c_int = 102;
const MADV_GUARD_REMOVE: libc::c_int = 103;

const SLOT_EMPTY: u8 = 0;
const SLOT_BUSY: u8 = 1;
const SLOT_READY: u8 = 2;

/// `N` lazily committed slots of `AtomicU64` words, handed out as shared
/// slices. Slots are never decommitted, which is what makes the returned
/// references valid for the lifetime of the arena.
#[derive(Debug)]
pub struct MetaArena<const N: usize> {
  region: Region,
  words: usize,
  slot_bytes: usize,
  state: [AtomicU8; N],
}

impl<const N: usize> MetaArena<N> {
  /// Reserves address space for `N` slots of `words` words each.
  #[must_use]
  pub fn reserve(words: usize) -> Option<Self> {
    let slot_bytes = words.checked_mul(8)?.next_multiple_of(GRANULE);
    let region = Region::reserve(slot_bytes.checked_mul(N)?, GRANULE)?;
    Some(Self {
      region,
      words,
      slot_bytes,
      state: [const { AtomicU8::new(SLOT_EMPTY) }; N],
    })
  }

  /// Commits slot `i` if needed and returns its words.
  pub fn commit(&self, i: usize) -> Option<&[AtomicU64]> {
    let st = self.state.get(i)?;
    loop {
      match st.compare_exchange(SLOT_EMPTY, SLOT_BUSY, Ordering::Acquire, Ordering::Acquire) {
        Ok(_) => {
          if !self.region.commit(i * self.slot_bytes, self.slot_bytes) {
            st.store(SLOT_EMPTY, Ordering::Release);
            return None;
          }
          st.store(SLOT_READY, Ordering::Release);
          return Some(self.slot(i));
        }
        Err(SLOT_READY) => return Some(self.slot(i)),
        Err(_) => core::hint::spin_loop(),
      }
    }
  }

  /// Words of slot `i` if it has been committed.
  #[must_use]
  pub fn get(&self, i: usize) -> Option<&[AtomicU64]> {
    (self.state.get(i)?.load(Ordering::Acquire) == SLOT_READY).then(|| self.slot(i))
  }

  /// Caller has observed `state[i] == SLOT_READY` with `Acquire`.
  fn slot(&self, i: usize) -> &[AtomicU64] {
    let p = self
      .region
      .base
      .as_ptr()
      .wrapping_add(i * self.slot_bytes)
      .cast::<AtomicU64>();
    // SAFETY: slot `i` lies inside the region (`i < N`, region is
    // `N * slot_bytes`), was committed read/write before READY was
    // published, is never decommitted or unmapped (`Region` has no
    // `Drop`), starts page-aligned (so 8-aligned), and `words * 8 <=
    // slot_bytes`. The kernel zero-fills it, `AtomicU64` accepts every bit
    // pattern, and all access is atomic, so shared references never race.
    #[expect(unsafe_code, reason = "exposing committed memory as atomics")]
    unsafe {
      core::slice::from_raw_parts(p, self.words)
    }
  }
}

/// Granularity of every range this crate maps, commits or purges.
///
/// 64 KiB is a multiple of every Linux page size (4, 16 and 64 KiB), so the
/// crate never has to query the page size. That matters: `rustix`'s
/// `page_size()` reads the auxiliary vector lazily and may allocate when its
/// `alloc` feature is unified in, which would re-enter the allocator.
pub const GRANULE: usize = 64 * 1024;

/// Gives up the CPU while spinning on a contended lock.
pub fn yield_now() {
  rustix::thread::sched_yield();
}

/// Registers `fork` handlers with `pthread_atfork(3)`: `prepare` runs in
/// the forking thread before the fork, `parent` and `child` after it in the
/// respective process. Returns whether the registration succeeded; handlers
/// stay registered for the life of the process.
pub fn register_atfork(
  prepare: extern "C" fn(),
  parent: extern "C" fn(),
  child: extern "C" fn(),
) -> bool {
  let [prepare, parent, child] = [prepare, parent, child].map(|f| f as unsafe extern "C" fn());
  // SAFETY: the handlers are `extern "C"` functions without arguments, as
  // `pthread_atfork` expects, and function pointers stay valid for the life
  // of the process. Calling them is sound: they are safe functions.
  #[expect(unsafe_code, reason = "pthread_atfork call")]
  let r = unsafe { libc::pthread_atfork(Some(prepare), Some(parent), Some(child)) };
  r == 0
}

/// 64 bits from the kernel CSPRNG (`getrandom(2)`), for hardening secrets.
/// Returns `None` instead of blocking when the kernel's pool is not
/// initialised yet (early boot).
#[must_use]
pub fn random_u64() -> Option<u64> {
  let mut buf = [0u8; 8];
  match rustix::rand::getrandom(&mut buf, rustix::rand::GetRandomFlags::NONBLOCK) {
    Ok(8) => Some(u64::from_ne_bytes(buf)),
    _ => None,
  }
}
