//! A checking model of the heap's environment, shared by the unit tests and
//! the fuzz target (`--features model`).
//!
//! [`MockOs`] never backs user memory. It checks the heap's promises against
//! shadow maps instead: blocks handed out are committed and overlap no live
//! block or guard page; purged, decommitted and guarded ranges hold no live
//! block; blocks reported as zeroed were not written since they were last
//! purged; nothing guarded is committed again. The checked operations below
//! (`alloc`, `free_c`, `resize`, ...) keep the shadow maps in step with the
//! heap, and [`run`] interprets arbitrary bytes as a program of them.

#![allow(
  clippy::unwrap_used,
  clippy::expect_used,
  reason = "a test harness: a failed check is meant to panic"
)]

use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use crate::core::{
  ARENA_SIZE, AgeKernel, Block, Heap, MAX_SEGMENTS, META_WORDS, Os, PAGE_SIZE, PURGE_BATCH, Purger,
  ReclaimTargets, Retention, SEGMENT_SIZE, ThreadCache, aged_pages,
};

/// An [`Os`] that records what the heap does and checks it.
pub struct MockOs {
  meta: Vec<OnceLock<Box<[AtomicU64]>>>,
  pub(crate) committed: Vec<AtomicBool>,
  /// Live blocks: start offset to end offset.
  pub(crate) live: Mutex<BTreeMap<usize, usize>>,
  /// Pages the "program" wrote to since they were last purged.
  pub(crate) written: Mutex<BTreeSet<usize>>,
  /// Pages behind a guard ([`Os::guard`]).
  pub(crate) guarded: Mutex<BTreeSet<usize>>,
  /// Bytes handed back to the OS by `purge` or `decommit`.
  pub(crate) purged: AtomicUsize,
  /// Makes `purge` and `decommit` report failure, as `madvise` does on
  /// `mlock`ed memory.
  pub(crate) purge_fails: AtomicBool,
  /// The clock `now_ms` reports; advanced by hand.
  clock: AtomicU64,
  /// `futex_wake` calls (lock hand-offs and maintenance wake-ups).
  pub(crate) wakes: AtomicUsize,
  /// Timeout of the last `futex_wait` that had one (an idle
  /// [`Heap::maintain`]), in ms.
  pub(crate) last_wait_ms: AtomicU64,
  /// The [`Os::shard_hint`] reported; `usize::MAX` for none.
  pub(crate) hint: AtomicUsize,
  /// Makes every [`Os::shard_hint`] report the next shard, as if the
  /// thread moved to another CPU between any two slow-path calls.
  pub(crate) migrate: AtomicBool,
  /// Makes [`Os::age_kernel`] return the portable [`aged_pages`], so that
  /// decay passes take the snapshot path that architecture kernels use.
  pub(crate) age_kernel: AtomicBool,
}

impl MockOs {
  /// A fresh environment: nothing committed, the clock at 0.
  #[must_use]
  pub fn new() -> Self {
    Self {
      meta: (0..MAX_SEGMENTS).map(|_| OnceLock::new()).collect(),
      committed: (0..MAX_SEGMENTS).map(|_| AtomicBool::new(false)).collect(),
      live: Mutex::new(BTreeMap::new()),
      written: Mutex::new(BTreeSet::new()),
      guarded: Mutex::new(BTreeSet::new()),
      purged: AtomicUsize::new(0),
      purge_fails: AtomicBool::new(false),
      clock: AtomicU64::new(0),
      wakes: AtomicUsize::new(0),
      last_wait_ms: AtomicU64::new(0),
      hint: AtomicUsize::new(usize::MAX),
      migrate: AtomicBool::new(false),
      age_kernel: AtomicBool::new(false),
    }
  }

  /// Moves the clock forward.
  pub fn advance(&self, ms: u64) {
    self.clock.fetch_add(ms, Ordering::Relaxed);
  }

  /// Clears the written marks of the range unless purging fails.
  fn zero(&self, offset: usize, len: usize) -> bool {
    if self.purge_fails.load(Ordering::Relaxed) {
      return false;
    }
    let mut w = self.written.lock().unwrap();
    let pages: Vec<_> = w
      .range(offset / PAGE_SIZE..(offset + len).div_ceil(PAGE_SIZE))
      .copied()
      .collect();
    for p in pages {
      w.remove(&p);
    }
    true
  }

  fn assert_no_live(&self, offset: usize, len: usize, what: &str) {
    let live = self.live.lock().unwrap();
    if let Some((&s, &e)) = live.range(..offset + len).next_back() {
      assert!(
        e <= offset,
        "{what} of {offset:#x}+{len:#x} overlaps live {s:#x}..{e:#x}"
      );
    }
  }

  pub(crate) fn assert_unguarded(&self, offset: usize, len: usize, what: &str) {
    let g = self.guarded.lock().unwrap();
    let hit = g
      .range(offset / PAGE_SIZE..(offset + len).div_ceil(PAGE_SIZE))
      .next();
    assert!(
      hit.is_none(),
      "{what} of {offset:#x}+{len:#x} covers guard page {hit:?}"
    );
  }
}

impl Default for MockOs {
  fn default() -> Self {
    Self::new()
  }
}

impl Os for MockOs {
  fn commit(&self, offset: usize, len: usize) -> bool {
    assert_eq!(offset % SEGMENT_SIZE, 0);
    self.assert_unguarded(offset, len, "commit");
    for s in offset / SEGMENT_SIZE..(offset + len) / SEGMENT_SIZE {
      self.committed[s].store(true, Ordering::Relaxed);
    }
    true
  }
  fn decommit(&self, offset: usize, len: usize) -> bool {
    self.assert_no_live(offset, len, "decommit");
    for s in offset / SEGMENT_SIZE..(offset + len) / SEGMENT_SIZE {
      self.committed[s].store(false, Ordering::Relaxed);
    }
    self.purged.fetch_add(len, Ordering::Relaxed);
    self.zero(offset, len)
  }
  fn purge(&self, offset: usize, len: usize) -> bool {
    self.assert_no_live(offset, len, "purge");
    self.purged.fetch_add(len, Ordering::Relaxed);
    self.zero(offset, len)
  }
  fn guard(&self, offset: usize, len: usize) -> bool {
    self.assert_no_live(offset, len, "guard");
    let mut g = self.guarded.lock().unwrap();
    g.extend(offset / PAGE_SIZE..(offset + len) / PAGE_SIZE);
    true
  }
  fn unguard(&self, offset: usize, len: usize) {
    let mut g = self.guarded.lock().unwrap();
    for p in offset / PAGE_SIZE..(offset + len) / PAGE_SIZE {
      assert!(g.remove(&p), "unguard of page {p}, which is not guarded");
    }
  }
  fn commit_meta(&self, segment: usize) -> Option<&[AtomicU64]> {
    Some(self.meta[segment].get_or_init(|| (0..META_WORDS).map(|_| AtomicU64::new(0)).collect()))
  }
  fn meta(&self, segment: usize) -> Option<&[AtomicU64]> {
    self.meta[segment].get().map(|m| &**m)
  }
  // No real futex: a parked thread yields and re-checks, which the lock
  // allows (spurious wake-ups), and wakes are then unnecessary.
  fn futex_wait(&self, word: &AtomicU32, expected: u32, timeout_ms: Option<u64>) {
    if let Some(ms) = timeout_ms {
      self.last_wait_ms.store(ms, Ordering::Relaxed);
    }
    if word.load(Ordering::Relaxed) == expected {
      std::thread::yield_now();
    }
  }
  fn futex_wake(&self, _word: &AtomicU32) {
    self.wakes.fetch_add(1, Ordering::Relaxed);
  }
  fn now_ms(&self) -> u64 {
    self.clock.load(Ordering::Relaxed)
  }
  fn shard_hint(&self) -> Option<usize> {
    let hint = if self.migrate.load(Ordering::Relaxed) {
      self.hint.fetch_add(1, Ordering::Relaxed)
    } else {
      self.hint.load(Ordering::Relaxed)
    };
    (hint != usize::MAX).then_some(hint)
  }

  fn age_kernel(&self) -> Option<AgeKernel> {
    self
      .age_kernel
      .load(Ordering::Relaxed)
      .then_some(aged_pages as AgeKernel)
  }

  fn fatal(&self, msg: &'static str) -> ! {
    panic!("{msg}")
  }
}

/// A [`Purger`] standing in for an asynchronous backend such as io_uring.
/// It checks each batch when it is "submitted", runs [`MockPurger::during`]
/// while the purges are "in flight", then completes them in reverse order,
/// checking again that nothing was handed out meanwhile. Every
/// `fail_every`-th run fails (0: none), as a failed completion would.
pub struct MockPurger<'a> {
  /// The environment whose shadow maps the purges update.
  pub os: &'a MockOs,
  /// Runs per batch the purger asks for.
  pub batch: usize,
  /// Fail every n-th run (counted across batches); 0 never fails.
  pub fail_every: usize,
  /// Runs seen so far.
  pub runs: usize,
  /// Batches seen so far.
  pub batches: usize,
  /// Run while a batch is in flight: other threads' allocations and frees.
  pub during: Option<&'a dyn Fn()>,
}

impl<'a> MockPurger<'a> {
  /// A purger with batches of `batch` runs that never fails.
  pub fn new(os: &'a MockOs, batch: usize) -> Self {
    Self {
      os,
      batch,
      fail_every: 0,
      runs: 0,
      batches: 0,
      during: None,
    }
  }
}

impl Purger for MockPurger<'_> {
  fn batch_size(&self) -> usize {
    self.batch
  }
  fn purge_batch(&mut self, ranges: &[(usize, usize)], purged: &mut [bool]) {
    assert!(ranges.len() <= PURGE_BATCH);
    assert_eq!(ranges.len(), purged.len());
    for &(offset, len) in ranges {
      assert!(len > 0 && offset.is_multiple_of(PAGE_SIZE) && len.is_multiple_of(PAGE_SIZE));
      self.os.assert_no_live(offset, len, "submitted purge");
      self.os.assert_unguarded(offset, len, "submitted purge");
    }
    if let Some(during) = self.during {
      during();
    }
    self.batches += 1;
    for (i, &(offset, len)) in ranges.iter().enumerate().rev() {
      let n = self.runs + i + 1;
      purged[i] = if self.fail_every != 0 && n.is_multiple_of(self.fail_every) {
        // Nothing handed out the pages meanwhile, even when it fails.
        self.os.assert_no_live(offset, len, "failed purge");
        false
      } else {
        self.os.purge(offset, len)
      };
    }
    self.runs += ranges.len();
  }
}

/// Allocates (uncached) and records the block in the shadow maps, checking
/// the allocator's post-conditions.
pub fn alloc(h: &Heap<MockOs>, shard: usize, size: usize, align: usize) -> usize {
  alloc_block(h, shard, size, align).offset
}

/// As [`alloc`], returning the whole [`Block`]. The block is then treated as
/// written, like a program would.
pub fn alloc_block(h: &Heap<MockOs>, shard: usize, size: usize, align: usize) -> Block {
  let b = h.alloc_block(shard, size, align).expect("out of memory");
  record(h, b, size, align);
  b
}

/// Allocates through a thread cache, with the same checks as [`alloc`].
pub fn alloc_c(h: &Heap<MockOs>, tc: &ThreadCache, size: usize, align: usize) -> usize {
  let b = h.alloc_cached(tc, size, align).expect("out of memory");
  record(h, b, size, align);
  b.offset
}

/// Frees (uncached), updating the shadow map.
pub fn free(h: &Heap<MockOs>, off: usize) {
  h.os().live.lock().unwrap().remove(&off);
  h.dealloc(off);
}

/// Frees through a thread cache, updating the shadow map.
pub fn free_c(h: &Heap<MockOs>, tc: &ThreadCache, off: usize) {
  h.os().live.lock().unwrap().remove(&off);
  h.dealloc_cached(tc, off);
}

/// An attached cache, as a thread would hold it.
pub fn cache(h: &Heap<MockOs>) -> ThreadCache {
  let tc = ThreadCache::new();
  tc.begin_attach();
  h.attach(&tc);
  tc
}

/// Checks the allocator's post-conditions for a fresh block and records it
/// in the shadow maps.
pub fn record(h: &Heap<MockOs>, b: Block, size: usize, align: usize) {
  let off = b.offset;
  {
    let mut w = h.os().written.lock().unwrap();
    let pages = off / PAGE_SIZE..(off + size.max(1)).div_ceil(PAGE_SIZE);
    if b.zeroed {
      let dirty = w.range(pages.clone()).next();
      assert!(
        dirty.is_none(),
        "{b:?} claims zero but page {dirty:?} was written"
      );
    }
    w.extend(pages);
  }
  h.os().assert_unguarded(off, size.max(1), "allocation");
  assert_eq!(off % align, 0, "size {size} align {align} -> {off:#x}");
  assert!(off + size <= ARENA_SIZE);
  let usable = h.usable_size(off);
  assert!(usable >= size, "usable {usable} < {size}");
  let end = off + size.max(1);
  for s in off / SEGMENT_SIZE..end.div_ceil(SEGMENT_SIZE) {
    assert!(
      h.os().committed[s].load(Ordering::Relaxed),
      "segment {s} not committed"
    );
  }
  let mut live = h.os().live.lock().unwrap();
  if let Some((&s, &e)) = live.range(..end).next_back() {
    assert!(
      e <= off,
      "new {off:#x}..{end:#x} overlaps live {s:#x}..{e:#x}"
    );
  }
  live.insert(off, end);
}

/// Resizes in place, updating the shadow maps and checking that a grown
/// block stays committed and overlaps nothing.
pub fn resize(h: &Heap<MockOs>, off: usize, new_size: usize) -> bool {
  // While shrinking, only the first `new_size` bytes must stay intact.
  let old_end = h.os().live.lock().unwrap()[&off];
  h.os()
    .live
    .lock()
    .unwrap()
    .insert(off, old_end.min(off + new_size.max(1)));
  if !h.resize_in_place(off, new_size) {
    h.os().live.lock().unwrap().insert(off, old_end);
    return false;
  }
  assert!(h.usable_size(off) >= new_size);
  h.os().assert_unguarded(off, new_size.max(1), "resize");
  let end = off + new_size.max(1);
  for s in off / SEGMENT_SIZE..end.div_ceil(SEGMENT_SIZE) {
    assert!(
      h.os().committed[s].load(Ordering::Relaxed),
      "segment {s} not committed"
    );
  }
  let mut live = h.os().live.lock().unwrap();
  live.remove(&off);
  if let Some((&s, &e)) = live.range(..end).next_back() {
    assert!(
      e <= off,
      "resized {off:#x}..{end:#x} overlaps live {s:#x}..{e:#x}"
    );
  }
  live.insert(off, end);
  h.os()
    .written
    .lock()
    .unwrap()
    .extend(off / PAGE_SIZE..end.div_ceil(PAGE_SIZE));
  true
}

/// Live bytes above which [`run`] stops allocating, so that the 64 GiB
/// arena cannot run out (which would be a legitimate `None`).
const RUN_LIVE_LIMIT: usize = 8 << 30;

/// Decodes a request size from two bytes, spread over every block kind:
/// class blocks, page runs and multi-segment blocks.
fn size_of(hi: u8, lo: u8) -> usize {
  let v = usize::from(hi & 0x3F) << 8 | usize::from(lo);
  match hi >> 6 {
    0 => v % 257,
    1 => v % 8193,
    2 => v * 16,
    _ => v * 1024,
  }
}

/// Runs the program encoded in `data` on a fresh heap, with every check of
/// this module. Any byte string is a valid program; a panic is a heap bug.
///
/// Operations go through two attached thread caches, a detached one (the
/// uncached paths through a cache) and the uncached API, so frees routinely
/// cross "threads". The program also flushes and retires caches, purges,
/// runs decay passes, advances the clock, changes the purge delay, the
/// reclamation thresholds, the slice size, the retention mode and how often
/// decay sweeps reconcile the empty-page candidates, hands
/// housekeeping to a maintenance "thread" and back, runs its rounds (also
/// with a batching [`MockPurger`] that fails some runs) and requests purges
/// from it; the
/// first byte seeds randomized placement (or not) and makes the shard
/// hints move on every call (or not). At the end everything is
/// freed and a forced purge must leave nothing dirty.
pub fn run(data: &[u8]) {
  let h = Box::new(Heap::new(MockOs::new()));
  let mut bytes = data.iter().copied();
  let seed = bytes.next().unwrap_or(0);
  if seed & 1 == 1 {
    h.set_seed(u64::from(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15));
  }
  if seed & 2 == 2 {
    // Shard hints that change on every call (an rseq `mm_cid` of a thread
    // that keeps migrating).
    h.os().hint.store(usize::from(seed), Ordering::Relaxed);
    h.os().migrate.store(true, Ordering::Relaxed);
  }
  let caches = [cache(&h), cache(&h), ThreadCache::new()];
  let mut live: Vec<(usize, usize)> = Vec::new();
  let mut live_bytes = 0usize;
  while let Some(op) = bytes.next() {
    let mut byte = || bytes.next().unwrap_or(0);
    let who = usize::from(op >> 5) % 4;
    let tc = caches.get(who);
    match op & 0x1F {
      0..=11 => {
        let size = size_of(byte(), byte());
        let align = 1usize << (byte() % 23);
        if live_bytes + size > RUN_LIVE_LIMIT {
          continue;
        }
        let off = match tc {
          Some(tc) => alloc_c(&h, tc, size, align),
          None => alloc(&h, usize::from(op), size, align),
        };
        live.push((off, size));
        live_bytes += size;
      }
      12..=19 if !live.is_empty() => {
        let (off, size) = live.swap_remove(usize::from(byte()) % live.len());
        live_bytes -= size;
        match tc {
          Some(tc) => free_c(&h, tc, off),
          None => free(&h, off),
        }
      }
      20 | 21 if !live.is_empty() => {
        let i = usize::from(byte()) % live.len();
        let size = size_of(byte(), byte());
        if live_bytes - live[i].1 + size <= RUN_LIVE_LIMIT && resize(&h, live[i].0, size) {
          live_bytes = live_bytes - live[i].1 + size;
          live[i].1 = size;
        }
      }
      22 => match tc {
        Some(tc) => h.flush(tc),
        // Asks every cache to drain itself at its next sampled slow path.
        None => h.request_cache_return(),
      },
      23 => {
        h.purge();
        h.check_indexes();
      }
      24 => {
        h.decay();
        h.check_indexes();
      }
      25 => h.os().advance(u64::from(byte()) * 16),
      26 => {
        let b = byte();
        match b % 4 {
          0 | 1 => h.set_purge_delay_ms(u64::from(byte()) * 8),
          2 => {
            // Thresholds, valid or not (a refused set changes nothing).
            let low = usize::from(byte()) * 4;
            let trigger = low + usize::from(byte()) * 4;
            let emergency = trigger + usize::from(byte()) * 8;
            if let Ok(t) = ReclaimTargets::new(low, trigger, emergency) {
              h.set_reclaim_targets(t);
            }
          }
          _ => {
            // Slices from one work unit up, so sweeps resume often.
            h.set_slice_work(1 + u64::from(byte()) * 8);
            // Decay sweeps that trust the empty-page candidates alone, or
            // reconcile every few epochs.
            h.set_reconcile_epochs(u64::from(byte() % 4));
            h.set_retention(if b & 4 == 0 {
              Retention::Fixed
            } else {
              Retention::Adaptive
            });
          }
        }
      }
      27 => tc.into_iter().for_each(|tc| h.retire(tc)),
      28 if h.maintenance_attached() => h.detach_maintenance(),
      28 => h.attach_maintenance(),
      29 => {
        let _ = h.maintain();
      }
      30 => h.request_purge(),
      31 => {
        let mut p = MockPurger::new(h.os(), usize::from(byte()) % (PURGE_BATCH + 2));
        p.fail_every = usize::from(byte() % 4);
        let _ = h.maintain_with(&mut p);
        assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
        check_observations(&h, &caches);
      }
      _ => {}
    }
  }
  for (off, _) in live {
    free(&h, off);
  }
  for tc in &caches {
    h.retire(tc);
  }
  assert!(h.os().live.lock().unwrap().is_empty());
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  h.purge();
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  if !h.os().purge_fails.load(Ordering::Relaxed) {
    assert_eq!(h.dirty_pages(), 0, "a forced purge left dirty pages");
  }
  // One (purged) segment per shard at most stays behind.
  assert!(h.segments_in_use() <= crate::core::SHARDS);
  check_observations(&h, &caches);
  // Nothing is allocated or cached, and the forced purge released every
  // small page.
  let u = h.usage();
  assert_eq!(
    (u.pages_in_use, u.small_pages, u.small_bytes_out),
    (0, 0, 0),
    "{u:?}"
  );
}

/// Checks the heap's observations (Stage A diagnostics) against each other
/// and against the shadow maps, while no operation is running.
pub fn check_observations(h: &Heap<MockOs>, caches: &[ThreadCache]) {
  let m = h.maintenance_stats();
  assert!(m.failed_runs <= m.purged_runs, "{m:?}");
  // Every page reported purged was handed to `purge` (or later
  // decommitted with its segment, which `purged` counts too).
  assert!(m.purged_pages as usize * PAGE_SIZE <= h.os().purged.load(Ordering::Relaxed));
  assert!(m.hard_limit_slices <= m.emergency_slices, "{m:?}");
  assert!(
    m.emergency_slices <= m.inline_slices && m.inline_slices <= m.slices,
    "{m:?}"
  );
  // A sweep ends in a slice.
  assert!(
    m.force_passes
      + m.budget_passes
      + m.decay_passes
      + m.inline_budget_passes
      + m.inline_decay_passes
      <= m.slices,
    "{m:?}"
  );
  assert!(
    m.released_pages + m.stale_empty_candidates <= m.trim_pages_inspected,
    "{m:?}"
  );
  // One thread at a time: no free publishes a candidate while a sweep
  // runs, so reconciling finds nothing the candidates missed.
  assert_eq!(m.reconciled_pages, 0, "{m:?}");
  h.check_indexes();
  let s = h.search_stats();
  assert!(s.stale_hints <= s.candidates, "{s:?}");
  assert!(s.cursor_claims <= s.refills, "{s:?}");
  assert!(s.new_segments <= s.run_searches, "{s:?}");
  let u = h.usage();
  assert_eq!(u.dirty_pages, h.dirty_pages(), "{u:?}");
  assert_eq!(
    u.owned_segments + u.huge_segments,
    h.segments_in_use(),
    "{u:?}"
  );
  assert_eq!(
    u.pages_in_use + u.dirty_pages + u.clean_pages,
    u.owned_segments * (crate::core::PAGES_PER_SEGMENT - 1),
    "{u:?}"
  );
  for tc in caches {
    let c = h.cache_stats(tc);
    assert_eq!(c.flushes, c.flush_sizes.iter().sum::<u64>());
    // A flush carries 1 to 64 blocks.
    assert!(
      c.flushes <= c.flushed_blocks && c.flushed_blocks <= 64 * c.flushes,
      "{c:?}"
    );
    assert!(c.buffered_words <= c.buffered_blocks, "{c:?}");
    assert!(c.evictions <= c.flushes, "{c:?}");
    // At most one slot per word, in its own set, and pending masks that
    // name exactly the occupied slots of each class.
    Heap::<MockOs>::check_free_buffer(tc);
  }
}
