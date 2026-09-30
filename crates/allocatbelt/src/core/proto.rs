//! The protocols on metadata words.
//!
//! The heap runs every transition that other threads can race with through
//! the functions here, so that loom (`--cfg loom`, see the `loom` tests
//! below) checks exactly the code the heap executes. Callers pass the words
//! involved; nothing here knows the metadata layout.
//!
//! Four protocols live here:
//!
//! * **Block bitmaps and page lists.** A small page has one bitmap bit per
//!   block (1 = free) and a counter of its free blocks. There are no
//!   summary bits above the bitmaps: the owning shard keeps, per size
//!   class, a list of its pages that may have free blocks, linked through
//!   the pages' metadata and changed only under the shard lock, and each
//!   page has a *listed* flag in its list word. Frees (any thread) set bits
//!   and then raise the counter without a lock; a free that then finds its
//!   page unlisted takes the owner's lock and lists it ([`needs_listing`]).
//!   The owner (under its lock) claims whole words, found by scanning the
//!   page's bitmap words ([`claim_word`]), and takes a page off its list
//!   only after clearing the flag and then finding the counter at zero
//!   ([`retire_page`]), so a racing free either shows in the counter or
//!   sees the flag clear and lists the page again. A listed page may have
//!   no free blocks left; a page with free blocks is never left unlisted
//!   once the frees that returned them are done.
//! * **Empty-page candidates.** A segment has an *empty* word with one bit
//!   per small page that may have become completely free. The free whose
//!   counter increment brings the page's free count to its capacity sets
//!   the bit ([`publish_if_empty`]); trimming, under the owner's lock,
//!   takes the whole word ([`take_candidates`]) and checks each page's
//!   counter before releasing it. The counter never exceeds the capacity
//!   and only the owner's claims lower it, so every fully free page was
//!   published by the increment that made it so, after any take that could
//!   have dropped its bit: a candidate may be stale, never lost.
//! * **Page runs.** A segment has a `pages` word (1 = claimed) and a
//!   `dirty` word (1 = free but not yet purged). Unlike the protocols
//!   above they are not lock-free: only a thread holding the lock of the
//!   shard that owns the segment changes them, and every change is a plain
//!   load and store under that lock, never a read-modify-write
//!   instruction. Allocation, in-place growth, frees of page runs, purges
//!   and trimming all take the lock; other threads read the words only as
//!   hints. A purge claims the dirty free pages like an allocation would
//!   and gives them back after the `madvise`, so no one can hand them out
//!   while their contents are being discarded; it holds the lock only for
//!   the claim and for the end, not while the purge is in flight.
//! * **Maintenance requests.** A word of work bits (1 = requested) that
//!   any thread posts to and the maintenance thread takes from. A poster
//!   first publishes the cause (e.g. adds to the dirty count) and wakes the
//!   thread only when it set the bit; the thread takes the bit *before* it
//!   reads the cause, so a post that races with a take is either seen by
//!   the pass that follows or re-posts the bit (and wakes the thread).

use crate::core::bits::find_run_aligned;
use crate::core::sync::Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst};
use crate::core::sync::{AtomicU32, AtomicU64, fence};

/// Set in a small page's list word while the page is on its shard's list
/// of pages of its class that may have free blocks. The rest of the word
/// links the list; the whole word changes only under the owning shard's
/// lock, and other threads read only this flag.
pub(crate) const LISTED: u64 = 1 << 63;

/// Returns the blocks in `mask` to bitmap `word` of a page whose free-block
/// counter is `count`. Returns the free count this free raised the counter
/// to, or `None`, having changed only `word`, if a bit of `mask` was already
/// free: a double free. The caller then asks [`needs_listing`] whether the
/// page must go back on its shard's list.
pub(crate) fn release_blocks(word: &AtomicU64, count: &AtomicU64, mask: u64) -> Option<u64> {
  let old = word.fetch_or(mask, AcqRel);
  if old & mask != 0 {
    return None;
  }
  // Bits first, then the counter: the counter never overstates the set
  // bits once the owner's claims are subtracted.
  let n = u64::from(mask.count_ones());
  Some(count.fetch_add(n, Release).wrapping_add(n))
}

/// Whether a page that a free just returned blocks to (with
/// [`release_blocks`]) is off its shard's list, as its list word `link`
/// shows. The freer then takes the owner's lock and lists the page if it is
/// still an unlisted small page of the class.
pub(crate) fn needs_listing(link: &AtomicU64) -> bool {
  // Pairs with the fence in `retire_page` (a store-buffering pattern):
  // either the owner's read of the counter after its fence sees this
  // free's increment, or this read sees the flag the owner cleared.
  fence(SeqCst);
  link.load(Relaxed) & LISTED == 0
}

/// Publishes a page as an empty-page candidate in its segment's `empty`
/// word if `now`, the free count a [`release_blocks`] just returned, is
/// the page's capacity `cap`: that free may have returned the page's last
/// block. A claim racing the free can make the candidate stale.
pub(crate) fn publish_if_empty(empty: &AtomicU64, page_bit: u64, now: u64, cap: u64) {
  if now == cap {
    // Release: whoever takes the bit reads the counter at least at `now`.
    empty.fetch_or(page_bit, Release);
  }
}

/// Whether a small page of `cap` blocks whose free-block counter is `count`
/// has every block free, for the owner to decide under its lock whether to
/// release it. The counter is read as signed: it drops below zero while the
/// owner holds blocks it claimed from frees that set their bits but have
/// not counted them yet, and such a page has live (claimed) blocks.
pub(crate) fn all_free(count: &AtomicU64, cap: u64) -> bool {
  count.load(Acquire).cast_signed() >= cap.cast_signed()
}

/// Takes a segment's empty-page candidates, for the owner to check under
/// its lock. A free that publishes after the take sets its bit again.
pub(crate) fn take_candidates(empty: &AtomicU64) -> u64 {
  empty.swap(0, AcqRel)
}

/// Claims every free block of one bitmap word of a page, choosing among its
/// non-zero `words` by rank: the non-zero words are counted, and `r`, read
/// as a fraction of 2^32, picks the rank among them (`r = 0` takes the
/// first). Returns the word index and the claimed bits, or `None` if every
/// word is zero. There is no summary of the words: they are read one by
/// one. The caller subtracts the claimed count from the page's counter.
/// Only the page's owner may call this (claims must not race each other).
pub(crate) fn claim_word(words: &[AtomicU64], r: u32) -> Option<(u32, u64)> {
  // Frees only set bits and only the owner clears them, so a word read as
  // non-zero stays so until it is taken here: the rank is always found.
  let k = words.iter().filter(|w| w.load(Relaxed) != 0).count() as u64;
  if k == 0 {
    return None;
  }
  let rank = (u64::from(r) * k) >> 32;
  let mut seen = 0;
  for (w, word) in words.iter().enumerate() {
    if word.load(Relaxed) == 0 {
      continue;
    }
    if seen == rank {
      let bits = word.swap(0, AcqRel);
      debug_assert_ne!(bits, 0, "a non-zero word lost its bits");
      return Some((w as u32, bits));
    }
    seen += 1;
  }
  None
}

/// Prepares to take a page whose claims found no free block off its
/// shard's list: clears the listed flag in its list word `link`, then reads
/// its free-block counter `count`. Returns `true` if the page may be
/// unlinked (a free that has not raised the counter yet will find the flag
/// clear and list the page again), or `false`, having set the flag again,
/// if a free raised the counter meanwhile, in which case the caller should
/// claim from the page again. Only the page's owner, under its lock, may
/// call this, and the page must be listed.
pub(crate) fn retire_page(link: &AtomicU64, count: &AtomicU64) -> bool {
  let l = link.load(Relaxed);
  link.store(l & !LISTED, Relaxed);
  // Pairs with the fence in `needs_listing`.
  fence(SeqCst);
  // Acquire: a counter raised by a free shows its bits to the claims that
  // follow. The counter never overstates the set bits (the owner's own
  // claims are subtracted under its lock), so a positive count means free
  // blocks. It is below zero while the owner has claimed bits whose frees
  // have not counted them yet; those frees find the flag clear.
  if count.load(Acquire).cast_signed() <= 0 {
    return true;
  }
  link.store(l, Relaxed);
  false
}

/// Claims a run of `n` free pages starting at a multiple of `step` in a
/// segment's `pages` word. Returns the first page and which of the claimed
/// pages were dirty (their dirty mark is cleared: reused memory needs no
/// purge). Caller holds the lock of the shard that owns the segment.
pub(crate) fn claim_run(
  pages: &AtomicU64,
  dirty: &AtomicU64,
  n: u32,
  step: u32,
) -> Option<(u32, u64)> {
  let used = pages.load(Relaxed);
  let start = find_run_aligned(!used, n, step)?;
  let mask = crate::core::bits::run_mask(start, n);
  pages.store(used | mask, Relaxed);
  Some((start, take_marks(dirty, mask)))
}

/// Claims the pages of `mask`, which must all be free, and reports which
/// were dirty. Fails without changing anything if one of them is taken.
/// Caller holds the lock of the shard that owns the segment.
pub(crate) fn claim_exact(pages: &AtomicU64, dirty: &AtomicU64, mask: u64) -> Option<u64> {
  let used = pages.load(Relaxed);
  if used & mask != 0 {
    return None;
  }
  pages.store(used | mask, Relaxed);
  Some(take_marks(dirty, mask))
}

/// Frees the claimed pages of `mask` and marks them dirty. Caller holds the
/// lock of the shard that owns the segment.
pub(crate) fn release_run(pages: &AtomicU64, dirty: &AtomicU64, mask: u64) {
  dirty.store(dirty.load(Relaxed) | mask, Relaxed);
  pages.store(pages.load(Relaxed) & !mask, Relaxed);
}

/// Claims the dirty free pages among `eligible` so their memory can be
/// discarded. Returns the claimed mask (possibly empty). Caller holds the
/// lock of the shard that owns the segment.
pub(crate) fn claim_dirty(pages: &AtomicU64, dirty: &AtomicU64, eligible: u64) -> u64 {
  let used = pages.load(Relaxed);
  let d = dirty.load(Relaxed) & !used & eligible;
  if d != 0 {
    pages.store(used | d, Relaxed);
  }
  d
}

/// Ends a purge of the `claimed` pages: those in `purged` (now zero) lose
/// their dirty mark, and all of them become free again. Returns the dirty
/// marks actually cleared. Caller holds the lock of the shard that owns
/// the segment.
pub(crate) fn finish_purge(pages: &AtomicU64, dirty: &AtomicU64, claimed: u64, purged: u64) -> u64 {
  let cleared = take_marks(dirty, purged);
  pages.store(pages.load(Relaxed) & !claimed, Relaxed);
  cleared
}

/// Clears the marks of `mask` in `marks` and returns those that were set.
/// Caller holds the lock that guards `marks`.
fn take_marks(marks: &AtomicU64, mask: u64) -> u64 {
  let old = marks.load(Relaxed);
  marks.store(old & !mask, Relaxed);
  old & mask
}

/// Posts work `bit` to `work` after the caller published its cause.
/// Returns whether the bit was newly set: then the caller wakes the
/// maintenance thread. While the bit is already set, a post is one load.
pub(crate) fn post_work(work: &AtomicU32, bit: u32) -> bool {
  // Pairs with the fence in `take_work` (a store-buffering pattern):
  // either this load sees the bit taken, and the post sets it again, or
  // the taker's reads after its fence see the cause published before
  // this one.
  fence(SeqCst);
  work.load(Relaxed) & bit == 0 && work.fetch_or(bit, Release) & bit == 0
}

/// Takes work `bit` off `work` before the caller runs it; the caller reads
/// the cause afterwards. A post that lands meanwhile sets the bit again.
pub(crate) fn take_work(work: &AtomicU32, bit: u32) {
  work.fetch_and(!bit, Acquire);
  fence(SeqCst);
}

/// The value of `work` the maintenance thread may sleep on: the word, if
/// every bit set in it is `deferred` work (none, or a budget request held
/// back after a stalled cycle), else `None`. Sleeping on the value read,
/// rather than on 0, keeps a deferred bit from waking the thread at once,
/// while any new bit changes the word, so the `FUTEX_WAIT` returns or the
/// poster's `FUTEX_WAKE` wakes it (`post_work` wakes on every new bit).
pub(crate) fn idle_word(work: &AtomicU32, deferred: u32) -> Option<u32> {
  let w = work.load(Acquire);
  (w & !deferred == 0).then_some(w)
}

#[cfg(all(test, loom))]
mod loom_tests {
  //! Exhaustive interleaving checks of the protocols above. Run with
  //! `RUSTFLAGS="--cfg loom" cargo test -p allocatbelt-core-check --release --lib loom`.

  use loom::sync::atomic::Ordering::{Acquire, Relaxed};
  use loom::sync::atomic::{AtomicU32, AtomicU64};
  use loom::sync::{Arc, Mutex};
  use loom::thread;
  use std::vec::Vec;

  use super::*;
  use crate::core::lock::{Lock, Park};

  struct Page {
    words: [AtomicU64; 2],
    count: AtomicU64,
    link: AtomicU64,
    /// The owner's shard lock, guarding whether the page is on its list.
    list: Mutex<bool>,
    /// The segment's empty-page candidates (this page is bit 0).
    empty: AtomicU64,
    /// Blocks of the page.
    cap: u64,
  }

  impl Page {
    /// A page of `cap` blocks whose free blocks are `words`, listed if it
    /// has any.
    fn new(words: [u64; 2], cap: u64) -> Self {
      let listed = words != [0, 0];
      Self {
        words: [AtomicU64::new(words[0]), AtomicU64::new(words[1])],
        count: AtomicU64::new(u64::from(words[0].count_ones() + words[1].count_ones())),
        link: AtomicU64::new(if listed { LISTED } else { 0 }),
        list: Mutex::new(listed),
        empty: AtomicU64::new(0),
        cap,
      }
    }

    /// A free, as `Heap::free_bits` makes it.
    fn free(&self, w: u32, mask: u64) -> bool {
      let Some(now) = release_blocks(&self.words[w as usize], &self.count, mask) else {
        return false;
      };
      publish_if_empty(&self.empty, 1, now, self.cap);
      if needs_listing(&self.link) {
        // As `Heap::relist_page`: under the owner's lock, list the page
        // unless it is listed by now.
        let mut on = self.list.lock().unwrap();
        if self.link.load(Relaxed) & LISTED == 0 {
          self.link.store(LISTED, Relaxed);
          *on = true;
        }
      }
      true
    }

    /// Trimming, under the owner's lock: takes the candidate and checks
    /// the counter, as `release_empty_pages` does. Returns whether the
    /// page would be released.
    fn trim(&self) -> bool {
      take_candidates(&self.empty) != 0 && all_free(&self.count, self.cap)
    }

    /// The owner's refill loop, as `Heap::claim_class_word` runs it on a
    /// listed page: claim words until the page is empty and taken off the
    /// list. Returns the claimed bits per word.
    fn drain(&self, r: u32) -> [u64; 2] {
      let mut got = [0; 2];
      let mut on = self.list.lock().unwrap();
      if !*on {
        return got;
      }
      loop {
        while let Some((w, b)) = claim_word(&self.words, r) {
          assert_eq!(got[w as usize] & b, 0, "block claimed twice");
          got[w as usize] |= b;
          self.count.fetch_sub(u64::from(b.count_ones()), Relaxed);
        }
        if retire_page(&self.link, &self.count) {
          self.link.store(0, Relaxed);
          *on = false;
          return got;
        }
      }
    }

    /// No free block may be unreachable: a page with a non-empty word is
    /// on the list, and the flag says so.
    fn check_reachable(&self) {
      let on = *self.list.lock().unwrap();
      assert_eq!(
        on,
        self.link.load(Relaxed) & LISTED != 0,
        "the flag and the list disagree"
      );
      if self.words.iter().any(|w| w.load(Acquire) != 0) {
        assert!(on, "page with free blocks not listed");
      }
    }
  }

  #[test]
  fn free_races_claim() {
    loom::model(|| {
      let page = Arc::new(Page::new([0b0001, 0], 3));
      let p = page.clone();
      let freer = thread::spawn(move || {
        assert!(p.free(0, 0b0010));
        assert!(p.free(1, 0b0100));
      });
      let got = page.drain(0);
      freer.join().unwrap();
      page.check_reachable();
      // Every block is either claimed or still free, never both.
      for (got, word) in got.iter().zip(&page.words) {
        assert_eq!(got & word.load(Relaxed), 0);
      }
      let all = [
        got[0] | page.words[0].load(Relaxed),
        got[1] | page.words[1].load(Relaxed),
      ];
      assert_eq!(all, [0b0011, 0b0100]);
      let claimed = u64::from(got[0].count_ones() + got[1].count_ones());
      assert_eq!(page.count.load(Relaxed), 3 - claimed);
    });
  }

  /// The owner claims a page's last free block and takes the page off its
  /// list while another block of it is freed: the free either shows in the
  /// counter, keeping the page listed, or lists it again.
  #[test]
  fn a_free_racing_retirement_relists_the_page() {
    loom::model(|| {
      // Block 0 free, block 1 live.
      let page = Arc::new(Page::new([0b01, 0], 2));
      let p = page.clone();
      let freer = thread::spawn(move || assert!(p.free(0, 0b10)));
      let got = page.drain(0);
      freer.join().unwrap();
      page.check_reachable();
      assert_eq!(got[0] | page.words[0].load(Relaxed), 0b11);
    });
  }

  #[test]
  fn two_freers_one_word() {
    loom::model(|| {
      let page = Arc::new(Page::new([0, 0], 2));
      let handles: Vec<_> = [0b01u64, 0b10]
        .into_iter()
        .map(|m| {
          let p = page.clone();
          thread::spawn(move || assert!(p.free(0, m)))
        })
        .collect();
      let got = page.drain(1);
      for h in handles {
        h.join().unwrap();
      }
      page.check_reachable();
      assert_eq!(got[0] | page.words[0].load(Relaxed), 0b11);
    });
  }

  #[test]
  fn full_counter_means_every_block_is_free() {
    loom::model(|| {
      // Two blocks: block 0 free, block 1 live and about to be freed.
      let page = Arc::new(Page::new([0b01, 0], 2));
      let p = page.clone();
      let freer = thread::spawn(move || assert!(p.free(0, 0b10)));
      // The owner claims what it can and hands it back, as a thread cache
      // does, then decides whether the page is empty (and releasable) from
      // the counter, as `release_empty_pages` does.
      if let Some((w, b)) = claim_word(&page.words, 0) {
        page.count.fetch_sub(u64::from(b.count_ones()), Relaxed);
        assert!(page.free(w, b));
      }
      if page.count.load(Acquire) >= 2 {
        assert_eq!(
          page.words[0].load(Relaxed),
          0b11,
          "the counter overstated the free blocks"
        );
      }
      freer.join().unwrap();
    });
  }

  /// The frees of a page's last two blocks race trimming: if the trim
  /// did not see the page empty, the candidate is still published.
  #[test]
  fn last_free_publishes_a_candidate() {
    loom::model(|| {
      let page = Arc::new(Page::new([0, 0], 2));
      let handles: Vec<_> = [0b01u64, 0b10]
        .into_iter()
        .map(|m| {
          let p = page.clone();
          thread::spawn(move || assert!(p.free(0, m)))
        })
        .collect();
      let released = page.trim();
      for h in handles {
        h.join().unwrap();
      }
      assert_eq!(page.count.load(Relaxed), 2);
      assert!(
        released || page.empty.load(Relaxed) == 1,
        "a fully free page is neither released nor a candidate"
      );
      if released {
        assert_eq!(page.words[0].load(Relaxed), 0b11);
      }
    });
  }

  /// The owner claims a word while the page's last live block is freed, so
  /// the free may publish a stale candidate; the owner hands the word back
  /// (a cache return) and trims. The candidate for the page, now fully
  /// free, is not lost.
  #[test]
  fn a_claim_racing_the_last_free_loses_no_candidate() {
    loom::model(|| {
      // Block 0 free, block 1 live.
      let page = Arc::new(Page::new([0b01, 0], 2));
      let p = page.clone();
      let freer = thread::spawn(move || assert!(p.free(0, 0b10)));
      if let Some((w, b)) = claim_word(&page.words, 0) {
        page.count.fetch_sub(u64::from(b.count_ones()), Relaxed);
        assert!(page.free(w, b));
      }
      let released = page.trim();
      freer.join().unwrap();
      assert_eq!(page.count.load(Relaxed), 2);
      assert!(
        released || page.empty.load(Relaxed) == 1,
        "a fully free page is neither released nor a candidate"
      );
    });
  }

  /// The owner claims a word holding a block whose free has set its bit
  /// but not counted it yet, which takes the counter below zero, and then
  /// trimming looks at the page: the owner holds blocks of it, so the page
  /// is not taken for fully free.
  #[test]
  fn a_claim_ahead_of_a_free_keeps_the_page() {
    loom::model(|| {
      // Block 0 free, block 1 live and about to be freed.
      let page = Arc::new(Page::new([0b01, 0], 2));
      let p = page.clone();
      let freer = thread::spawn(move || assert!(p.free(0, 0b10)));
      let (_, b) = claim_word(&page.words, 0).unwrap();
      page.count.fetch_sub(u64::from(b.count_ones()), Relaxed);
      assert!(
        !all_free(&page.count, page.cap),
        "a page with claimed blocks looked fully free"
      );
      freer.join().unwrap();
    });
  }

  #[test]
  fn racing_double_free_is_caught() {
    loom::model(|| {
      let page = Arc::new(Page::new([0, 0], 1));
      let p = page.clone();
      let t = thread::spawn(move || p.free(0, 0b1));
      let mine = page.free(0, 0b1);
      let theirs = t.join().unwrap();
      assert!(
        mine ^ theirs,
        "exactly one of two frees of a block succeeds"
      );
      page.check_reachable();
    });
  }

  /// A segment's page-run words and the lock of the shard that owns it,
  /// which every change to them takes.
  struct Runs {
    lock: Lock,
    futex: Futex,
    pages: AtomicU64,
    dirty: AtomicU64,
  }

  impl Runs {
    fn new(pages: u64, dirty: u64) -> Arc<Self> {
      Arc::new(Self {
        lock: Lock::new(),
        futex: Futex::default(),
        pages: AtomicU64::new(pages),
        dirty: AtomicU64::new(dirty),
      })
    }

    /// Runs `f` on the words under the owner's lock.
    fn locked<R>(&self, f: impl FnOnce(&AtomicU64, &AtomicU64) -> R) -> R {
      let _g = self.lock.lock(&self.futex);
      f(&self.pages, &self.dirty)
    }
  }

  #[test]
  fn page_runs_race_purge() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
      // Pages 0 and 1 are live; page 2 is free and dirty; the rest of
      // the segment is taken.
      let runs = Runs::new(!0b100, 0b100);
      let r1 = runs.clone();
      let releaser = thread::spawn(move || r1.locked(|p, d| release_run(p, d, 0b001)));
      let r2 = runs.clone();
      let purger = thread::spawn(move || {
        let c = r2.locked(|p, d| claim_dirty(p, d, u64::MAX));
        // Nothing that is live may be purged.
        assert_eq!(c & 0b010, 0);
        r2.locked(|p, d| finish_purge(p, d, c, c));
        c
      });
      let claimed = runs.locked(|p, d| claim_run(p, d, 1, 1));
      releaser.join().unwrap();
      let purged = purger.join().unwrap();
      let (used, d) = runs.locked(|p, d| (p.load(Relaxed), d.load(Relaxed)));
      // The live page and the claimed page are held; page 0 was freed.
      let mine = claimed.map_or(0, |(start, _)| 1u64 << start);
      assert!(
        mine == 0 || mine == 0b001 || mine == 0b100,
        "claimed a taken page"
      );
      assert_eq!(used, !0b101 | mine);
      // No held page is marked dirty at rest.
      assert_eq!(d & used, 0, "held page left dirty");
      // A page is clean only if it was purged or never dirtied.
      let clean_free = !used & !d & 0b101;
      assert_eq!(
        clean_free & !purged,
        0,
        "a freed page lost its dirty mark without a purge"
      );
    });
  }

  /// A purge whose completion comes later, as with io_uring, and fails for
  /// one page: while the purge is in flight (outside the lock) an allocator
  /// claims pages and a thread frees one; no claimed page may be handed
  /// out before the purge ends, and the failed page keeps its dirty mark.
  #[test]
  fn async_purge_with_failure() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
      // Page 0 is live, page 1 free and clean, pages 2 and 3 free and
      // dirty; the rest of the segment is taken.
      let runs = Runs::new(!0b1110, 0b1100);
      let in_flight = Arc::new(AtomicU64::new(0));
      let r1 = runs.clone();
      let freer = thread::spawn(move || r1.locked(|p, d| release_run(p, d, 0b0001)));
      let (r2, f2) = (runs.clone(), in_flight.clone());
      let purger = thread::spawn(move || {
        let c = r2.locked(|p, d| {
          let c = claim_dirty(p, d, u64::MAX);
          f2.store(c, Relaxed);
          c
        });
        // Submitted; the completion arrives later. Page 3 fails.
        thread::yield_now();
        let purged = c & 0b0100;
        r2.locked(|p, d| {
          f2.store(0, Relaxed);
          finish_purge(p, d, c, purged)
        });
        (c, purged)
      });
      let mut mine = 0;
      for _ in 0..2 {
        runs.locked(|p, d| {
          if let Some((start, _)) = claim_run(p, d, 1, 1) {
            let bit = 1u64 << start;
            assert_eq!(
              in_flight.load(Relaxed) & bit,
              0,
              "handed out a page in flight"
            );
            mine |= bit;
          }
        });
      }
      freer.join().unwrap();
      let (claimed, purged) = purger.join().unwrap();
      let (used, d) = runs.locked(|p, d| (p.load(Relaxed), d.load(Relaxed)));
      assert_eq!(mine & !0b1111, 0, "claimed a taken page");
      assert_eq!(used, !0b1111 | mine);
      assert_eq!(d & used, 0, "held page left dirty");
      // A failed page the allocator did not take is still dirty.
      if claimed & 0b1000 != 0 && mine & 0b1000 == 0 {
        assert_ne!(d & 0b1000, 0, "a failed purge lost the dirty mark");
      }
      // A page is clean only if it was purged or never dirtied.
      assert_eq!(!used & !d & 0b1101 & !purged, 0);
    });
  }

  #[test]
  fn grow_races_trim() {
    loom::model(|| {
      // Page 0 is live; a trimmer claims the whole segment only if it
      // is empty, as `trim_step` does, and a grower extends page 0 into
      // page 1.
      let runs = Runs::new(0b01, 0);
      let r = runs.clone();
      let trimmer = thread::spawn(move || {
        r.locked(|p, _| {
          let empty = p.load(Relaxed) == 0;
          if empty {
            p.store(u64::MAX, Relaxed);
          }
          empty
        })
      });
      let grown = runs.locked(|p, d| claim_exact(p, d, 0b10)).is_some();
      assert!(
        !trimmer.join().unwrap(),
        "trimmed a segment with a live page"
      );
      assert!(grown);
    });
  }

  /// A futex for loom: a mutex-protected wait queue. `wait` checks the
  /// word and blocks under the same mutex that `wake` takes, which is the
  /// atomicity `FUTEX_WAIT`/`FUTEX_WAKE` guarantee, so a lost wake-up shows
  /// up as a deadlock that loom reports.
  #[derive(Default)]
  struct Futex {
    queue: loom::sync::Mutex<()>,
    cond: loom::sync::Condvar,
  }

  impl Park for Futex {
    fn wait(&self, word: &AtomicU32, expected: u32) {
      let g = self.queue.lock().unwrap();
      if word.load(Relaxed) == expected {
        drop(self.cond.wait(g).unwrap());
      }
    }
    fn wake(&self, word: &AtomicU32) {
      let _ = word;
      let _g = self.queue.lock().unwrap();
      self.cond.notify_one();
    }
  }

  /// `threads` threads each take the lock `rounds` times around a
  /// non-atomic read-modify-write; the lock must exclude them and no thread
  /// may stay parked.
  fn lock_model(threads: usize, rounds: usize, preemption_bound: Option<usize>) {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = preemption_bound;
    model.check(move || {
      let lock = Arc::new(Lock::new());
      let futex = Arc::new(Futex::default());
      let data = Arc::new(AtomicU64::new(0));
      let handles: Vec<_> = (0..threads)
        .map(|_| {
          let (lock, futex, data) = (lock.clone(), futex.clone(), data.clone());
          thread::spawn(move || {
            for _ in 0..rounds {
              let _g = lock.lock(&*futex);
              // A non-atomic read-modify-write, made safe by the lock.
              let v = data.load(Relaxed);
              data.store(v + 1, Relaxed);
            }
          })
        })
        .collect();
      for h in handles {
        h.join().unwrap();
      }
      assert_eq!(data.load(Relaxed), (threads * rounds) as u64);
    });
  }

  #[test]
  fn lock_excludes() {
    lock_model(2, 1, None);
  }

  /// Re-locking after a release exercises taking the lock as CONTENDED
  /// while the other thread is parked or about to park.
  #[test]
  fn lock_wakes_parked_threads() {
    lock_model(2, 2, None);
  }

  /// Two threads parked at once: each unlock must pass the wake-up on.
  /// Exhaustive search takes more than ten minutes here, so preemptions
  /// are bounded (loom's recommended way to cut the search).
  #[test]
  fn lock_three_threads() {
    lock_model(3, 1, Some(3));
  }

  /// `try_lock` excludes like `lock`, and a failed `try_lock` leaves the
  /// holder's lock alone: two threads `lock` while a third `try_lock`s,
  /// and every entry into the critical section must be counted once.
  #[test]
  fn try_lock_and_lock() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
      let lock = Arc::new(Lock::new());
      let futex = Arc::new(Futex::default());
      let data = Arc::new(AtomicU64::new(0));
      let handles: Vec<_> = (0..2)
        .map(|_| {
          let (l, f, d) = (lock.clone(), futex.clone(), data.clone());
          thread::spawn(move || {
            let _g = l.lock(&*f);
            let v = d.load(Relaxed);
            d.store(v + 1, Relaxed);
          })
        })
        .collect();
      let mut entered = 2;
      if let Some(_g) = lock.try_lock(&*futex) {
        let v = data.load(Relaxed);
        data.store(v + 1, Relaxed);
        entered += 1;
      }
      for h in handles {
        h.join().unwrap();
      }
      assert_eq!(data.load(Relaxed), entered);
    });
  }

  /// The fork handlers' pair: `acquire` in one call, `release` in another.
  #[test]
  fn acquire_release() {
    loom::model(|| {
      let lock = Arc::new(Lock::new());
      let futex = Arc::new(Futex::default());
      let (l, f) = (lock.clone(), futex.clone());
      let t = thread::spawn(move || drop(l.lock(&*f)));
      lock.acquire(&*futex);
      lock.release(&*futex);
      t.join().unwrap();
    });
  }

  /// Maintenance requests: two threads each publish one unit of work (as
  /// a free adds dirty pages) and post the same bit; the maintenance
  /// thread takes the bit, then collects the units, and sleeps while no
  /// bit is set. The sleep has no timeout here, so a lost request would
  /// leave it asleep forever, which loom reports as a deadlock. Three
  /// threads, so preemptions are bounded as in `lock_three_threads`.
  #[test]
  fn maintenance_requests_are_not_lost() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
      const BIT: u32 = 1 << 1;
      let work = Arc::new(AtomicU32::new(0));
      let units = Arc::new(AtomicU64::new(0));
      let futex = Arc::new(Futex::default());
      let posters: Vec<_> = (0..2)
        .map(|_| {
          let (work, units, futex) = (work.clone(), units.clone(), futex.clone());
          thread::spawn(move || {
            units.fetch_add(1, Relaxed);
            if post_work(&work, BIT) {
              futex.wake(&work);
            }
          })
        })
        .collect();
      let mut collected = 0;
      while collected < 2 {
        if work.load(Acquire) == 0 {
          futex.wait(&work, 0);
          continue;
        }
        take_work(&work, BIT);
        let n = units.load(Relaxed);
        units.fetch_sub(n, Relaxed);
        collected += n;
      }
      for p in posters {
        p.join().unwrap();
      }
    });
  }

  /// A budget request held back after a stalled cycle: the maintenance
  /// thread sleeps on the word with that bit set, a second budget post
  /// lands on the set bit (no wake-up), and a force request must still
  /// wake it. A lost wake-up would leave it asleep, which loom reports as
  /// a deadlock.
  #[test]
  fn deferred_budget_does_not_hide_a_force_request() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
      const FORCE: u32 = 1 << 0;
      const BUDGET: u32 = 1 << 1;
      let work = Arc::new(AtomicU32::new(BUDGET));
      let futex = Arc::new(Futex::default());
      let posters: Vec<_> = [BUDGET, FORCE]
        .into_iter()
        .map(|bit| {
          let (work, futex) = (work.clone(), futex.clone());
          thread::spawn(move || {
            if post_work(&work, bit) {
              futex.wake(&work);
            }
          })
        })
        .collect();
      loop {
        match idle_word(&work, BUDGET) {
          Some(w) => futex.wait(&work, w),
          None => {
            take_work(&work, FORCE);
            break;
          }
        }
      }
      // The deferred request is still recorded.
      assert_ne!(work.load(Relaxed) & BUDGET, 0);
      for p in posters {
        p.join().unwrap();
      }
    });
  }
}
