//! The lock-free protocols on metadata words.
//!
//! The heap runs every transition that other threads can race with through
//! the functions here, so that loom (`--cfg loom`, see the `loom` tests
//! below) checks exactly the code the heap executes. Callers pass the words
//! involved; nothing here knows the metadata layout.
//!
//! Two protocols live here:
//!
//! * **Block bitmaps.** A small page has one bitmap bit per block (1 =
//!   free), a *summary* word with one bit per bitmap word that may be
//!   non-zero, and the segment has an *avail* word per size class with one
//!   bit per page that may have free blocks. Frees (any thread) set bits
//!   bottom-up and propagate only on a zero → non-zero transition; the page's
//!   owner (under its shard lock) claims whole words top-down, clearing the
//!   hint *before* taking the bits, so a racing free either lands in the
//!   bits it takes or re-sets the hint afterwards. A hint may be stale-set,
//!   never stale-clear while bits are waiting.
//! * **Page runs.** A segment has a `pages` word (1 = claimed) and a
//!   `dirty` word (1 = free but not yet purged). Claims are compare-exchanges
//!   on `pages`; releases mark dirty before freeing; a purge claims the dirty
//!   free pages like an allocation would, so no one can hand them out while
//!   their contents are being discarded.

use crate::bits::{find_run_aligned, pick_bit};
use crate::sync::AtomicU64;
use crate::sync::Ordering::{AcqRel, Acquire, Release};

/// Returns the blocks in `mask` to bitmap `word` (index `w` in its page).
///
/// `count` is the page's free-block counter, `summary` its word summary and
/// `avail`/`page_bit` its bit in the segment's availability word for its
/// class. Returns `false`, having changed only `word`, if a bit of `mask`
/// was already free: a double free.
pub(crate) fn release_blocks(
  word: &AtomicU64,
  count: &AtomicU64,
  summary: &AtomicU64,
  avail: &AtomicU64,
  w: u32,
  page_bit: u64,
  mask: u64,
) -> bool {
  let old = word.fetch_or(mask, AcqRel);
  if old & mask != 0 {
    return false;
  }
  // Bits first, then the counter: the counter never overstates the set
  // bits once the owner's claims are subtracted.
  count.fetch_add(u64::from(mask.count_ones()), Release);
  if old == 0 && summary.fetch_or(1 << w, AcqRel) == 0 {
    avail.fetch_or(page_bit, AcqRel);
  }
  true
}

/// Claims every free block of one bitmap word of a page, choosing among the
/// words its `summary` marks by [`pick_bit`] with `r`. Returns the word index
/// and the claimed bits, or `None` once the summary is empty. The caller
/// subtracts the claimed count from the page's counter. Only the page's owner
/// may call this (claims must not race each other).
pub(crate) fn claim_word(summary: &AtomicU64, words: &[AtomicU64], r: u32) -> Option<(u32, u64)> {
  loop {
    let s = summary.load(Acquire);
    if s == 0 {
      return None;
    }
    let w = pick_bit(s, r);
    // Clear the hint before taking the bits: a free that lands after the
    // swap sees an empty word and sets the hint again.
    summary.fetch_and(!(1 << w), AcqRel);
    let Some(word) = words.get(w as usize) else {
      continue;
    };
    let bits = word.swap(0, AcqRel);
    if bits != 0 {
      return Some((w, bits));
    }
  }
}

/// Takes a page whose summary looked empty off its segment's availability
/// word. Returns `false`, leaving the bit set, if a free refilled the page
/// meanwhile, in which case the caller should claim from it again.
pub(crate) fn retire_page(avail: &AtomicU64, page_bit: u64, summary: &AtomicU64) -> bool {
  avail.fetch_and(!page_bit, AcqRel);
  // A read-modify-write rather than a load: it reads the latest summary,
  // and it synchronises with the free whose summary update follows it, so
  // that free's `avail` update is ordered after the clear above.
  if summary.fetch_or(0, AcqRel) == 0 {
    return true;
  }
  avail.fetch_or(page_bit, AcqRel);
  false
}

/// Atomically claims a run of `n` free pages starting at a multiple of
/// `step` in a segment's `pages` word, never touching pages in `reserved`.
/// Returns the first page and which of the claimed pages were dirty (their
/// dirty mark is cleared: reused memory needs no purge).
pub(crate) fn claim_run(
  pages: &AtomicU64,
  dirty: &AtomicU64,
  n: u32,
  step: u32,
) -> Option<(u32, u64)> {
  let mut used = pages.load(Acquire);
  loop {
    let start = find_run_aligned(!used, n, step)?;
    let mask = crate::bits::run_mask(start, n);
    match pages.compare_exchange_weak(used, used | mask, AcqRel, Acquire) {
      Ok(_) => return Some((start, dirty.fetch_and(!mask, AcqRel) & mask)),
      Err(now) => used = now,
    }
  }
}

/// Claims the pages of `mask`, which must all be free, and reports which
/// were dirty. Fails without changing anything if one of them is taken.
pub(crate) fn claim_exact(pages: &AtomicU64, dirty: &AtomicU64, mask: u64) -> Option<u64> {
  let mut used = pages.load(Acquire);
  loop {
    if used & mask != 0 {
      return None;
    }
    match pages.compare_exchange_weak(used, used | mask, AcqRel, Acquire) {
      Ok(_) => return Some(dirty.fetch_and(!mask, AcqRel) & mask),
      Err(now) => used = now,
    }
  }
}

/// Frees the claimed pages of `mask`, marking them dirty first so that a
/// claimer that grabs them clears the mark.
pub(crate) fn release_run(pages: &AtomicU64, dirty: &AtomicU64, mask: u64) {
  dirty.fetch_or(mask, Release);
  pages.fetch_and(!mask, Release);
}

/// Claims the dirty free pages among `eligible` so their memory can be
/// discarded. Returns the claimed mask (possibly empty).
pub(crate) fn claim_dirty(pages: &AtomicU64, dirty: &AtomicU64, eligible: u64) -> u64 {
  let mut used = pages.load(Acquire);
  loop {
    let d = dirty.load(Acquire) & !used & eligible;
    if d == 0 {
      return 0;
    }
    match pages.compare_exchange_weak(used, used | d, AcqRel, Acquire) {
      Ok(_) => return d,
      Err(now) => used = now,
    }
  }
}

/// Ends a purge of the `claimed` pages: those in `purged` (now zero) lose
/// their dirty mark, and all of them become free again. Returns the dirty
/// marks actually cleared.
pub(crate) fn finish_purge(pages: &AtomicU64, dirty: &AtomicU64, claimed: u64, purged: u64) -> u64 {
  let cleared = dirty.fetch_and(!purged, AcqRel) & purged;
  pages.fetch_and(!claimed, Release);
  cleared
}

#[cfg(all(test, loom))]
mod loom_tests {
  //! Exhaustive interleaving checks of the protocols above. Run with
  //! `RUSTFLAGS="--cfg loom" cargo test -p allocatbelt-core --release --lib loom`.

  use loom::sync::Arc;
  use loom::sync::atomic::Ordering::{Acquire, Relaxed};
  use loom::sync::atomic::{AtomicU32, AtomicU64};
  use loom::thread;
  use std::vec::Vec;

  use super::*;
  use crate::lock::{Lock, Park};

  struct Page {
    words: [AtomicU64; 2],
    count: AtomicU64,
    summary: AtomicU64,
    avail: AtomicU64,
  }

  impl Page {
    fn new(words: [u64; 2]) -> Self {
      let summary = u64::from(words[0] != 0) | u64::from(words[1] != 0) << 1;
      Self {
        words: [AtomicU64::new(words[0]), AtomicU64::new(words[1])],
        count: AtomicU64::new(u64::from(words[0].count_ones() + words[1].count_ones())),
        summary: AtomicU64::new(summary),
        avail: AtomicU64::new(u64::from(summary != 0)),
      }
    }

    fn free(&self, w: u32, mask: u64) -> bool {
      release_blocks(
        &self.words[w as usize],
        &self.count,
        &self.summary,
        &self.avail,
        w,
        1,
        mask,
      )
    }

    /// The owner's refill loop: claim words until the page is empty and
    /// retired. Returns the claimed bits per word.
    fn drain(&self, r: u32) -> [u64; 2] {
      let mut got = [0; 2];
      loop {
        while let Some((w, b)) = claim_word(&self.summary, &self.words, r) {
          assert_eq!(got[w as usize] & b, 0, "block claimed twice");
          got[w as usize] |= b;
          self.count.fetch_sub(u64::from(b.count_ones()), Relaxed);
        }
        if retire_page(&self.avail, 1, &self.summary) {
          return got;
        }
      }
    }

    /// No free block may be unreachable: a non-empty word is in the
    /// summary, and a non-empty summary is in the availability word.
    fn check_reachable(&self) {
      let s = self.summary.load(Acquire);
      for (w, word) in self.words.iter().enumerate() {
        if word.load(Acquire) != 0 {
          assert!(
            s >> w & 1 == 1,
            "free blocks in word {w} not in the summary"
          );
        }
      }
      if s != 0 {
        assert_eq!(
          self.avail.load(Acquire),
          1,
          "page with free blocks not available"
        );
      }
    }
  }

  #[test]
  fn free_races_claim() {
    loom::model(|| {
      let page = Arc::new(Page::new([0b0001, 0]));
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

  #[test]
  fn two_freers_one_word() {
    loom::model(|| {
      let page = Arc::new(Page::new([0, 0]));
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
      let page = Arc::new(Page::new([0b01, 0]));
      let p = page.clone();
      let freer = thread::spawn(move || assert!(p.free(0, 0b10)));
      // The owner claims what it can and hands it back, as a thread cache
      // does, then decides whether the page is empty (and releasable) from
      // the counter, as `release_empty_pages` does.
      if let Some((w, b)) = claim_word(&page.summary, &page.words, 0) {
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

  #[test]
  fn racing_double_free_is_caught() {
    loom::model(|| {
      let page = Arc::new(Page::new([0, 0]));
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

  #[test]
  fn page_runs_race_purge() {
    loom::model(|| {
      // Pages 0 and 1 are live; page 2 is free and dirty; the rest of
      // the segment is taken.
      let pages = Arc::new(AtomicU64::new(!0b100));
      let dirty = Arc::new(AtomicU64::new(0b100));
      let (p1, d1) = (pages.clone(), dirty.clone());
      let releaser = thread::spawn(move || release_run(&p1, &d1, 0b001));
      let (p2, d2) = (pages.clone(), dirty.clone());
      let purger = thread::spawn(move || {
        let c = claim_dirty(&p2, &d2, u64::MAX);
        // Nothing that is live may be purged.
        assert_eq!(c & 0b010, 0);
        finish_purge(&p2, &d2, c, c);
        c
      });
      let claimed = claim_run(&pages, &dirty, 1, 1);
      releaser.join().unwrap();
      let purged = purger.join().unwrap();
      let (used, d) = (pages.load(Relaxed), dirty.load(Relaxed));
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

  #[test]
  fn grow_races_trim() {
    loom::model(|| {
      // Page 0 is live; a trimmer claims the whole segment only if it
      // is empty, a grower extends page 0 into page 1.
      let pages = Arc::new(AtomicU64::new(0b01));
      let dirty = Arc::new(AtomicU64::new(0));
      let p = pages.clone();
      let trimmer = thread::spawn(move || p.compare_exchange(0, u64::MAX, AcqRel, Acquire).is_ok());
      let grown = claim_exact(&pages, &dirty, 0b10).is_some();
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
}
