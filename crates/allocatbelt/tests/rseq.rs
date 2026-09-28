//! Experimental `mm_cid` shard selection (feature `experimental-rseq`): the
//! policy resolves as documented, and many more threads than CPUs, all
//! picking shards by `mm_cid` while they migrate, keep every block intact.
//! A separate test binary, so that the policy changes nothing elsewhere.

#![cfg(feature = "experimental-rseq")]

use std::sync::Mutex;

use allocatbelt::{Allocatbelt, RseqPolicy};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

#[test]
fn oversubscribed_threads_share_shards_by_mm_cid() {
  let status = GLOBAL.rseq_status();
  eprintln!(
    "rseq: {status:?}, mm_cid of this thread {:?}",
    GLOBAL.mm_cid()
  );
  // Nothing is selected by default.
  assert_eq!(status.policy, RseqPolicy::Auto);
  assert!(!status.active);
  // `Require` fails, and changes nothing, exactly where `mm_cid` cannot be
  // read; `Prefer` then falls back to per-thread shards.
  match GLOBAL.set_rseq_policy(RseqPolicy::Require) {
    Ok(s) => assert!(s.active && s.available.is_ok() && s.policy == RseqPolicy::Require),
    Err(e) => {
      assert_eq!(status.available, Err(e));
      assert_eq!(GLOBAL.rseq_status(), status);
    }
  }
  let status = GLOBAL.set_rseq_policy(RseqPolicy::Prefer).unwrap();
  assert_eq!(status.active, status.available.is_ok());
  assert_eq!(GLOBAL.mm_cid().is_some(), status.available.is_ok());

  let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
  let threads = 8 * cpus.max(4);
  let shared = Mutex::new(Vec::<Vec<u64>>::new());
  let max_cid = std::sync::atomic::AtomicU32::new(0);
  std::thread::scope(|s| {
    for t in 0..threads {
      let (shared, max_cid) = (&shared, &max_cid);
      s.spawn(move || {
        let tag = t as u64;
        let mut mine: Vec<Vec<u64>> = Vec::new();
        for i in 0..3000usize {
          // Small blocks (cache refills pick the shard) and page runs.
          let len = if i % 64 == 0 { 20_000 } else { 1 + i % 60 };
          mine.push(vec![tag << 32 | i as u64; len]);
          if mine.len() == 32 {
            let theirs = {
              let mut sh = shared.lock().unwrap();
              sh.extend(mine.drain(..16));
              let n = sh.len().min(16);
              sh.drain(..n).collect::<Vec<_>>()
            };
            for v in theirs.iter().chain(&mine) {
              assert!(v.iter().all(|&x| x == v[0]), "a block was overwritten");
            }
            mine.clear();
            if i % 256 == 0 {
              // Off the CPU and back, probably with another `mm_cid`.
              std::thread::yield_now();
            }
          }
          if let Some(cid) = GLOBAL.mm_cid() {
            max_cid.fetch_max(cid, std::sync::atomic::Ordering::Relaxed);
          }
        }
      });
    }
  });
  for v in shared.into_inner().unwrap() {
    assert!(v.iter().all(|&x| x == v[0]));
  }
  // Dense: below the number of threads that ever used the process's
  // memory at once (these, the harness's and the main thread).
  let max_cid = max_cid.into_inner();
  eprintln!("{threads} threads on {cpus} CPUs: largest mm_cid seen {max_cid}");
  assert!((max_cid as usize) < threads + 8);
  assert!(!GLOBAL.set_rseq_policy(RseqPolicy::Disable).unwrap().active);
}
