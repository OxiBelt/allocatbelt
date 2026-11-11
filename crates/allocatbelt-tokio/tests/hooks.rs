//! The hooks on real multi-thread runtimes, with allocatbelt as the global
//! allocator.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use allocatbelt::{Allocatbelt, Region};
use allocatbelt_tokio::Hooks;
use tokio::runtime::Builder;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// Blocks a parking thread's cache holds right after the park hook ran,
/// summed over parks, and the parks seen.
#[derive(Default)]
struct Parks {
  parks: AtomicU64,
  held_after: AtomicU64,
}

fn held() -> u64 {
  Allocatbelt
    .thread_cache_stats()
    .map_or(0, |s| s.claimed_blocks + s.buffered_blocks)
}

/// Runs small-block work on a two-worker runtime whose park callback runs
/// `hooks` and then records what the cache still holds; returns the
/// record once the workers parked after the work.
fn park_after_work(hooks: Hooks) -> Arc<Parks> {
  let parks = Arc::new(Parks::default());
  let mut b = Builder::new_multi_thread();
  b.worker_threads(2);
  let (h, p) = (hooks.clone(), parks.clone());
  b.on_thread_start(move || h.thread_started());
  b.on_thread_park(move || {
    hooks.thread_parking();
    p.held_after.fetch_add(held(), Ordering::Relaxed);
    p.parks.fetch_add(1, Ordering::Relaxed);
  });
  let rt = b.build().unwrap();
  rt.block_on(async {
    let tasks: Vec<_> = (0..64)
      .map(|i| {
        tokio::spawn(async move {
          let mut keep = Vec::new();
          for j in 0..200 {
            keep.push(vec![i as u8; 16 + (j % 7) * 24]);
            if j % 3 == 0 {
              keep.swap_remove(0);
            }
            tokio::task::yield_now().await;
          }
          keep.len()
        })
      })
      .collect();
    for t in tasks {
      assert!(t.await.unwrap() > 0);
    }
  });
  // The workers park once the work is done: wait for parks after it.
  let base = parks.parks.load(Ordering::Relaxed);
  parks.held_after.store(0, Ordering::Relaxed);
  let deadline = Instant::now() + Duration::from_secs(10);
  // Wake both workers and let them park again.
  rt.block_on(async {
    let a = tokio::spawn(async { vec![0u8; 40].len() });
    let b = tokio::spawn(async { vec![0u8; 40].len() });
    assert_eq!(a.await.unwrap() + b.await.unwrap(), 80);
  });
  while parks.parks.load(Ordering::Relaxed) < base + 2 && Instant::now() < deadline {
    std::thread::sleep(Duration::from_millis(5));
  }
  assert!(
    parks.parks.load(Ordering::Relaxed) >= base + 2,
    "the workers did not park"
  );
  drop(rt);
  parks
}

#[test]
fn parking_workers_return_their_caches() {
  let parks = park_after_work(Hooks::new());
  assert_eq!(parks.held_after.load(Ordering::Relaxed), 0);
}

#[test]
fn without_the_park_hook_workers_keep_their_caches() {
  let parks = park_after_work(Hooks::new().flush_on_park(false));
  assert!(parks.held_after.load(Ordering::Relaxed) > 0);
}

#[test]
fn each_started_thread_takes_the_next_shard() {
  let hooks = Hooks::new().first_shard(62);
  let shards = Arc::new(Mutex::new(Vec::new()));
  let mut b = Builder::new_multi_thread();
  b.worker_threads(4);
  let (h, s) = (hooks.clone(), shards.clone());
  b.on_thread_start(move || {
    h.thread_started();
    let shard = Allocatbelt.thread_cache_stats().map(|c| c.shard);
    s.lock().unwrap().push(shard);
  });
  let rt = b.build().unwrap();
  rt.block_on(async { tokio::spawn(async {}).await.unwrap() });
  drop(rt);
  let mut got = shards.lock().unwrap().clone();
  got.sort_unstable();
  // 62, 63, then around to 0 and 1.
  assert_eq!(got, [Some(0), Some(1), Some(62), Some(63)]);
  assert_eq!(hooks.threads_started(), 4);
}

#[test]
fn installed_hooks_run_on_the_runtime() {
  let hooks = Hooks::new().first_shard(8);
  let mut b = Builder::new_multi_thread();
  b.worker_threads(3);
  hooks.clone().install(&mut b);
  let rt = b.build().unwrap();
  let shard = rt.block_on(async {
    tokio::spawn(async { Allocatbelt.thread_cache_stats().map(|c| c.shard) })
      .await
      .unwrap()
  });
  drop(rt);
  assert!(matches!(shard, Some(8..=10)), "{shard:?}");
  assert_eq!(hooks.threads_started(), 3);
}

/// A task owns a region across `.await`s and keeps pieces across them: the
/// future is `Send` (the region moves with it), so it runs on the
/// multi-thread runtime; only holding `&Region` itself across an await is
/// not `Send` (the `compile_fail` example in the crate docs).
#[test]
fn tasks_own_regions_across_awaits() {
  let rt = Builder::new_multi_thread()
    .worker_threads(4)
    .build()
    .unwrap();
  let sums = rt.block_on(async {
    let tasks: Vec<_> = (0..16u64)
      .map(|t| {
        tokio::spawn(async move {
          let mut region = Region::new();
          let mut total = 0;
          for request in 0..50u64 {
            let xs = region.alloc_slice_fill(100, t + request).unwrap();
            tokio::task::yield_now().await;
            xs[0] += 1;
            total += xs.iter().sum::<u64>();
            // The request is done: its pieces go at once.
            region.reset();
          }
          (total, region.stats())
        })
      })
      .collect();
    let mut out = Vec::new();
    for t in tasks {
      out.push(t.await.unwrap());
    }
    out
  });
  for (t, (total, stats)) in sums.into_iter().enumerate() {
    let t = t as u64;
    let expect: u64 = (0..50).map(|r| 100 * (t + r) + 1).sum();
    assert_eq!(total, expect);
    assert_eq!((stats.chunks, stats.resets), (1, 50));
  }
}
