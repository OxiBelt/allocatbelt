//! The workers' allocatbelt hooks with allocatbelt as the global allocator:
//! each worker's cache prefers its own shard and holds no claimed or
//! buffered blocks after it parked. Not built under `--cfg loom`, which
//! leaves allocatbelt out.

#![cfg(not(loom))]

use std::time::{Duration, Instant};

use allocatbelt::Allocatbelt;
use allocatbelt_runtime::{Config, Resources, Runtime, ShutdownMode};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

fn runtime(workers: usize) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding: 64,
    capacity: Resources::ZERO,
  })
  .unwrap()
}

fn wait_idle(rt: &Runtime, workers: usize) {
  let deadline = Instant::now() + Duration::from_secs(30);
  while rt.snapshot().idle_workers < workers {
    assert!(Instant::now() < deadline, "workers did not park");
    std::thread::yield_now();
  }
}

#[test]
fn each_worker_prefers_its_own_shard() {
  let mut rt = runtime(3);
  let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
  let jobs: Vec<_> = (0..3)
    .map(|_| {
      let b = std::sync::Arc::clone(&barrier);
      rt.try_spawn(Resources::ZERO, move |_| {
        b.wait();
        Allocatbelt.thread_cache_stats().map(|s| s.shard)
      })
      .unwrap()
    })
    .collect();
  let mut shards: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
  shards.sort_unstable();
  assert_eq!(shards, [Some(0), Some(1), Some(2)]);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn a_parked_worker_returned_its_claimed_blocks() {
  let mut rt = runtime(1);
  // Small allocations leave claimed blocks in the worker's cache.
  let held = rt
    .try_spawn(Resources::ZERO, |_| {
      let v: Vec<Box<u64>> = (0..256).map(Box::new).collect();
      drop(v);
      let keep = Box::new(1u64);
      let s = Allocatbelt.thread_cache_stats().unwrap();
      drop(keep);
      s.claimed_blocks
    })
    .unwrap()
    .join()
    .unwrap();
  assert!(held > 0, "the job claimed no blocks");
  wait_idle(&rt, 1);
  // The worker flushed before parking and has not allocated since.
  let after = rt
    .try_spawn(Resources::ZERO, |_| {
      let s = Allocatbelt.thread_cache_stats().unwrap();
      (s.claimed_blocks, s.buffered_blocks)
    })
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(after, (0, 0));
  rt.shutdown(ShutdownMode::Drain).unwrap();
}
