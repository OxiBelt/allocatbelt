//! Allocation workloads shared by the per-allocator benchmark binaries.
//!
//! Each binary installs a different `#[global_allocator]` and calls [`run`].
//! Workloads approximate a proxy's allocation pattern: many short-lived
//! small buffers, cross-thread hand-off (accept thread → worker, worker →
//! writer), and occasional large bodies.

use std::hint::black_box;
use std::sync::mpsc;
use std::time::Instant;

/// Deterministic xorshift so every allocator sees the same request stream.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }
  fn size(&mut self) -> usize {
    // Mostly small, with a tail of larger buffers (headers, bodies).
    match self.next() % 100 {
      0..=69 => 16 + (self.next() % 240) as usize,
      70..=94 => 256 + (self.next() % 3840) as usize,
      95..=98 => 4096 + (self.next() % 60_000) as usize,
      _ => 65_536 + (self.next() % 1_000_000) as usize,
    }
  }
}

fn churn(seed: u64, ops: usize, window: usize) -> usize {
  let mut rng = Rng(seed | 1);
  let mut live: Vec<Vec<u8>> = Vec::with_capacity(window);
  let mut touched = 0usize;
  for _ in 0..ops {
    let size = rng.size();
    let mut v = Vec::with_capacity(size);
    v.push(1u8);
    touched += v.capacity();
    if live.len() < window {
      live.push(v);
    } else {
      let i = (rng.next() as usize) % window;
      live[i] = v;
    }
  }
  black_box(&live);
  touched
}

/// Small objects only (16–256 B), the class-block fast path.
fn small_churn(seed: u64, ops: usize, window: usize) -> usize {
  let mut rng = Rng(seed | 1);
  let mut live: Vec<Box<[u8]>> = Vec::with_capacity(window);
  let mut n = 0usize;
  for _ in 0..ops {
    let b = vec![1u8; 16 + (rng.next() % 241) as usize].into_boxed_slice();
    n += b.len();
    if live.len() < window {
      live.push(b);
    } else {
      let i = (rng.next() as usize) % window;
      live[i] = b;
    }
  }
  black_box(&live);
  n
}

fn threads_small(threads: usize, ops: usize) {
  std::thread::scope(|s| {
    for t in 0..threads {
      s.spawn(move || black_box(small_churn(t as u64 * 7919 + 1, ops, 1000)));
    }
  });
}

fn threads_local(threads: usize, ops: usize) {
  std::thread::scope(|s| {
    for t in 0..threads {
      s.spawn(move || black_box(churn(t as u64 * 7919 + 1, ops, 1000)));
    }
  });
}

fn producer_consumer(pairs: usize, batches: usize) {
  std::thread::scope(|s| {
    for p in 0..pairs {
      let (tx, rx) = mpsc::sync_channel::<Vec<Vec<u8>>>(16);
      s.spawn(move || {
        let mut rng = Rng(p as u64 * 104_729 + 3);
        for _ in 0..batches {
          let batch = (0..64).map(|_| vec![0u8; rng.size() % 4096 + 1]).collect();
          if tx.send(batch).is_err() {
            break;
          }
        }
      });
      s.spawn(move || {
        let mut n = 0usize;
        for b in rx {
          n += b.len();
        }
        black_box(n)
      });
    }
  });
}

fn rss_kib(field: &str) -> u64 {
  std::fs::read_to_string("/proc/self/status")
    .ok()
    .and_then(|s| {
      s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
    })
    .unwrap_or(0)
}

fn time(label: &str, name: &str, f: impl FnOnce()) {
  let t = Instant::now();
  f();
  let ms = t.elapsed().as_secs_f64() * 1e3;
  println!(
    "{name}\t{label}\t{ms:.1} ms\tVmRSS {} KiB",
    rss_kib("VmRSS:")
  );
}

/// Runs every workload and prints one tab-separated line per result.
pub fn run(name: &str) {
  let threads = std::thread::available_parallelism()
    .map_or(4, |n| n.get())
    .min(16);
  time("single-thread churn 2M", name, || {
    black_box(churn(42, 2_000_000, 1000));
  });
  time(
    &format!("{threads}-thread local churn 1M each"),
    name,
    || threads_local(threads, 1_000_000),
  );
  time(
    &format!("{threads}-thread small churn 4M each"),
    name,
    || threads_small(threads, 4_000_000),
  );
  time(
    &format!("{} producer/consumer pairs 20k batches", threads / 2),
    name,
    || {
      producer_consumer(threads / 2, 20_000);
    },
  );
  println!(
    "{name}\tpeak\tVmHWM {} KiB\tVmRSS after {} KiB",
    rss_kib("VmHWM:"),
    rss_kib("VmRSS:")
  );
  // What a server keeps after a burst while it waits for the next one: no
  // allocator calls happen during the sleep.
  std::thread::sleep(std::time::Duration::from_secs(3));
  println!(
    "{name}\tidle\tVmRSS after 3 s idle {} KiB",
    rss_kib("VmRSS:")
  );
  // The local churn's work spread over four times as many threads as
  // CPUs, so lock holders get preempted and waiters must get out of the
  // way (docs/research/benchmarks.md, lock contention). Last, so that it
  // does not change the peak and idle figures above.
  time(
    &format!(
      "{}-thread local churn 250k each (oversubscribed)",
      4 * threads
    ),
    name,
    || threads_local(4 * threads, 250_000),
  );
}
