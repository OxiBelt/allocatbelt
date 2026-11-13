//! Allocation workloads shared by the per-allocator benchmark binaries.
//!
//! Each binary installs a different `#[global_allocator]` and calls [`run`].
//! Workloads approximate a proxy's allocation pattern: many short-lived
//! small buffers, cross-thread hand-off (accept thread → worker, worker →
//! writer), and occasional large bodies.
//!
//! Every workload line also carries the CPU time, page faults and storage
//! bytes the process spent on it (`allocatbelt_profile::Usage`). Arguments,
//! for profiling one workload at a time (`scripts/profile.sh`):
//!
//! - `--quick`: a twentieth of the operations and a shorter idle wait, for
//!   smoke runs and slow tools such as callgrind. Not for timings.
//! - `--only KEY[,KEY...]`: run only these workloads, of `single`, `local`,
//!   `small`, `pairs`, `idle`, `oversubscribed`, `aligned`, `region`,
//!   `small1`, `aligned-mix`, `runs`, `runs4000` and `huge`.

use std::hint::black_box;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use allocatbelt_profile::Usage;

pub mod adaptive_feedback;
pub mod application;
pub mod runtime;
pub mod soak;

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

/// Buffers of 8 KiB to 64 KiB only, each one page run in allocatbelt, with
/// `window` of them live: frees leave single free pages among full ones.
fn run_churn(seed: u64, ops: usize, window: usize) -> usize {
  let mut rng = Rng(seed | 1);
  let mut live: Vec<Vec<u8>> = Vec::with_capacity(window);
  let mut touched = 0usize;
  for _ in 0..ops {
    let mut v = Vec::with_capacity(8193 + (rng.next() % 57_344) as usize);
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

#[repr(align(64))]
struct Aligned64([u8; 192]);

#[repr(align(256))]
struct Aligned256([u8; 768]);

/// Alignment-sensitive small allocations, with live payload checks.
fn aligned_churn(ops: usize) {
  let mut checksum = 0usize;
  for i in 0..ops {
    let a = Box::new(Aligned64([i as u8; 192]));
    let b = Box::new(Aligned256([i as u8; 768]));
    black_box(&a);
    black_box(&b);
    checksum = checksum.wrapping_add(usize::from(a.0[191]) + usize::from(b.0[767]));
  }
  black_box(checksum);
}

/// Element types of [`aligned_mix`]: as large as their alignment, and never
/// read, since only their layout matters.
macro_rules! aligned_types {
  ($($name:ident $align:literal),*) => {
    $(
      #[allow(dead_code, reason = "only the size and alignment are used")]
      #[repr(align($align))]
      struct $name([u8; $align]);
    )*
  };
}

aligned_types!(Align32 32, Align64 64, Align128 128, Align512 512, Align4096 4096);

/// A live buffer of [`aligned_mix`]: one to four elements of an aligned type.
enum AlignedBuf {
  A32(Vec<Align32>),
  A64(Vec<Align64>),
  A128(Vec<Align128>),
  A512(Vec<Align512>),
  A4096(Vec<Align4096>),
}

impl AlignedBuf {
  fn bytes(&self) -> usize {
    match self {
      Self::A32(v) => v.capacity() * size_of::<Align32>(),
      Self::A64(v) => v.capacity() * size_of::<Align64>(),
      Self::A128(v) => v.capacity() * size_of::<Align128>(),
      Self::A512(v) => v.capacity() * size_of::<Align512>(),
      Self::A4096(v) => v.capacity() * size_of::<Align4096>(),
    }
  }
}

/// Small allocations aligned to 32 to 4096 bytes (32 B to 8 KiB, every one
/// a small-class size), kept in a window of live buffers and freed in
/// random order. Only the capacity is requested: the row measures the
/// aligned allocation and its free, not the writes of a payload.
fn aligned_mix(seed: u64, ops: usize, window: usize) -> usize {
  let mut rng = Rng(seed | 1);
  let mut live: Vec<AlignedBuf> = Vec::with_capacity(window);
  let mut n = 0usize;
  for _ in 0..ops {
    let k = 1 + (rng.next() % 4) as usize;
    let b = match rng.next() % 8 {
      0 | 1 => AlignedBuf::A32(Vec::with_capacity(k)),
      2 | 3 => AlignedBuf::A64(Vec::with_capacity(k)),
      4 | 5 => AlignedBuf::A128(Vec::with_capacity(k)),
      6 => AlignedBuf::A512(Vec::with_capacity(k)),
      _ => AlignedBuf::A4096(Vec::with_capacity(k.min(2))),
    };
    n += b.bytes();
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

/// Sizes of the huge-block churn: above the longest page run (63 pages of
/// 64 KiB), so each takes whole segments, and below the dirty budget.
const HUGE_SIZES: [usize; 3] = [9 << 19, 8 << 20, 16 << 20];

/// Huge blocks allocated, written one byte per 4 KiB page, and freed, one
/// at a time: a buffer that a program grows to megabytes again and again.
/// The bytes are written into the spare capacity, without zero-filling the
/// block first, so the row measures the allocator and its page faults
/// rather than a memset. Every allocator has to fault the pages in once;
/// the row shows what a free costs the next allocation.
fn huge_churn(ops: usize) {
  for i in 0..ops {
    let size = HUGE_SIZES[i % HUGE_SIZES.len()];
    let mut v = Vec::<u8>::with_capacity(size);
    let spare = v.spare_capacity_mut();
    for p in (0..size).step_by(4096) {
      spare[p].write(i as u8);
    }
    black_box(&mut v);
  }
}

/// Bump hits, standard chunk changes, and reuse after reset. This explicit
/// Region uses allocatbelt even in the system/mimalloc comparison binaries.
fn region_churn(ops: usize) {
  let mut region = allocatbelt::Region::new();
  let mut checksum = 0u64;
  for i in 0..ops {
    let value = region.alloc_copy([i as u64; 8]).expect("region piece");
    checksum = checksum.wrapping_add(black_box(value)[7]);
    if (i + 1).is_multiple_of(1024) {
      region.reset();
    }
  }
  assert_eq!(
    checksum,
    (ops as u64).wrapping_mul(ops.saturating_sub(1) as u64) / 2
  );
  region.release();
  assert_eq!(region.stats().capacity, 0);
}

/// Spawns a named worker, so per-thread profiles (`threads-by-name.csv`,
/// `perf-by-thread.txt`) tell the workloads' threads apart.
fn spawn<'scope, T: Send + 'scope>(
  s: &'scope std::thread::Scope<'scope, '_>,
  name: &str,
  f: impl FnOnce() -> T + Send + 'scope,
) {
  std::thread::Builder::new()
    .name(name.to_owned())
    .spawn_scoped(s, f)
    .expect("spawn a benchmark thread");
}

fn threads_small(threads: usize, ops: usize) {
  std::thread::scope(|s| {
    for t in 0..threads {
      spawn(s, "small-churn", move || {
        black_box(small_churn(t as u64 * 7919 + 1, ops, 1000))
      });
    }
  });
}

fn threads_local(threads: usize, ops: usize) {
  std::thread::scope(|s| {
    for t in 0..threads {
      spawn(s, "local-churn", move || {
        black_box(churn(t as u64 * 7919 + 1, ops, 1000))
      });
    }
  });
}

fn producer_consumer(pairs: usize, batches: usize) {
  std::thread::scope(|s| {
    for p in 0..pairs {
      let (tx, rx) = mpsc::sync_channel::<Vec<Vec<u8>>>(16);
      spawn(s, "producer", move || {
        let mut rng = Rng(p as u64 * 104_729 + 3);
        for _ in 0..batches {
          let batch = (0..64).map(|_| vec![0u8; rng.size() % 4096 + 1]).collect();
          if tx.send(batch).is_err() {
            break;
          }
        }
      });
      spawn(s, "consumer", move || {
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
  let before = Usage::of_self();
  let t = Instant::now();
  f();
  let ms = t.elapsed().as_secs_f64() * 1e3;
  let u = Usage::of_self().since(&before);
  println!(
    "{name}\t{label}\t{ms:.1} ms\tVmRSS {} KiB\tuser {:.0} ms\tsys {:.0} ms\tminflt {}\tmajflt {}\tdisk read {} B\tdisk write {} B",
    rss_kib("VmRSS:"),
    u.user_s * 1e3,
    u.sys_s * 1e3,
    u.minflt,
    u.majflt,
    u.read_bytes,
    u.write_bytes,
  );
}

/// The command-line options of the benchmark binaries.
struct Options {
  /// Divides every operation count.
  scale: usize,
  idle: Duration,
  only: Option<Vec<String>>,
}

impl Options {
  fn from_args() -> Self {
    let mut o = Self {
      scale: 1,
      idle: Duration::from_secs(3),
      only: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
      match a.as_str() {
        "--quick" => {
          o.scale = 20;
          o.idle = Duration::from_millis(500);
        }
        "--only" => {
          o.only = args
            .next()
            .map(|v| v.split(',').map(str::to_owned).collect());
        }
        _ => eprintln!("ignoring unknown argument {a:?} (known: --quick, --only KEY[,KEY...])"),
      }
    }
    o
  }

  fn runs(&self, key: &str) -> bool {
    self
      .only
      .as_ref()
      .is_none_or(|keys| keys.iter().any(|k| k == key))
  }
}

/// Runs every workload and prints one tab-separated line per result.
pub fn run(name: &str) {
  let o = Options::from_args();
  // A selected workload's retained-memory summary must follow its work.
  // The default suite keeps its historical peak/idle ordering below.
  let peak_after_oversubscribed = o.only.is_some() && o.runs("oversubscribed");
  let n = |ops: usize| ops / o.scale;
  let threads = std::thread::available_parallelism()
    .map_or(4, |n| n.get())
    .min(16);
  if o.runs("single") {
    time(
      &format!("single-thread churn {}", count(n(2_000_000))),
      name,
      || {
        black_box(churn(42, n(2_000_000), 1000));
      },
    );
  }
  if o.runs("local") {
    time(
      &format!("{threads}-thread local churn {} each", count(n(1_000_000))),
      name,
      || threads_local(threads, n(1_000_000)),
    );
  }
  if o.runs("small") {
    time(
      &format!("{threads}-thread small churn {} each", count(n(4_000_000))),
      name,
      || threads_small(threads, n(4_000_000)),
    );
  }
  if o.runs("pairs") {
    time(
      &format!(
        "{} producer/consumer pairs {} batches",
        threads / 2,
        count(n(20_000))
      ),
      name,
      || {
        producer_consumer(threads / 2, n(20_000));
      },
    );
  }
  if o.runs("aligned") {
    time("aligned 64/256-byte churn", name, || {
      aligned_churn(n(4_000_000))
    });
  }
  if o.runs("region") {
    time("region 64-byte bump/reset", name, || {
      region_churn(n(10_000_000))
    });
  }
  if !peak_after_oversubscribed {
    peak(name);
  }
  // What a server keeps after a burst while it waits for the next one: no
  // allocator calls happen during the sleep.
  if o.runs("idle") {
    std::thread::sleep(o.idle);
    println!(
      "{name}\tidle\tVmRSS after {:.1} s idle {} KiB",
      o.idle.as_secs_f64(),
      rss_kib("VmRSS:")
    );
  }
  // The local churn's work spread over four times as many threads as
  // CPUs, so lock holders get preempted and waiters must get out of the
  // way (docs/research/benchmarks.md, lock contention). Last, so that it
  // does not change the peak and idle figures above.
  if o.runs("oversubscribed") {
    time(
      &format!(
        "{}-thread local churn {} each (oversubscribed)",
        4 * threads,
        count(n(250_000))
      ),
      name,
      || threads_local(4 * threads, n(250_000)),
    );
  }
  if peak_after_oversubscribed {
    peak(name);
  }
  // After the peak and idle figures, which they would change, and before
  // the huge blocks: the small-object fast path on one thread, without
  // and with alignments above the default 16 bytes.
  if o.runs("small1") {
    time(
      &format!("single-thread small churn {}", count(n(4_000_000))),
      name,
      || {
        black_box(small_churn(42, n(4_000_000), 1000));
      },
    );
  }
  if o.runs("aligned-mix") {
    time(
      &format!("aligned 32-4096-byte mix churn {}", count(n(4_000_000))),
      name,
      || {
        black_box(aligned_mix(42, n(4_000_000), 1000));
      },
    );
  }
  // After the peak and idle figures too: page runs of 8 to 64 KiB, with
  // as many live as fill about 16 and about 64 segments.
  for (key, live) in [("runs", 1000), ("runs4000", 4000)] {
    if o.runs(key) {
      time(
        &format!(
          "page-run 8-64 KiB churn {}, {live} live",
          count(n(1_000_000))
        ),
        name,
        || {
          black_box(run_churn(42, n(1_000_000), live));
        },
      );
    }
  }
  // Last too: a few huge blocks would raise the peak above.
  if o.runs("huge") {
    time(
      &format!("huge 4.5-16 MiB churn {}", count(n(3_000))),
      name,
      || huge_churn(n(3_000)),
    );
  }
}

fn peak(name: &str) {
  println!(
    "{name}\tpeak\tVmHWM {} KiB\tVmRSS after {} KiB",
    rss_kib("VmHWM:"),
    rss_kib("VmRSS:")
  );
}

/// `2000000` as `2M`, `250000` as `250k`, the way the workload names had them.
fn count(n: usize) -> String {
  if n >= 1_000_000 && n.is_multiple_of(1_000_000) {
    format!("{}M", n / 1_000_000)
  } else if n >= 1000 && n.is_multiple_of(1000) {
    format!("{}k", n / 1000)
  } else {
    n.to_string()
  }
}

pub mod latency;

pub mod cache_retention;
