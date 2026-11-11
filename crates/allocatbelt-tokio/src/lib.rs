//! Tokio runtime hooks for allocatbelt: the runtime's threads return their
//! allocator caches when they park and prefer one shard each.
//!
//! ```
//! use allocatbelt_tokio::Hooks;
//!
//! let mut builder = tokio::runtime::Builder::new_multi_thread();
//! builder.worker_threads(4);
//! Hooks::new().install(&mut builder);
//! let runtime = builder.build()?;
//! let n = runtime.block_on(async { tokio::spawn(async { vec![1u8; 64].len() }).await })?;
//! assert_eq!(n, 64);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! What the hooks do, with the stable Tokio hooks only (no
//! `tokio_unstable`):
//!
//! - **Park.** When a thread of the runtime runs out of work and is about
//!   to park, it hands its allocatbelt cache back to the shared heap
//!   ([`Allocatbelt::flush_thread_cache`]): an idle worker stops holding
//!   blocks the busy ones could use, and freed memory reaches the purge
//!   passes sooner.
//! - **Start.** Each thread the runtime starts takes the next shard
//!   ([`Allocatbelt::set_thread_shard`]), from [`Hooks::first_shard`] on, so
//!   a fixed pool of workers spreads evenly over the heap's 64 shards
//!   whatever other threads started in between. Tokio runs the same start
//!   hook for its blocking-pool threads, which take the following shards.
//!
//! These change where memory is cached, not how Tokio schedules: which task
//! runs, on which worker and when is still Tokio's decision. The hooks do
//! not install allocatbelt as the global allocator; without it, they only
//! touch caches that stay empty. **Performance not measured; benchmark
//! gate intentionally disabled.**
//!
//! # Regions in tasks
//!
//! A task can own an [`allocatbelt::Region`] for its temporary data and keep
//! pieces of it across `.await`s: the region moves with the task's future,
//! which stays `Send`, so `tokio::spawn` accepts it on the multi-thread
//! runtime. Reset it when a unit of work ends:
//!
//! ```
//! # let rt = tokio::runtime::Builder::new_multi_thread().build()?;
//! # rt.block_on(async {
//! let task = tokio::spawn(async {
//!   let mut region = allocatbelt::Region::new();
//!   let xs = region.alloc_slice_fill(16, 1u32).unwrap();
//!   tokio::task::yield_now().await; // may resume on another worker
//!   xs[0] += 1;
//!   let sum: u32 = xs.iter().sum();
//!   region.reset();
//!   sum
//! });
//! assert_eq!(task.await.unwrap(), 17);
//! # });
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! What such a task cannot do is keep a `&Region` itself across an
//! `.await`: a region is not `Sync`, so the future would not be `Send`.
//!
//! ```compile_fail,E0277
//! # let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();
//! # rt.block_on(async {
//! tokio::spawn(async {
//!   let region = allocatbelt::Region::new();
//!   let r = &region;
//!   tokio::task::yield_now().await;
//!   r.alloc_copy(1u8).map(|x| *x)
//! });
//! # });
//! ```
//!
//! Tokio keeps one callback per hook, so [`Hooks::install`] replaces the
//! builder's `on_thread_start` and `on_thread_park` callbacks. An
//! application with its own calls [`Hooks::thread_started`] and
//! [`Hooks::thread_parking`] from them instead.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use allocatbelt::Allocatbelt;
use tokio::runtime::Builder;

/// The runtime hooks and their settings. Cheap to clone: clones share the
/// shard counter.
#[derive(Debug, Clone)]
pub struct Hooks {
  flush_on_park: bool,
  shard_per_thread: bool,
  first_shard: usize,
  next: Arc<AtomicUsize>,
}

impl Default for Hooks {
  fn default() -> Self {
    Self::new()
  }
}

impl Hooks {
  /// Both hooks on, shards from 0.
  #[must_use]
  pub fn new() -> Self {
    Self {
      flush_on_park: true,
      shard_per_thread: true,
      first_shard: 0,
      next: Arc::new(AtomicUsize::new(0)),
    }
  }

  /// Whether a parking thread returns its cache (default `true`).
  #[must_use]
  pub fn flush_on_park(mut self, on: bool) -> Self {
    self.flush_on_park = on;
    self
  }

  /// Whether each started thread takes the next shard (default `true`).
  /// Off, threads keep the shard their cache was attached to.
  #[must_use]
  pub fn shard_per_thread(mut self, on: bool) -> Self {
    self.shard_per_thread = on;
    self
  }

  /// The shard the first started thread takes (default 0): two runtimes in
  /// one process can start at different shards, such as 0 and 32.
  #[must_use]
  pub fn first_shard(mut self, shard: usize) -> Self {
    self.first_shard = shard;
    self
  }

  /// Sets the builder's `on_thread_start` and `on_thread_park` callbacks
  /// to these hooks, replacing any set before.
  pub fn install(self, builder: &mut Builder) -> &mut Builder {
    let start = self.clone();
    builder
      .on_thread_start(move || start.thread_started())
      .on_thread_park(move || self.thread_parking())
  }

  /// The start hook: call it from the runtime's `on_thread_start` callback
  /// when the application has its own.
  pub fn thread_started(&self) {
    if self.shard_per_thread {
      let n = self.next.fetch_add(1, Ordering::Relaxed);
      Allocatbelt.set_thread_shard(self.first_shard.wrapping_add(n));
    }
  }

  /// The park hook: call it from the runtime's `on_thread_park` callback
  /// when the application has its own. Bounded and allocation-free.
  pub fn thread_parking(&self) {
    if self.flush_on_park {
      Allocatbelt.flush_thread_cache();
    }
  }

  /// Threads that ran the start hook so far.
  #[must_use]
  pub fn threads_started(&self) -> usize {
    self.next.load(Ordering::Relaxed)
  }
}
