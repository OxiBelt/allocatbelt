//! The I/O adapter pool: worker threads and a queue that run only the
//! per-operation jobs of the asynchronous adapters over blocking calls.
//!
//! [`BlockingReader`](crate::runtime::blocking_io::BlockingReader),
//! [`BlockingWriter`](crate::runtime::blocking_io::BlockingWriter), the
//! standard-stream helpers, [`FsHandle`](crate::runtime::fs::FsHandle),
//! [`AsyncFile`](crate::runtime::fs_io::AsyncFile) and the blocking connect
//! and name resolution of [`NetHandle`](crate::runtime::net::NetHandle) submit
//! their jobs here, not to a user [`Runtime`](crate::runtime::Runtime). An
//! [`IoPool`] has a fixed set of workers, its own FIFO queue, its own
//! outstanding-job bound and resource capacity, and its own shutdown. A user
//! pool's `shutdown(ShutdownMode::CancelPending)` therefore leaves queued
//! adapter operations queued, and the only jobs on a user pool are closures
//! the user submitted.
//!
//! No shutdown or drop of this pool discards an admitted operation or
//! signals an operation's token. [`IoPool::shutdown`] drains: it closes
//! admission and waits until every queued and running operation has
//! finished. Dropping a pool detaches it: admission closes, the caller does
//! not wait, and each worker runs the queued operations it reaches and then
//! exits. Operations queued behind a worker blocked in a call stay queued,
//! with their `Job`s pending and their permits, managed buffers, tenant
//! charges and the pool's waiter share held, until that worker returns.
//! Detached workers end with the process, so a queued operation such as a
//! stdout flush can be lost if `main` returns first; shut the pool down and
//! wait when it must complete. One job is cancelled only through its own
//! [`Job`] handle.
//!
//! The pool reuses the blocking runtime's scheduler and worker loop, so
//! admission, FIFO order, joins, deadlock detection and resource-domain
//! accounting behave as documented for [`Runtime`](crate::runtime::Runtime).
//! Each pool is a separate instance with a separate queue. A caller cannot
//! submit its own closure through [`IoPoolHandle`]; only the adapters in this
//! crate submit jobs, although caller `Read` and `Write` implementations run
//! inside them. The handle offers no listing of the operations and no call
//! that acts on all of them.
//!
//! Workers are named `allocatbelt-io-<index>`. Their number is fixed at
//! construction. A worker blocked in a call that waits on external input,
//! such as a stdin read, holds that worker until the call returns, and a
//! draining shutdown waits for it; size the pool with that in mind, and make
//! such streams return (for example by closing their peer) before shutting
//! down.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::io;

use crate::runtime::blocking::{Config, DropPolicy, Handle, Runtime, ShutdownMode};
use crate::runtime::error::SubmitError;
use crate::runtime::job::{CancellationToken, Job};
#[cfg(not(loom))]
use crate::runtime::managed::ResourceScope;
use crate::runtime::resources::Resources;
use crate::runtime::scheduler::Snapshot;
#[cfg(not(loom))]
use crate::runtime::time::TimerHandle;

/// The thread-name prefix of I/O adapter pool workers.
const IO_THREAD_PREFIX: &str = "allocatbelt-io-";

/// A fixed pool of worker threads reserved for the asynchronous I/O
/// adapters, with its own queue and shutdown.
///
/// Dropping a pool that was not shut down closes admission and detaches its
/// workers without discarding an operation or signalling a token; the
/// module documentation describes what stays held while a worker is blocked
/// and that detached workers end with the process.
pub struct IoPool {
  runtime: Runtime,
}

/// A cloneable handle that adapters use to submit their operations to an
/// [`IoPool`]. A caller cannot queue its own closure through it; caller
/// `Read` and `Write` implementations given to the stream adapters still run
/// on the pool's workers.
///
/// A user blocking [`Handle`](crate::runtime::Handle) is a different type,
/// so an adapter cannot be built over one:
///
/// ```compile_fail,E0308
/// use allocatbelt::runtime::{Config, Resources, Runtime};
/// use allocatbelt::runtime::fs::FsHandle;
/// use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
///
/// let runtime = Runtime::new(Config {
///   workers: 1,
///   max_outstanding: 1,
///   capacity: Resources::ZERO,
/// })
/// .unwrap();
/// let scope = ResourceScope::new(ResourceLimits::default());
/// let _fs = FsHandle::new(runtime.handle(), scope);
/// ```
///
/// ```compile_fail,E0624
/// use allocatbelt::runtime::{Config, IoPool, Resources};
///
/// let pool = IoPool::new(Config {
///   workers: 1,
///   max_outstanding: 1,
///   capacity: Resources::ZERO,
/// })
/// .unwrap();
/// let _ = pool.handle().try_spawn(Resources::ZERO, |_| ());
/// ```
#[derive(Clone)]
pub struct IoPoolHandle {
  handle: Handle,
}

impl IoPool {
  /// Starts `config.workers` I/O adapter workers with their own queue.
  ///
  /// # Errors
  ///
  /// As for [`Runtime::new`].
  pub fn new(config: Config) -> io::Result<Self> {
    Runtime::start(
      config,
      None,
      IO_THREAD_PREFIX,
      DropPolicy::Detach,
      |builder, f| builder.spawn(f),
      |_| {},
    )
    .map(|runtime| Self { runtime })
  }

  /// Starts a pool whose adapter jobs take Tasks and active CPU charges from
  /// the tenant bound to `resources`, as a facade-owned user pool does.
  #[cfg(not(loom))]
  pub(crate) fn with_resources(config: Config, resources: ResourceScope) -> io::Result<Self> {
    Runtime::start(
      config,
      Some(resources),
      IO_THREAD_PREFIX,
      DropPolicy::Detach,
      |builder, f| builder.spawn(f),
      |_| {},
    )
    .map(|runtime| Self { runtime })
  }

  /// Associates facade-owned adapter admissions with a paused-auto clock.
  #[cfg(not(loom))]
  pub(crate) fn bind_clock(&mut self, timer: TimerHandle) {
    self.runtime.bind_clock(timer);
  }

  /// A submission handle for the adapters.
  #[must_use]
  pub fn handle(&self) -> IoPoolHandle {
    IoPoolHandle {
      handle: self.runtime.handle(),
    }
  }

  /// Admits a test closure, for tests that hold or fill the adapter queue.
  #[cfg(all(test, not(loom)))]
  pub(crate) fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    self.runtime.try_spawn(request, f)
  }

  /// The current accounting of this pool alone.
  #[must_use]
  pub fn snapshot(&self) -> Snapshot {
    self.runtime.snapshot()
  }

  /// Closes admission, lets every queued and running operation finish, and
  /// waits for the workers to exit. Nothing is cancelled, so this can wait
  /// indefinitely for a blocking stream; drop the pool instead to stop
  /// waiting. User blocking pools are not affected.
  ///
  /// # Errors
  ///
  /// As for [`Runtime::shutdown`]: `Deadlock` when called from one of this
  /// pool's workers (nothing is closed then), `Other` if a worker panicked
  /// outside a job.
  pub fn shutdown(&mut self) -> io::Result<()> {
    self.runtime.shutdown(ShutdownMode::Drain)
  }

  /// Closes admission for a draining shutdown without waiting.
  #[cfg(not(loom))]
  pub(crate) fn request_shutdown(&mut self) -> io::Result<()> {
    self.runtime.request_shutdown(ShutdownMode::Drain)
  }

  #[cfg(not(loom))]
  pub(crate) fn poll_shutdown(&mut self) -> io::Result<bool> {
    self.runtime.poll_shutdown()
  }

  #[cfg(not(loom))]
  pub(crate) fn shutdown_complete(&self) -> bool {
    self.runtime.shutdown_complete()
  }
}

impl IoPoolHandle {
  /// Admits one adapter job, as [`Handle::try_spawn`] does on a user pool.
  pub(crate) fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    self.handle.try_spawn(request, f)
  }

  /// The current accounting of the pool this handle submits to.
  #[must_use]
  pub fn snapshot(&self) -> Snapshot {
    self.handle.snapshot()
  }
}

impl std::fmt::Debug for IoPool {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("IoPool")
      .field("snapshot", &self.snapshot())
      .finish_non_exhaustive()
  }
}

impl std::fmt::Debug for IoPoolHandle {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("IoPoolHandle").finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
#[path = "io_pool_tests.rs"]
mod tests;
