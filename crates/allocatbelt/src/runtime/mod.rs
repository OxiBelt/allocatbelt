//! Bounded blocking and owned-future runtime foundations for allocatbelt.
//! See [`asynchronous`] for owned futures and [`managed`] for storage ledgers.
//! The blocking pool uses a fixed set
//! of worker threads runs submitted closures in FIFO order under an
//! outstanding-job bound and a declared resource capacity, and each worker
//! prefers its own allocatbelt shard and returns its thread cache before it
//! parks and before it exits.
//!
//! ```
//! use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};
//!
//! let mut rt = Runtime::new(Config {
//!   workers: 2,
//!   max_outstanding: 8,
//!   capacity: Resources { cpu: 4, memory: 1 << 20, disk: 0, network: 0 },
//! })?;
//! let request = Resources { cpu: 1, memory: 4096, ..Resources::ZERO };
//! let job = rt.try_spawn(request, |_token| vec![1u8; 64].len()).map_err(|e| e.kind)?;
//! assert_eq!(job.join()?, 64);
//! rt.shutdown(ShutdownMode::Drain)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Admission
//!
//! [`Handle::try_spawn`] admits a job or rejects it at once, returning the
//! closure. Admission reserves the full [`Resources`] request and one of
//! `max_outstanding` slots, both held while the job is queued or running
//! and released exactly once: after its closure returns or panics and its
//! captures are dropped, or, for a job a worker or a shutdown takes off the
//! queue unstarted, after its closure and captures are dropped. A zero request
//! takes only a slot. The bounds count what callers declare, such as the
//! bytes a job says its working allocations need. They are not enforced:
//! the runtime does not measure memory, and there is no CPU quota, RSS,
//! bandwidth, rate or disk-space limit. What a job really allocates, and
//! the result it returns after release, is not checked against them.
//!
//! # Cancellation
//!
//! A job leaves the queued state once, by one atomic swap: a worker
//! starting it, or [`Job::cancel`] (or a cancelling shutdown) cancelling it.
//! That swap is the linearization point for whether the closure runs. If
//! the cancellation wins, the closure is never called. The job keeps its
//! slot and resources until it is taken off the queue and its closure is
//! dropped, outside the lock; only then are they released, and then
//! [`Job::join`] returns [`JoinError::Cancelled`]. If the start wins, the
//! closure runs and its [`CancellationToken`] reports the cancellation;
//! nothing is preempted. Dropping a [`Job`] detaches it and does not
//! cancel.
//!
//! # Locks and user code
//!
//! The scheduler lock is never held while a closure runs or while a
//! closure, a result or a panic payload is dropped. With `panic = unwind`,
//! a closure's panic is caught and returned by `join`, and a panic in a
//! `Drop` the runtime runs is contained, so the worker keeps running; a
//! panic payload whose own `Drop` panics is leaked. With `panic = abort`,
//! or a panic while already unwinding, the process aborts as usual.
//!
//! # Shutdown and joins
//!
//! [`Runtime::shutdown`] closes the runtime and waits ([`ShutdownMode`]).
//! Called from one of the runtime's workers, it fails with `Deadlock`
//! instead of joining. A [`Job::join`] that would block on a worker of the
//! job's runtime (thread-local destructors as it exits included), or on
//! the thread dropping its queued jobs (through any nested cleanup of other
//! runtimes), returns [`JoinError::WouldDeadlock`] instead. Dropping a [`Runtime`] does not
//! join its workers (see [`Runtime`]).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod admission;
pub mod asynchronous;
pub mod barrier;
mod blocking;
pub mod buffered_io;
mod cache;
pub mod channel;
mod error;
pub mod fs;
pub mod io;
mod job;
pub mod managed;
#[cfg(all(test, loom))]
mod model;
pub mod mutex;
#[cfg(not(loom))]
pub mod net;
pub mod notify;
pub mod once_cell;
pub mod oneshot;
#[cfg(not(loom))]
pub mod reactor;
mod resources;
pub mod rwlock;
mod scheduler;
pub mod semaphore;
mod state;
mod sync;
mod task;
pub mod task_local;
#[cfg(all(test, not(loom)))]
mod tests;
#[cfg(all(test, not(loom)))]
mod tests_guard;
pub mod time;
pub mod watch;
mod worker;

pub use crate::runtime::blocking::{Config, Handle, Runtime, ShutdownMode};
pub use crate::runtime::error::{JoinError, SubmitError, SubmitErrorKind};
pub use crate::runtime::job::{CancellationToken, Job};
pub use crate::runtime::resources::Resources;
pub use crate::runtime::scheduler::Snapshot;
