//! Holds one I/O pool worker in a blocking pipe read until released.
//!
//! The I/O pool admits only adapter operations, so tests that need a busy
//! or full pool occupy a worker with a blocking reader instead of a closure.

use std::future::Future;
use std::io::{PipeWriter, Write};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::blocking_io::{self, BlockingReader};
use allocatbelt::runtime::io::AsyncReadExt;
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::{IoPoolHandle, Resources};

const WAIT: Duration = Duration::from_secs(5);

/// One admitted blocking read that occupies an I/O pool worker and one
/// outstanding slot until [`IoGate::release`].
pub struct IoGate {
  reader: BlockingReader<std::io::PipeReader>,
  writer: PipeWriter,
}

impl IoGate {
  /// Admits the read and waits until a worker runs it.
  ///
  /// Precondition: the pool has a free worker and no other operation that
  /// can start or finish while this waits, normally an idle pool. The wait
  /// observes only the pool's running count, so concurrent activity could
  /// make it return before the gate itself is running.
  pub fn occupy(pool: &IoPoolHandle) -> Self {
    let running_before = pool.snapshot().running;
    let (pipe_reader, writer) = std::io::pipe().expect("gate pipe should open");
    // The gate buffer is charged to its own scope, not the test's ledger.
    let buffer = ResourceScope::new(ResourceLimits {
      managed_memory: 1,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    })
    .try_alloc_zeroed(1)
    .expect("gate buffer should fit");
    let mut reader = blocking_io::reader(pool.clone(), Resources::ZERO, pipe_reader, buffer)
      .unwrap_or_else(|error| panic!("gate reader should initialize: {}", error.kind));
    let mut byte = [0_u8; 1];
    let mut context = Context::from_waker(Waker::noop());
    assert!(
      pin!(reader.read(&mut byte)).poll(&mut context).is_pending(),
      "gate read should wait for its release byte"
    );
    let deadline = Instant::now() + WAIT;
    while pool.snapshot().running <= running_before {
      assert!(
        Instant::now() < deadline,
        "gate read should occupy a worker"
      );
      thread::yield_now();
    }
    Self { reader, writer }
  }

  /// Lets the read finish and waits for its job to complete.
  pub fn release(mut self) {
    self
      .writer
      .write_all(&[1])
      .expect("gate release byte should be written");
    let mut byte = [0_u8; 1];
    let mut context = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + WAIT;
    loop {
      if let Poll::Ready(result) = pin!(self.reader.read(&mut byte)).poll(&mut context) {
        assert_eq!(result.expect("gate read should finish"), 1);
        return;
      }
      assert!(Instant::now() < deadline, "gate read should finish");
      thread::yield_now();
    }
  }
}
