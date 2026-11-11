//! Shared readiness-gated syscall attempts for reactor-backed endpoints.
//!
//! A `Pending` readiness poll and a stale `WouldBlock` refund the provisional
//! cooperative charge. `Interrupted` consumes it. Every syscall retry re-enters
//! the gate, while the endpoint-local retry ceiling bounds work in one poll.

#![forbid(unsafe_code)]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::asynchronous;
use super::reactor::{AsyncFd, OwnedReadiness};

const IO_BUDGET: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum IoDirection {
  Read,
  Write,
}

#[derive(Debug)]
pub(super) enum IoAttempt<T> {
  RetryCharged,
  RetryRefunded,
  Complete(io::Result<T>),
}

/// Polls one readiness-plus-syscall attempt behind the shared cooperative
/// gate. The owned waiter remains in `waiter` across readiness `Pending` and
/// is removed before a terminal result.
pub(super) fn poll_io_attempt<T, R>(
  cx: &mut Context<'_>,
  fd: &AsyncFd<T>,
  waiter: &mut Option<OwnedReadiness<T>>,
  direction: IoDirection,
  operation: impl FnOnce(&T) -> io::Result<R>,
) -> Poll<IoAttempt<R>> {
  let mut stale_would_block = false;
  let result = asynchronous::poll_cooperative(cx, |cx| {
    if waiter.is_none() {
      *waiter = Some(match direction {
        IoDirection::Read => fd.readable_owned(),
        IoDirection::Write => fd.writable_owned(),
      });
    }
    let readiness = match waiter.as_mut() {
      Some(readiness) => Pin::new(readiness).poll(cx),
      None => unreachable!("readiness waiter was just created"),
    };
    match readiness {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => {
        drop(waiter.take());
        Poll::Ready(IoAttempt::Complete(Err(error)))
      }
      Poll::Ready(Ok(guard)) => {
        drop(waiter.take());
        match guard.try_io(operation) {
          Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            Poll::Ready(IoAttempt::RetryCharged)
          }
          Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            stale_would_block = true;
            Poll::Pending
          }
          result => Poll::Ready(IoAttempt::Complete(result)),
        }
      }
    }
  });
  match result {
    Poll::Pending if stale_would_block => Poll::Ready(IoAttempt::RetryRefunded),
    result => result,
  }
}

/// Polls at most 64 endpoint attempts in one poll. On the local cap, the last
/// stale syscall has cleared readiness, so self-wake before returning `Pending`.
pub(super) fn poll_io_with_retry<T, R>(
  cx: &mut Context<'_>,
  fd: &AsyncFd<T>,
  waiter: &mut Option<OwnedReadiness<T>>,
  direction: IoDirection,
  mut operation: impl FnMut(&T) -> io::Result<R>,
) -> Poll<io::Result<R>> {
  let mut attempts = 0;
  loop {
    if attempts == IO_BUDGET {
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    match poll_io_attempt(cx, fd, waiter, direction, |value| operation(value)) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(IoAttempt::RetryCharged | IoAttempt::RetryRefunded) => attempts += 1,
      Poll::Ready(IoAttempt::Complete(result)) => return Poll::Ready(result),
    }
  }
}
