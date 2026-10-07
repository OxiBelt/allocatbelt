//! Bounded bidirectional copying between two borrowed duplex endpoints through
//! two caller-owned initialized slices.
//!
//! [`copy_bidirectional_with_buffers`] runs two independent directions, A to B
//! and B to A, on the caller's task. Each direction reads into its own slice,
//! writes everything it read, and at end of stream flushes and then shuts down
//! its destination's write side. Neither direction waits for the other: one
//! direction may finish, block or shut down while the other keeps copying.
//!
//! The future borrows both endpoints and both slices, so it allocates nothing,
//! reserves no managed storage and needs no endpoint split. It is a serial
//! state machine over generic endpoints: in one poll it alternates single
//! endpoint calls between the directions, which interleaves full-duplex
//! traffic but does not run the directions in parallel.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::{AsyncRead, AsyncWrite, POLL_BUDGET, checked_count, yield_now};

/// Copies from `a` to `b` through `a_to_b` and from `b` to `a` through
/// `b_to_a` until both directions finish, completing with the bytes each
/// destination accepted, `(a_to_b, b_to_a)`, each saturating at `u64::MAX`.
///
/// Each direction reads into its slice only after its destination accepted
/// every byte of the previous read. When a direction's source reports end of
/// stream, the direction flushes its destination and, once that flush
/// succeeds, polls the destination's [`AsyncWrite::poll_shutdown`] until it
/// succeeds. A completed flush or shutdown is never repeated. The future
/// completes only when both directions have shut down their destinations.
/// When a source returns `Pending` after its direction wrote bytes that were
/// not flushed since, the direction owes its destination a flush, so a
/// buffering destination is not left holding bytes the source's peer may be
/// waiting for. The owed flush is kept across polls, including when the
/// budget runs out or the flush returns `Pending`, and the direction polls it
/// before it reads or writes again until it succeeds. The source is not
/// polled again in the poll in which it returned `Pending`, so its registered
/// waker stays in place.
///
/// # Half-close
///
/// Whether shutting down one direction leaves the endpoint readable depends
/// on the endpoint. [`TcpStream`](crate::runtime::net::TcpStream) shuts down
/// only its write half, so the reverse direction continues. An adapter whose
/// shutdown closes the whole endpoint, or that rejects reads after shutdown,
/// ends or fails the reverse direction instead; this helper does not provide
/// half-close on endpoints that lack it.
///
/// # Fairness
///
/// One poll makes at most [`POLL_BUDGET`] endpoint calls in total, counting
/// reads, writes, flushes, shutdowns and `Interrupted` attempts of both
/// directions. Calls alternate between the directions, and the direction that
/// would have gone next starts the following poll, so a direction whose
/// endpoint is always ready cannot starve the other. A direction whose
/// endpoint returned `Pending` is not polled again in that poll. When both
/// directions wait on their endpoints, or one has finished and the other
/// waits, the future returns `Pending` without waking itself; only an
/// exhausted budget with work left wakes the task once before returning
/// `Pending`. This bounds the helper's own loop; it is not runtime-wide
/// cooperative scheduling for other endpoint polls.
///
/// # Cancellation and partial progress
///
/// Dropping the future is safe for ownership and is not transactional. Bytes
/// a destination accepted stay accepted, completed flushes and shutdowns are
/// not undone, and bytes a source yielded but its destination has not accepted
/// stay in the caller's slice. [`CopyBidirectional::transferred`] and
/// [`CopyBidirectional::unwritten`] report both directions; they are updated
/// as soon as an endpoint's count is validated, before any further call, and
/// remain readable after an error. The unwritten range is lost to the stream
/// unless the caller reads it before dropping the future and writes it
/// itself. Nothing is rolled back or replayed. A panicking endpoint may leave
/// its own state partially changed.
///
/// Polling the future after it returned a result panics.
///
/// # Errors
///
/// `InvalidInput` when either slice is empty, before either endpoint is
/// polled; `WriteZero` when a destination accepts no bytes of a nonempty
/// write; `InvalidData` when an endpoint reports more bytes than it was
/// offered, checked before the count is used; otherwise the first error from
/// any read, write, flush or shutdown. `Interrupted` is retried within the
/// budget; every other error, including `WouldBlock`, ends the whole copy
/// without polling either direction again.
pub fn copy_bidirectional_with_buffers<'a, A, B>(
  a: &'a mut A,
  b: &'a mut B,
  a_to_b: &'a mut [u8],
  b_to_a: &'a mut [u8],
) -> CopyBidirectional<'a, A, B>
where
  A: AsyncRead + AsyncWrite + Unpin + ?Sized,
  B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
  CopyBidirectional {
    a,
    b,
    a_to_b: Direction::new(a_to_b),
    b_to_a: Direction::new(b_to_a),
    next: Side::AToB,
    done: false,
  }
}

/// A bounded bidirectional copy; see [`copy_bidirectional_with_buffers`].
#[must_use = "futures do nothing unless polled"]
pub struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
  a: &'a mut A,
  b: &'a mut B,
  a_to_b: Direction<'a>,
  b_to_a: Direction<'a>,
  /// The direction that makes the next endpoint call.
  next: Side,
  /// A result was returned.
  done: bool,
}

impl<A: ?Sized, B: ?Sized> CopyBidirectional<'_, A, B> {
  /// Bytes each destination has accepted so far, `(a_to_b, b_to_a)`,
  /// including before an error or a `Pending` the caller may abandon, each
  /// saturating at `u64::MAX`.
  #[must_use]
  pub const fn transferred(&self) -> (u64, u64) {
    (self.a_to_b.transferred, self.b_to_a.transferred)
  }

  /// The ranges of the `a_to_b` and `b_to_a` slices holding bytes taken from
  /// a source and not yet accepted by its destination; a range is empty when
  /// there are none. These bytes are lost to the stream if the caller drops
  /// the copy without writing them itself.
  #[must_use]
  pub const fn unwritten(&self) -> (Range<usize>, Range<usize>) {
    (self.a_to_b.unwritten(), self.b_to_a.unwritten())
  }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
  A: AsyncRead + AsyncWrite + Unpin + ?Sized,
  B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
  type Output = io::Result<(u64, u64)>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "CopyBidirectional polled after completion");
    if this.a_to_b.buf.is_empty() || this.b_to_a.buf.is_empty() {
      this.done = true;
      return Poll::Ready(Err(ErrorKind::InvalidInput.into()));
    }
    let mut a_to_b = Turn::default();
    let mut b_to_a = Turn::default();
    let mut budget = POLL_BUDGET;
    loop {
      let a_to_b_runs = this.a_to_b.phase != Phase::Done && !a_to_b.blocked;
      let b_to_a_runs = this.b_to_a.phase != Phase::Done && !b_to_a.blocked;
      if !a_to_b_runs && !b_to_a_runs {
        if this.a_to_b.phase == Phase::Done && this.b_to_a.phase == Phase::Done {
          this.done = true;
          return Poll::Ready(Ok(this.transferred()));
        }
        // Every unfinished direction waits on an endpoint that holds the
        // task's waker.
        return Poll::Pending;
      }
      if budget == 0 {
        return yield_now(cx);
      }
      budget -= 1;
      let side = match this.next {
        Side::AToB if a_to_b_runs => Side::AToB,
        Side::BToA if b_to_a_runs => Side::BToA,
        Side::AToB => Side::BToA,
        Side::BToA => Side::AToB,
      };
      this.next = side.other();
      let result = match side {
        Side::AToB => this
          .a_to_b
          .step(&mut a_to_b, &mut *this.a, &mut *this.b, cx),
        Side::BToA => this
          .b_to_a
          .step(&mut b_to_a, &mut *this.b, &mut *this.a, cx),
      };
      if let Err(error) = result {
        this.done = true;
        return Poll::Ready(Err(error));
      }
    }
  }
}

impl<A: ?Sized, B: ?Sized> fmt::Debug for CopyBidirectional<'_, A, B> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CopyBidirectional")
      .field("a_to_b", &self.a_to_b)
      .field("b_to_a", &self.b_to_a)
      .field("done", &self.done)
      .finish_non_exhaustive()
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
  AToB,
  BToA,
}

impl Side {
  const fn other(self) -> Self {
    match self {
      Self::AToB => Self::BToA,
      Self::BToA => Self::AToB,
    }
  }
}

/// Where a direction is between its first read and its shutdown. Each phase
/// is entered once and never revisited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
  /// Reading from the source and writing every byte read.
  Copying,
  /// The source reported end of stream and every byte was written; flushing
  /// the destination.
  Flushing,
  /// The flush succeeded; shutting down the destination's write side.
  ShuttingDown,
  /// The shutdown succeeded.
  Done,
}

/// What one direction learned about its endpoints during the current poll.
#[derive(Debug, Default)]
struct Turn {
  /// An endpoint returned `Pending` and holds the task's waker.
  blocked: bool,
  /// The source returned `Pending` in this poll and still holds the task's
  /// waker, so it is not read again until the next poll.
  source_waiting: bool,
}

/// One direction's borrowed slice and persistent progress.
struct Direction<'a> {
  buf: &'a mut [u8],
  /// `buf[start..end]` was read and not yet written; both are zero when it
  /// is empty, and `end` never exceeds `buf.len()`.
  start: usize,
  end: usize,
  phase: Phase,
  /// Bytes were written since the last successful flush.
  need_flush: bool,
  /// The source returned `Pending` while `need_flush` was set, and the flush
  /// this owes has not succeeded yet. It survives an exhausted budget and a
  /// pending flush, and the flush runs before the source is read again.
  flush_owed: bool,
  transferred: u64,
}

impl<'a> Direction<'a> {
  const fn new(buf: &'a mut [u8]) -> Self {
    Self {
      buf,
      start: 0,
      end: 0,
      phase: Phase::Copying,
      need_flush: false,
      flush_owed: false,
      transferred: 0,
    }
  }

  const fn unwritten(&self) -> Range<usize> {
    self.start..self.end
  }

  /// Makes exactly one endpoint call for this direction and records its
  /// result. `Interrupted` leaves the state unchanged so the next step
  /// retries the same call.
  fn step<R, W>(
    &mut self,
    turn: &mut Turn,
    reader: &mut R,
    writer: &mut W,
    cx: &mut Context<'_>,
  ) -> io::Result<()>
  where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
  {
    let polled = match self.phase {
      Phase::Copying if self.start < self.end => {
        let unwritten = &self.buf[self.start..self.end];
        match Pin::new(&mut *writer).poll_write(cx, unwritten) {
          Poll::Ready(Ok(0)) => return Err(ErrorKind::WriteZero.into()),
          Poll::Ready(Ok(count)) => {
            self.start += checked_count(count, unwritten.len())?;
            // `usize` is 64 bits on every supported target.
            self.transferred = self.transferred.saturating_add(count as u64);
            self.need_flush = true;
            if self.start == self.end {
              self.start = 0;
              self.end = 0;
            }
            Poll::Ready(Ok(()))
          }
          other => other.map_ok(drop),
        }
      }
      // An owed flush only arises with every read byte written, so it never
      // overtakes a write.
      Phase::Copying if self.flush_owed => match Pin::new(&mut *writer).poll_flush(cx) {
        Poll::Ready(Ok(())) => {
          self.need_flush = false;
          self.flush_owed = false;
          // A source that waited in this poll still holds the task's waker;
          // after an earlier poll's wait, the next step reads it again.
          turn.blocked = turn.source_waiting;
          Poll::Ready(Ok(()))
        }
        other => other,
      },
      Phase::Copying => match Pin::new(&mut *reader).poll_read(cx, self.buf) {
        Poll::Pending if self.need_flush => {
          turn.source_waiting = true;
          self.flush_owed = true;
          Poll::Ready(Ok(()))
        }
        Poll::Ready(Ok(0)) => {
          self.phase = Phase::Flushing;
          Poll::Ready(Ok(()))
        }
        Poll::Ready(Ok(count)) => {
          self.end = checked_count(count, self.buf.len())?;
          Poll::Ready(Ok(()))
        }
        other => other.map_ok(drop),
      },
      Phase::Flushing => match Pin::new(&mut *writer).poll_flush(cx) {
        Poll::Ready(Ok(())) => {
          self.need_flush = false;
          self.phase = Phase::ShuttingDown;
          Poll::Ready(Ok(()))
        }
        other => other,
      },
      Phase::ShuttingDown => match Pin::new(&mut *writer).poll_shutdown(cx) {
        Poll::Ready(Ok(())) => {
          self.phase = Phase::Done;
          Poll::Ready(Ok(()))
        }
        other => other,
      },
      Phase::Done => Poll::Ready(Ok(())),
    };
    match polled {
      Poll::Pending => {
        turn.blocked = true;
        Ok(())
      }
      Poll::Ready(Err(error)) if error.kind() != ErrorKind::Interrupted => Err(error),
      Poll::Ready(_) => Ok(()),
    }
  }
}

impl fmt::Debug for Direction<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Direction")
      .field("len", &self.buf.len())
      .field("unwritten", &self.unwritten())
      .field("phase", &self.phase)
      .field("transferred", &self.transferred)
      .finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
#[path = "io_bidirectional_tests.rs"]
mod tests;
