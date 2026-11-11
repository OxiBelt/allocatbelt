use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use super::{CopyBidirectional, Phase, copy_bidirectional_with_buffers};
use crate::runtime::io::{AsyncRead, AsyncWrite, POLL_BUDGET};

#[derive(Clone, Copy, Debug)]
enum ReadStep {
  /// Copies the bytes; a remainder that does not fit is read next.
  Bytes(&'static [u8]),
  Eof,
  Pending,
  Fail(ErrorKind),
  /// Reports this count without copying anything.
  Count(usize),
}

#[derive(Clone, Copy, Debug)]
enum WriteStep {
  All,
  /// Accepts at most this many bytes; `Up(0)` reports `Ok(0)`.
  Up(usize),
  /// Reports this count without accepting anything.
  Count(usize),
  Pending,
  Fail(ErrorKind),
}

#[derive(Clone, Copy, Debug)]
enum UnitStep {
  Done,
  Pending,
  Fail(ErrorKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
  Read,
  Write,
  Flush,
  Shutdown,
}

type Trace = Rc<RefCell<Vec<(&'static str, Call)>>>;

/// A duplex endpoint that follows a script and records every call, in order
/// across both endpoints, in a shared trace.
struct Endpoint {
  name: &'static str,
  trace: Trace,
  reads: VecDeque<ReadStep>,
  /// Used once `reads` is exhausted.
  read_default: ReadStep,
  writes: VecDeque<WriteStep>,
  flushes: VecDeque<UnitStep>,
  shutdowns: VecDeque<UnitStep>,
  shutdown_default: UnitStep,
  written: Vec<u8>,
  read_waker: Option<Waker>,
  write_waker: Option<Waker>,
}

impl Endpoint {
  fn new(name: &'static str, trace: &Trace) -> Self {
    Self {
      name,
      trace: Rc::clone(trace),
      reads: VecDeque::new(),
      read_default: ReadStep::Pending,
      writes: VecDeque::new(),
      flushes: VecDeque::new(),
      shutdowns: VecDeque::new(),
      shutdown_default: UnitStep::Done,
      written: Vec::new(),
      read_waker: None,
      write_waker: None,
    }
  }

  fn reads(mut self, steps: impl IntoIterator<Item = ReadStep>) -> Self {
    self.reads.extend(steps);
    self
  }

  fn read_forever(mut self, step: ReadStep) -> Self {
    self.read_default = step;
    self
  }

  fn writes(mut self, steps: impl IntoIterator<Item = WriteStep>) -> Self {
    self.writes.extend(steps);
    self
  }

  fn flushes(mut self, steps: impl IntoIterator<Item = UnitStep>) -> Self {
    self.flushes.extend(steps);
    self
  }

  fn shutdowns(mut self, steps: impl IntoIterator<Item = UnitStep>) -> Self {
    self.shutdowns.extend(steps);
    self
  }

  fn shutdown_forever(mut self, step: UnitStep) -> Self {
    self.shutdown_default = step;
    self
  }

  fn record(&self, call: Call) {
    self.trace.borrow_mut().push((self.name, call));
  }

  fn unit(&mut self, step: UnitStep, cx: &Context<'_>) -> Poll<io::Result<()>> {
    match step {
      UnitStep::Done => Poll::Ready(Ok(())),
      UnitStep::Pending => {
        self.write_waker = Some(cx.waker().clone());
        Poll::Pending
      }
      UnitStep::Fail(kind) => Poll::Ready(Err(kind.into())),
    }
  }
}

impl AsyncRead for Endpoint {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    this.record(Call::Read);
    match this.reads.pop_front().unwrap_or(this.read_default) {
      ReadStep::Bytes(bytes) => {
        let count = bytes.len().min(buf.len());
        buf[..count].copy_from_slice(&bytes[..count]);
        if count < bytes.len() {
          this.reads.push_front(ReadStep::Bytes(&bytes[count..]));
        }
        Poll::Ready(Ok(count))
      }
      ReadStep::Eof => Poll::Ready(Ok(0)),
      ReadStep::Pending => {
        this.read_waker = Some(cx.waker().clone());
        Poll::Pending
      }
      ReadStep::Fail(kind) => Poll::Ready(Err(kind.into())),
      ReadStep::Count(count) => Poll::Ready(Ok(count)),
    }
  }
}

impl AsyncWrite for Endpoint {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    this.record(Call::Write);
    let accepted = match this.writes.pop_front().unwrap_or(WriteStep::All) {
      WriteStep::All => buf.len(),
      WriteStep::Up(limit) => buf.len().min(limit),
      WriteStep::Count(count) => return Poll::Ready(Ok(count)),
      WriteStep::Pending => {
        this.write_waker = Some(cx.waker().clone());
        return Poll::Pending;
      }
      WriteStep::Fail(kind) => return Poll::Ready(Err(kind.into())),
    };
    this.written.extend_from_slice(&buf[..accepted]);
    Poll::Ready(Ok(accepted))
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    this.record(Call::Flush);
    let step = this.flushes.pop_front().unwrap_or(UnitStep::Done);
    this.unit(step, cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    this.record(Call::Shutdown);
    let step = this.shutdowns.pop_front().unwrap_or(this.shutdown_default);
    this.unit(step, cx)
  }
}

/// Counts wakes, so a test can tell a self-wake from an endpoint `Pending`.
#[derive(Default)]
struct CountingWake(AtomicUsize);

impl Wake for CountingWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, Ordering::Relaxed);
  }
}

fn counting_waker() -> (Arc<CountingWake>, Waker) {
  let wake = Arc::new(CountingWake::default());
  (Arc::clone(&wake), Waker::from(wake))
}

fn wakes(wake: &CountingWake) -> usize {
  wake.0.load(Ordering::Relaxed)
}

type Relay<'a> = CopyBidirectional<'a, Endpoint, Endpoint>;

fn poll(copy: &mut Relay<'_>, waker: &Waker) -> Poll<io::Result<(u64, u64)>> {
  Pin::new(copy).poll(&mut Context::from_waker(waker))
}

fn new_trace() -> Trace {
  Rc::new(RefCell::new(Vec::new()))
}

fn count(trace: &Trace, name: &str, call: Call) -> usize {
  trace
    .borrow()
    .iter()
    .filter(|&&entry| entry == (name, call))
    .count()
}

fn calls(trace: &Trace) -> usize {
  trace.borrow().len()
}

fn calls_since(trace: &Trace, start: usize) -> Vec<(&'static str, Call)> {
  trace.borrow()[start..].to_vec()
}

#[test]
fn either_empty_slice_fails_before_any_endpoint_call() {
  for (a_to_b_len, b_to_a_len) in [(0, 4), (4, 0), (0, 0)] {
    let trace = new_trace();
    let mut a = Endpoint::new("a", &trace).read_forever(ReadStep::Bytes(b"x"));
    let mut b = Endpoint::new("b", &trace).read_forever(ReadStep::Bytes(b"y"));
    let mut a_to_b = vec![0; a_to_b_len];
    let mut b_to_a = vec![0; b_to_a_len];
    let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
    let (wake, waker) = counting_waker();
    let Poll::Ready(Err(error)) = poll(&mut copy, &waker) else {
      panic!("an empty slice must fail at once");
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(copy.transferred(), (0, 0));
    assert_eq!(calls(&trace), 0);
    assert_eq!(wakes(&wake), 0);
  }
}

#[test]
fn source_eof_shuts_down_destination_after_its_bytes_while_reverse_continues() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Bytes(b"hello"), ReadStep::Eof]);
  let mut b = Endpoint::new("b", &trace).reads([
    ReadStep::Bytes(b"wo"),
    ReadStep::Pending,
    ReadStep::Bytes(b"rld"),
    ReadStep::Eof,
  ]);
  let (mut a_to_b, mut b_to_a) = ([0; 8], [0; 8]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(wakes(&wake), 0, "endpoint Pending must not self-wake");
  assert_eq!(copy.a_to_b.phase, Phase::Done);
  assert_eq!(copy.b.written, b"hello");
  // B's write side was flushed and then shut down after its last write.
  let b_writes: Vec<Call> = trace
    .borrow()
    .iter()
    .filter(|(name, call)| *name == "b" && *call != Call::Read)
    .map(|&(_, call)| call)
    .collect();
  assert_eq!(b_writes, [Call::Write, Call::Flush, Call::Shutdown]);
  // The reverse direction delivered its first bytes and is still running.
  assert_eq!(copy.a.written, b"wo");
  assert_eq!(copy.transferred(), (5, 2));
  assert_eq!(count(&trace, "a", Call::Shutdown), 0);

  let reads_from_a = count(&trace, "a", Call::Read);
  assert!(matches!(poll(&mut copy, &waker), Poll::Ready(Ok((5, 5)))));
  assert_eq!(copy.a.written, b"world");
  // The finished direction neither reads again nor repeats its shutdown.
  assert_eq!(count(&trace, "a", Call::Read), reads_from_a);
  assert_eq!(count(&trace, "b", Call::Shutdown), 1);
  assert_eq!(count(&trace, "a", Call::Shutdown), 1);
  assert_eq!(wakes(&wake), 0);
}

#[test]
fn delayed_flush_and_shutdown_resume_without_repeating_completed_phases() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Bytes(b"ab"), ReadStep::Eof]);
  let mut b = Endpoint::new("b", &trace)
    .reads([
      ReadStep::Bytes(b"x"),
      ReadStep::Pending,
      ReadStep::Bytes(b"yz"),
      ReadStep::Eof,
    ])
    .flushes([UnitStep::Pending, UnitStep::Done])
    .shutdowns([
      UnitStep::Pending,
      UnitStep::Fail(ErrorKind::Interrupted),
      UnitStep::Done,
    ]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  // The A to B flush waits; B to A copies its first byte and waits to read.
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(copy.a_to_b.phase, Phase::Flushing);
  assert!(
    copy
      .b
      .write_waker
      .as_ref()
      .is_some_and(|w| w.will_wake(&waker))
  );
  assert_eq!(copy.a.written, b"x");

  // The flush completes and the shutdown waits; the reverse direction keeps
  // copying, reaches EOF and shuts A down while B's shutdown is pending.
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(copy.a_to_b.phase, Phase::ShuttingDown);
  assert_eq!(copy.b_to_a.phase, Phase::Done);
  assert_eq!(copy.a.written, b"xyz");
  assert_eq!(count(&trace, "b", Call::Flush), 2);
  assert_eq!(count(&trace, "b", Call::Shutdown), 1);

  // The shutdown retries an interruption, and the finished flush is not
  // polled again.
  assert!(matches!(poll(&mut copy, &waker), Poll::Ready(Ok((2, 3)))));
  assert_eq!(count(&trace, "b", Call::Flush), 2);
  assert_eq!(count(&trace, "b", Call::Shutdown), 3);
  assert_eq!(count(&trace, "a", Call::Read), 2);
  assert_eq!(count(&trace, "a", Call::Shutdown), 1);
  assert_eq!(wakes(&wake), 0);
}

#[test]
fn both_directions_pending_keep_both_wakers_without_a_self_wake() {
  let trace = new_trace();
  let mut a =
    Endpoint::new("a", &trace).reads([ReadStep::Pending, ReadStep::Bytes(b"1"), ReadStep::Eof]);
  let mut b =
    Endpoint::new("b", &trace).reads([ReadStep::Pending, ReadStep::Bytes(b"2"), ReadStep::Eof]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(wakes(&wake), 0);
  assert_eq!(calls(&trace), 2, "each blocked direction is polled once");
  assert!(
    copy
      .a
      .read_waker
      .as_ref()
      .is_some_and(|w| w.will_wake(&waker))
  );
  assert!(
    copy
      .b
      .read_waker
      .as_ref()
      .is_some_and(|w| w.will_wake(&waker))
  );

  assert!(matches!(poll(&mut copy, &waker), Poll::Ready(Ok((1, 1)))));
  assert_eq!(copy.a.written, b"2");
  assert_eq!(copy.b.written, b"1");
  assert_eq!(wakes(&wake), 0);
}

#[test]
fn a_ready_hot_direction_lets_the_reverse_copy_and_finish_in_one_bounded_poll() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).read_forever(ReadStep::Bytes(b"hot"));
  let mut b = Endpoint::new("b", &trace).reads([ReadStep::Bytes(b"r"), ReadStep::Eof]);
  let (mut a_to_b, mut b_to_a) = ([0; 3], [0; 3]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(calls(&trace), POLL_BUDGET);
  assert_eq!(wakes(&wake), 1, "an exhausted budget wakes once");
  // Read, write, EOF read, flush and shutdown all fit in the same poll.
  assert_eq!(copy.b_to_a.phase, Phase::Done);
  assert_eq!(copy.a.written, b"r");
  assert_eq!(count(&trace, "a", Call::Shutdown), 1);
  assert_eq!(copy.transferred().1, 1);
  // A to B used the rest of the budget: alternating reads and writes.
  assert_eq!(
    count(&trace, "a", Call::Read) + count(&trace, "b", Call::Write),
    POLL_BUDGET - 5
  );

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(calls(&trace), 2 * POLL_BUDGET);
  assert_eq!(wakes(&wake), 2);
  assert_eq!(count(&trace, "a", Call::Shutdown), 1);
}

#[test]
fn two_hot_directions_alternate_calls_and_split_the_budget() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).read_forever(ReadStep::Bytes(b"a"));
  let mut b = Endpoint::new("b", &trace).read_forever(ReadStep::Bytes(b"b"));
  let (mut a_to_b, mut b_to_a) = ([0; 1], [0; 1]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(wakes(&wake), 1);
  assert_eq!(
    calls_since(&trace, 0)[..4],
    [
      ("a", Call::Read),
      ("b", Call::Read),
      ("b", Call::Write),
      ("a", Call::Write),
    ]
  );
  let half = (POLL_BUDGET / 2) as u64;
  assert_eq!(copy.transferred(), (half / 2, half / 2));
}

#[test]
fn the_next_direction_starts_the_following_poll() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).read_forever(ReadStep::Bytes(b"x"));
  let mut b =
    Endpoint::new("b", &trace).reads([ReadStep::Pending, ReadStep::Bytes(b"r"), ReadStep::Eof]);
  let (mut a_to_b, mut b_to_a) = ([0; 1], [0; 1]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  // B to A blocks on its second call; A to B makes the rest, ending its turn.
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(wakes(&wake), 1);
  assert_eq!(calls(&trace), POLL_BUDGET);
  assert_eq!(count(&trace, "b", Call::Read), 1);

  let start = calls(&trace);
  assert!(poll(&mut copy, &waker).is_pending());
  let second = calls_since(&trace, start);
  assert_eq!(second[0], ("b", Call::Read), "B to A goes first");
  assert_eq!(second.len(), POLL_BUDGET);
  assert_eq!(copy.a.written, b"r");
}

#[test]
fn interrupted_calls_count_against_the_shared_budget() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).read_forever(ReadStep::Fail(ErrorKind::Interrupted));
  let mut b = Endpoint::new("b", &trace).read_forever(ReadStep::Fail(ErrorKind::Interrupted));
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(calls(&trace), POLL_BUDGET);
  assert_eq!(count(&trace, "a", Call::Read), POLL_BUDGET / 2);
  assert_eq!(wakes(&wake), 1);
  assert_eq!(copy.transferred(), (0, 0));
}

#[test]
fn invalid_counts_fail_before_the_count_is_used() {
  let cases: [(ReadStep, WriteStep, ErrorKind, std::ops::Range<usize>); 3] = [
    (
      ReadStep::Count(5),
      WriteStep::All,
      ErrorKind::InvalidData,
      0..0,
    ),
    (
      ReadStep::Bytes(b"abc"),
      WriteStep::Count(4),
      ErrorKind::InvalidData,
      0..3,
    ),
    (
      ReadStep::Bytes(b"abc"),
      WriteStep::Up(0),
      ErrorKind::WriteZero,
      0..3,
    ),
  ];
  for (read, write, kind, unwritten) in cases {
    let trace = new_trace();
    let mut a = Endpoint::new("a", &trace).reads([read]);
    let mut b = Endpoint::new("b", &trace).writes([write]);
    let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
    let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
    let (_, waker) = counting_waker();
    let Poll::Ready(Err(error)) = poll(&mut copy, &waker) else {
      panic!("an invalid count must fail");
    };
    assert_eq!(error.kind(), kind);
    assert_eq!(copy.transferred(), (0, 0));
    assert_eq!(copy.unwritten(), (unwritten, 0..0));
    assert!(copy.b.written.is_empty());
  }
}

#[test]
fn an_error_ends_both_directions_and_keeps_the_opposite_unwritten_bytes() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace)
    .reads([ReadStep::Bytes(b"data")])
    .writes([WriteStep::Up(2)]);
  let mut b = Endpoint::new("b", &trace)
    .reads([
      ReadStep::Bytes(b"pong"),
      ReadStep::Fail(ErrorKind::ConnectionReset),
    ])
    .writes([WriteStep::Pending]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  let Poll::Ready(Err(error)) = poll(&mut copy, &waker) else {
    panic!("the reset must end the copy");
  };
  assert_eq!(error.kind(), ErrorKind::ConnectionReset);
  assert_eq!(
    calls_since(&trace, 0),
    [
      ("a", Call::Read),
      ("b", Call::Read),
      ("b", Call::Write),
      ("a", Call::Write),
      ("a", Call::Write),
      ("b", Call::Read),
    ]
  );
  assert_eq!(copy.transferred(), (0, 4));
  assert_eq!(copy.unwritten(), (0..4, 0..0));
  assert_eq!(copy.a.written, b"pong");
  assert_eq!(wakes(&wake), 0);
  drop(copy);
  assert_eq!(&a_to_b, b"data");
}

#[test]
fn non_interrupted_errors_are_not_retried() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Eof]);
  let mut b = Endpoint::new("b", &trace).flushes([UnitStep::Fail(ErrorKind::BrokenPipe)]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (_, waker) = counting_waker();

  let Poll::Ready(Err(error)) = poll(&mut copy, &waker) else {
    panic!("a failed flush must end the copy");
  };
  assert_eq!(error.kind(), ErrorKind::BrokenPipe);
  assert_eq!(count(&trace, "b", Call::Flush), 1);
  assert_eq!(count(&trace, "b", Call::Shutdown), 0);

  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Bytes(b"z")]);
  let mut b = Endpoint::new("b", &trace).writes([WriteStep::Fail(ErrorKind::WouldBlock)]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let Poll::Ready(Err(error)) = poll(&mut copy, &waker) else {
    panic!("WouldBlock must end the copy");
  };
  assert_eq!(error.kind(), ErrorKind::WouldBlock);
  assert_eq!(count(&trace, "b", Call::Write), 1);
  assert_eq!(copy.unwritten(), (0..1, 0..0));
}

#[test]
fn a_waiting_source_flushes_accepted_writes_and_keeps_its_waker() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([
    ReadStep::Bytes(b"ab"),
    ReadStep::Pending,
    ReadStep::Pending,
    ReadStep::Pending,
    ReadStep::Bytes(b"c"),
    ReadStep::Eof,
  ]);
  let mut b = Endpoint::new("b", &trace)
    .reads([ReadStep::Eof])
    .flushes([UnitStep::Pending, UnitStep::Done]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  // A waits after "ab" was written: B is flushed once, and A is not read
  // again in the same poll.
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(count(&trace, "a", Call::Read), 2);
  assert_eq!(count(&trace, "b", Call::Flush), 1);
  assert!(
    copy
      .a
      .read_waker
      .as_ref()
      .is_some_and(|w| w.will_wake(&waker))
  );
  assert!(
    copy
      .b
      .write_waker
      .as_ref()
      .is_some_and(|w| w.will_wake(&waker))
  );
  assert_eq!(copy.b_to_a.phase, Phase::Done);

  // The pending flush is retried and succeeds before A is read again.
  let start = calls(&trace);
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(
    calls_since(&trace, start),
    [("b", Call::Flush), ("a", Call::Read)]
  );
  assert_eq!(count(&trace, "a", Call::Read), 3);
  assert_eq!(count(&trace, "b", Call::Flush), 2);

  // Nothing is left to flush, so a waiting A does not flush B.
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(count(&trace, "a", Call::Read), 4);
  assert_eq!(count(&trace, "b", Call::Flush), 2);

  assert!(matches!(poll(&mut copy, &waker), Poll::Ready(Ok((3, 0)))));
  assert_eq!(copy.b.written, b"abc");
  assert_eq!(count(&trace, "b", Call::Flush), 3);
  assert_eq!(wakes(&wake), 0);
}

#[test]
fn a_flush_owed_at_the_last_budgeted_call_runs_before_the_next_read() {
  let trace = new_trace();
  // With B to A blocked on its first read, A's reads are calls 1 and every
  // even call from 4, so its 32nd read is the poll's last budgeted call.
  let reads = std::iter::repeat_n(ReadStep::Bytes(b"x"), 31).chain([ReadStep::Pending]);
  let mut a = Endpoint::new("a", &trace)
    .reads(reads)
    .read_forever(ReadStep::Bytes(b"y"));
  let mut b = Endpoint::new("b", &trace);
  let (mut a_to_b, mut b_to_a) = ([0; 1], [0; 1]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(calls(&trace), POLL_BUDGET);
  assert_eq!(trace.borrow().last(), Some(&("a", Call::Read)));
  assert_eq!(count(&trace, "a", Call::Read), 32);
  assert_eq!(count(&trace, "b", Call::Flush), 0);
  assert_eq!(wakes(&wake), 1, "the exhausted budget wakes once");
  assert!(copy.a_to_b.flush_owed);

  // A is ready again, but the owed flush is A to B's first call.
  let start = calls(&trace);
  assert!(poll(&mut copy, &waker).is_pending());
  let second = calls_since(&trace, start);
  assert_eq!(
    second[..4],
    [
      ("b", Call::Read),
      ("b", Call::Flush),
      ("a", Call::Read),
      ("b", Call::Write),
    ]
  );
  assert_eq!(second.len(), POLL_BUDGET);
  assert_eq!(count(&trace, "b", Call::Flush), 1);
  assert!(!copy.a_to_b.flush_owed);
  assert_eq!(wakes(&wake), 2);
  assert_eq!(copy.transferred().0, 31 + 31);
}

#[test]
fn a_pending_owed_flush_is_kept_while_its_source_is_ready() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([
    ReadStep::Bytes(b"ab"),
    ReadStep::Pending,
    ReadStep::Bytes(b"c"),
    ReadStep::Eof,
  ]);
  let mut b =
    Endpoint::new("b", &trace).flushes([UnitStep::Pending, UnitStep::Pending, UnitStep::Done]);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(count(&trace, "a", Call::Read), 2);
  assert_eq!(count(&trace, "b", Call::Flush), 1);
  assert!(copy.a_to_b.flush_owed);

  // A would now yield "c", but the flush is still pending, so A is not read.
  let start = calls(&trace);
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(
    calls_since(&trace, start),
    [("b", Call::Read), ("b", Call::Flush)]
  );
  assert!(copy.a_to_b.flush_owed);
  assert_eq!(copy.b.written, b"ab");

  // Once the flush succeeds A is read in the same poll, and its EOF flushes
  // and shuts down B while B to A keeps waiting.
  let start = calls(&trace);
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(
    calls_since(&trace, start),
    [
      ("b", Call::Read),
      ("b", Call::Flush),
      ("a", Call::Read),
      ("b", Call::Write),
      ("a", Call::Read),
      ("b", Call::Flush),
      ("b", Call::Shutdown),
    ]
  );
  assert!(!copy.a_to_b.flush_owed);
  assert_eq!(copy.a_to_b.phase, Phase::Done);
  assert_eq!(copy.b.written, b"abc");
  assert_eq!(copy.transferred(), (3, 0));
  assert_eq!(count(&trace, "b", Call::Shutdown), 1);
  assert_eq!(wakes(&wake), 0, "blocked directions never self-wake");
}

#[test]
fn cancellation_keeps_counts_and_unwritten_ranges_in_the_caller_slices() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace)
    .reads([ReadStep::Bytes(b"hello")])
    .writes([WriteStep::Up(1), WriteStep::Pending]);
  let mut b = Endpoint::new("b", &trace)
    .reads([ReadStep::Bytes(b"xyz")])
    .writes([WriteStep::Up(2), WriteStep::Pending]);
  let (mut a_to_b, mut b_to_a) = ([0; 8], [0; 8]);
  let (transferred, unwritten) = {
    let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
    let (_, waker) = counting_waker();
    assert!(poll(&mut copy, &waker).is_pending());
    (copy.transferred(), copy.unwritten())
  };
  assert_eq!(transferred, (2, 1));
  assert_eq!(unwritten, (2..5, 1..3));
  assert_eq!(&a_to_b[unwritten.0], b"llo");
  assert_eq!(&b_to_a[unwritten.1], b"yz");
  assert_eq!(b.written, b"he");
  assert_eq!(a.written, b"x");
}

#[test]
fn a_pending_shutdown_is_retried_and_cancellation_keeps_the_flush() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Bytes(b"ab"), ReadStep::Eof]);
  let mut b = Endpoint::new("b", &trace).shutdown_forever(UnitStep::Pending);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (wake, waker) = counting_waker();

  assert!(poll(&mut copy, &waker).is_pending());
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(count(&trace, "b", Call::Flush), 1);
  assert_eq!(count(&trace, "b", Call::Shutdown), 2);
  assert_eq!(count(&trace, "a", Call::Read), 2);
  assert_eq!(copy.a_to_b.phase, Phase::ShuttingDown);
  assert_eq!(copy.transferred(), (2, 0));
  assert_eq!(wakes(&wake), 0);
  drop(copy);
  assert_eq!(b.written, b"ab");
}

#[test]
fn transferred_counts_saturate() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Bytes(b"abc")]);
  let mut b = Endpoint::new("b", &trace);
  let (mut a_to_b, mut b_to_a) = ([0; 4], [0; 4]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  copy.a_to_b.transferred = u64::MAX - 1;
  let (_, waker) = counting_waker();
  assert!(poll(&mut copy, &waker).is_pending());
  assert_eq!(copy.transferred(), (u64::MAX, 0));
}

#[test]
#[should_panic(expected = "CopyBidirectional polled after completion")]
fn polling_after_completion_panics() {
  let trace = new_trace();
  let mut a = Endpoint::new("a", &trace).reads([ReadStep::Eof]);
  let mut b = Endpoint::new("b", &trace).reads([ReadStep::Eof]);
  let (mut a_to_b, mut b_to_a) = ([0; 1], [0; 1]);
  let mut copy = copy_bidirectional_with_buffers(&mut a, &mut b, &mut a_to_b, &mut b_to_a);
  let (_, waker) = counting_waker();
  assert!(matches!(poll(&mut copy, &waker), Poll::Ready(Ok((0, 0)))));
  let _ = poll(&mut copy, &waker);
}

#[test]
fn loopback_tcp_relay_half_closes_each_direction_independently() {
  use std::io::{Read, Write};
  use std::net::{Shutdown, TcpListener, TcpStream as StdTcpStream};
  use std::thread;
  use std::time::{Duration, Instant};

  use crate::runtime::net::TcpStream;
  use crate::runtime::reactor::{Reactor, ReactorConfig};

  const TIMEOUT: Duration = Duration::from_secs(10);

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 4,
    max_waiters: 16,
  })
  .unwrap();
  let handle = reactor.handle();
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  let mut client = StdTcpStream::connect_timeout(&address, TIMEOUT).unwrap();
  let (client_side, _) = listener.accept().unwrap();
  let mut server = StdTcpStream::connect_timeout(&address, TIMEOUT).unwrap();
  let (server_side, _) = listener.accept().unwrap();
  for peer in [&client, &server] {
    peer.set_read_timeout(Some(TIMEOUT)).unwrap();
    peer.set_write_timeout(Some(TIMEOUT)).unwrap();
  }
  let mut a = TcpStream::from_std(client_side, &handle).unwrap();
  let mut b = TcpStream::from_std(server_side, &handle).unwrap();

  let request: Vec<u8> = (0..300_000u32).map(|index| (index % 251) as u8).collect();
  let response: Vec<u8> = (0..200_000u32).map(|index| (index % 241) as u8).collect();
  let sent_request = request.clone();
  let client = thread::spawn(move || {
    client.write_all(&sent_request).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap();
    received
  });
  let sent_response = response.clone();
  let server = thread::spawn(move || {
    // The server replies only after the relay forwarded the client's EOF.
    let mut received = Vec::new();
    server.read_to_end(&mut received).unwrap();
    server.write_all(&sent_response).unwrap();
    server.shutdown(Shutdown::Write).unwrap();
    received
  });

  let (mut a_to_b, mut b_to_a) = ([0; 4096], [0; 1024]);
  let mut copy = pin!(copy_bidirectional_with_buffers(
    &mut a,
    &mut b,
    &mut a_to_b,
    &mut b_to_a
  ));
  let mut context = Context::from_waker(Waker::noop());
  let deadline = Instant::now() + TIMEOUT;
  let copied = loop {
    match copy.as_mut().poll(&mut context) {
      Poll::Ready(result) => break result.unwrap(),
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "relay exceeded its test deadline"
        );
        thread::sleep(Duration::from_millis(1));
      }
    }
  };

  assert_eq!(copied, (request.len() as u64, response.len() as u64));
  assert_eq!(server.join().unwrap(), request);
  assert_eq!(client.join().unwrap(), response);
}
