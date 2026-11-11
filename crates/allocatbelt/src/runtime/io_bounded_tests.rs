use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::runtime::buffered_io::AsyncBufRead;
use crate::runtime::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BoundedReadStop, POLL_BUDGET};

#[derive(Clone, Copy)]
enum Step {
  Data,
  Pending,
  Interrupted,
  Error(ErrorKind),
}

struct ScriptReader {
  bytes: Vec<u8>,
  position: usize,
  max_chunk: usize,
  steps: VecDeque<Step>,
  calls: Rc<Cell<usize>>,
}

impl ScriptReader {
  fn new(bytes: &[u8], max_chunk: usize) -> Self {
    Self {
      bytes: bytes.to_vec(),
      position: 0,
      max_chunk,
      steps: VecDeque::new(),
      calls: Rc::new(Cell::new(0)),
    }
  }

  fn with_steps(mut self, steps: impl IntoIterator<Item = Step>) -> Self {
    self.steps.extend(steps);
    self
  }

  fn remaining(&self) -> &[u8] {
    &self.bytes[self.position..]
  }

  fn step(&mut self) -> Poll<io::Result<()>> {
    self.calls.set(self.calls.get() + 1);
    match self.steps.pop_front().unwrap_or(Step::Data) {
      Step::Data => Poll::Ready(Ok(())),
      Step::Pending => Poll::Pending,
      Step::Interrupted => Poll::Ready(Err(ErrorKind::Interrupted.into())),
      Step::Error(kind) => Poll::Ready(Err(kind.into())),
    }
  }
}

impl AsyncRead for ScriptReader {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    match self.step() {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => {
        if output.is_empty() {
          return Poll::Ready(Ok(0));
        }
        let count = output
          .len()
          .min(self.max_chunk)
          .min(self.bytes.len() - self.position);
        output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(count))
      }
    }
  }
}

impl AsyncBufRead for ScriptReader {
  fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.get_mut();
    match this.step() {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => {
        let end = this
          .position
          .saturating_add(this.max_chunk)
          .min(this.bytes.len());
        Poll::Ready(Ok(&this.bytes[this.position..end]))
      }
    }
  }

  fn consume(self: Pin<&mut Self>, amount: usize) {
    let this = self.get_mut();
    let available = this.max_chunk.min(this.bytes.len() - this.position);
    this.position += amount.min(available);
  }
}

struct BadCount;

impl AsyncRead for BadCount {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(output.len() + 1))
  }
}

struct CountingWake(AtomicUsize);

impl std::task::Wake for CountingWake {
  fn wake(self: Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
  let mut cx = Context::from_waker(Waker::noop());
  Pin::new(future).poll(&mut cx)
}

fn run<F: Future>(future: F) -> F::Output {
  let mut future = pin_box(future);
  for _ in 0..10_000 {
    let mut cx = Context::from_waker(Waker::noop());
    if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
      return output;
    }
  }
  panic!("bounded read did not finish")
}

// Keep the polling helper safe and independent of a runtime.
fn pin_box<F: Future>(future: F) -> Pin<Box<F>> {
  Box::pin(future)
}

#[test]
fn read_until_copies_through_delimiter_and_keeps_the_buffered_tail() {
  let mut reader = ScriptReader::new(b"head\ntail", 32);
  let mut output = [0; 5];
  let result = run(reader.read_until_bounded(b'\n', &mut output)).unwrap();
  assert_eq!(result.filled, 5);
  assert_eq!(result.stop, BoundedReadStop::Delimiter);
  assert_eq!(&output, b"head\n");
  assert_eq!(reader.remaining(), b"tail");
}

#[test]
fn delimiter_at_last_capacity_byte_wins_without_an_extra_poll() {
  let mut reader = ScriptReader::new(b"abc\nrest", 64);
  let mut output = [0; 4];
  let result = run(reader.read_until_bounded(b'\n', &mut output)).unwrap();
  assert_eq!(result.stop, BoundedReadStop::Delimiter);
  assert_eq!(reader.calls.get(), 1);
  assert_eq!(reader.remaining(), b"rest");
}

#[test]
fn exact_full_is_capacity_even_when_eof_would_be_next() {
  let mut reader = ScriptReader::new(b"abc", 8);
  let mut output = [0; 3];
  let result = run(reader.read_to_end_bounded(&mut output)).unwrap();
  assert_eq!(
    result,
    crate::runtime::io::BoundedRead {
      filled: 3,
      stop: BoundedReadStop::Capacity
    }
  );
  assert_eq!(reader.calls.get(), 1);
  assert!(reader.remaining().is_empty());
}

#[test]
fn empty_destination_is_capacity_without_polling() {
  let mut read = ScriptReader::new(b"x", 1);
  let mut bytes = [];
  let result = run(read.read_to_end_bounded(&mut bytes)).unwrap();
  assert_eq!(result.filled, 0);
  assert_eq!(result.stop, BoundedReadStop::Capacity);
  assert_eq!(read.calls.get(), 0);

  let mut buffered = ScriptReader::new(b"x", 1);
  let result = run(buffered.read_until_bounded(b'\n', &mut bytes)).unwrap();
  assert_eq!(result.stop, BoundedReadStop::Capacity);
  assert_eq!(buffered.calls.get(), 0);
  assert_eq!(buffered.remaining(), b"x");

  let mut string_reader = ScriptReader::new(b"x", 1);
  let result = run(string_reader.read_to_string_bounded(&mut bytes)).unwrap();
  assert_eq!(result.filled, 0);
  assert_eq!(result.stop, BoundedReadStop::Capacity);
  assert_eq!(string_reader.calls.get(), 0);

  let mut line_reader = ScriptReader::new(b"x", 1);
  let result = run(line_reader.read_line_bounded(&mut bytes)).unwrap();
  assert_eq!(result.filled, 0);
  assert_eq!(result.stop, BoundedReadStop::Capacity);
  assert_eq!(line_reader.calls.get(), 0);
}

#[test]
fn arbitrary_chunks_and_eof_are_reported_separately() {
  let mut reader = ScriptReader::new(b"abcdef", 2);
  let mut output = [0; 8];
  let result = run(reader.read_to_end_bounded(&mut output)).unwrap();
  assert_eq!(result.filled, 6);
  assert_eq!(result.stop, BoundedReadStop::Eof);
  assert_eq!(&output[..6], b"abcdef");
}

#[test]
fn pending_and_cancellation_preserve_filled_bytes_and_unread_tail() {
  let mut reader = ScriptReader::new(b"ab\nrest", 2).with_steps([Step::Data, Step::Pending]);
  let mut output = [0; 8];
  {
    let mut future = reader.read_until_bounded(b'\n', &mut output);
    assert!(poll_once(&mut future).is_pending());
    assert_eq!(future.filled(), 2);
  }
  assert_eq!(&output[..2], b"ab");
  assert_eq!(reader.remaining(), b"\nrest");
}

#[test]
fn whole_stream_pending_and_cancellation_keep_filled_prefix() {
  let mut reader = ScriptReader::new(b"abcdef", 2).with_steps([Step::Data, Step::Pending]);
  let mut output = [0; 8];
  {
    let mut future = reader.read_to_end_bounded(&mut output);
    assert!(poll_once(&mut future).is_pending());
    assert_eq!(future.filled(), 2);
  }
  assert_eq!(&output[..2], b"ab");
  assert_eq!(reader.remaining(), b"cdef");
}

#[test]
fn endpoint_error_carries_partial_progress_without_consuming_later_bytes() {
  let mut reader =
    ScriptReader::new(b"abcdef", 2).with_steps([Step::Data, Step::Error(ErrorKind::BrokenPipe)]);
  let mut output = [0; 8];
  let error = run(reader.read_until_bounded(b'\n', &mut output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::BrokenPipe);
  assert_eq!(error.filled(), 2);
  assert_eq!(&output[..2], b"ab");
  assert_eq!(reader.remaining(), b"cdef");
}

#[test]
fn interrupted_buffered_calls_count_toward_the_same_poll_budget() {
  let mut reader =
    ScriptReader::new(b"x\n", 2).with_steps(std::iter::repeat_n(Step::Interrupted, POLL_BUDGET));
  let calls = Rc::clone(&reader.calls);
  let mut output = [0; 4];
  let mut future = reader.read_until_bounded(b'\n', &mut output);
  assert!(poll_once(&mut future).is_pending());
  assert_eq!(calls.get(), POLL_BUDGET);
  assert_eq!(future.filled(), 0);
  let Poll::Ready(Ok(read)) = poll_once(&mut future) else {
    panic!("expected delimiter after interrupted calls")
  };
  assert_eq!(read.filled, 2);
  assert_eq!(read.stop, BoundedReadStop::Delimiter);
  assert_eq!(calls.get(), POLL_BUDGET + 1);
}

#[test]
fn sixty_four_ready_read_polls_self_wake_before_pending() {
  let mut reader = ScriptReader::new(&[b'x'; 100], 1);
  let calls = Rc::clone(&reader.calls);
  let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&wake_count));
  let mut cx = Context::from_waker(&waker);
  let mut output = [0; 101];
  let mut future = reader.read_to_end_bounded(&mut output);

  assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
  assert_eq!(calls.get(), POLL_BUDGET);
  assert_eq!(future.filled(), POLL_BUDGET);
  assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);

  let Poll::Ready(Ok(read)) = Pin::new(&mut future).poll(&mut cx) else {
    panic!("expected EOF after the remaining bytes")
  };
  assert_eq!(read.filled, 100);
  assert_eq!(read.stop, BoundedReadStop::Eof);
  assert_eq!(calls.get(), 101);
  assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn sixty_four_ready_buffer_fills_self_wake_before_pending() {
  let mut reader = ScriptReader::new(&[b'x'; 100], 1);
  let calls = Rc::clone(&reader.calls);
  let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&wake_count));
  let mut cx = Context::from_waker(&waker);
  let mut output = [0; 101];
  let mut future = reader.read_until_bounded(b'\n', &mut output);

  assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
  assert_eq!(calls.get(), POLL_BUDGET);
  assert_eq!(future.filled(), POLL_BUDGET);
  assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);

  let Poll::Ready(Ok(read)) = Pin::new(&mut future).poll(&mut cx) else {
    panic!("expected EOF after the remaining buffered bytes")
  };
  assert_eq!(read.filled, 100);
  assert_eq!(read.stop, BoundedReadStop::Eof);
  assert_eq!(calls.get(), 101);
  assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn interrupted_calls_count_toward_per_poll_budget() {
  let mut reader =
    ScriptReader::new(b"x", 1).with_steps(std::iter::repeat_n(Step::Interrupted, POLL_BUDGET));
  let calls = Rc::clone(&reader.calls);
  let mut output = [0; 2];
  let mut future = reader.read_to_end_bounded(&mut output);
  assert!(poll_once(&mut future).is_pending());
  assert_eq!(calls.get(), POLL_BUDGET);
  assert_eq!(future.filled(), 0);
  let Poll::Ready(Ok(read)) = poll_once(&mut future) else {
    panic!("expected EOF after interrupted calls")
  };
  assert_eq!(read.filled, 1);
  assert_eq!(read.stop, BoundedReadStop::Eof);
  assert_eq!(calls.get(), POLL_BUDGET + 2);
}

#[test]
fn overreported_scalar_read_count_is_invalid_data_without_slicing() {
  let mut reader = BadCount;
  let mut output = [0; 3];
  let error = run(reader.read_to_end_bounded(&mut output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(error.filled(), 0);
}

#[test]
fn line_read_includes_crlf_and_accepts_utf8_split_across_chunks() {
  let mut reader = ScriptReader::new("hé\r\nnext".as_bytes(), 1);
  let mut output = [0; 16];
  let result = run(reader.read_line_bounded(&mut output)).unwrap();
  assert_eq!(result.stop, BoundedReadStop::Delimiter);
  assert_eq!(std::str::from_utf8(&output[..result.filled]), Ok("hé\r\n"));
  assert_eq!(reader.remaining(), b"next");
}

#[test]
fn string_read_validates_utf8_at_eof_and_preserves_bytes_on_failure() {
  let mut valid = ScriptReader::new("aé".as_bytes(), 1);
  let mut output = [0; 8];
  let result = run(valid.read_to_string_bounded(&mut output)).unwrap();
  assert_eq!(result.stop, BoundedReadStop::Eof);
  assert_eq!(std::str::from_utf8(&output[..result.filled]), Ok("aé"));

  let mut invalid = ScriptReader::new(b"a\xffz", 2);
  let mut invalid_output = [0; 2];
  let error = run(invalid.read_to_string_bounded(&mut invalid_output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(error.filled(), 2);
  assert_eq!(&invalid_output, b"a\xff");
  assert_eq!(invalid.remaining(), b"z");
}

#[test]
fn capacity_cutting_a_utf8_sequence_is_invalid_data_with_progress() {
  let mut reader = ScriptReader::new("é\n".as_bytes(), 8);
  let mut output = [0; 1];
  let error = run(reader.read_line_bounded(&mut output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(error.filled(), 1);
  assert_eq!(output, [0xc3]);
  assert_eq!(reader.remaining(), b"\xa9\n");
}

#[test]
fn buffered_partial_utf8_is_retained_on_pending_and_utf8_error_is_later() {
  let mut reader = ScriptReader::new("é\n".as_bytes(), 1).with_steps([Step::Data, Step::Pending]);
  let mut output = [0; 3];
  {
    let mut future = reader.read_line_bounded(&mut output);
    assert!(poll_once(&mut future).is_pending());
    assert_eq!(future.filled(), 1);
  }
  assert_eq!(reader.remaining(), b"\xa9\n");

  let mut reader = ScriptReader::new("é\n".as_bytes(), 8);
  let mut output = [0; 1];
  let error = run(reader.read_line_bounded(&mut output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidData);
}

#[test]
fn io_error_after_invalid_prefix_keeps_io_error_kind_and_partial_bytes() {
  let mut reader =
    ScriptReader::new(b"\xfftail", 1).with_steps([Step::Data, Step::Error(ErrorKind::BrokenPipe)]);
  let mut output = [0; 8];
  let error = run(reader.read_to_string_bounded(&mut output)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::BrokenPipe);
  assert_eq!(error.filled(), 1);
  assert_eq!(output[0], 0xff);
  assert_eq!(reader.remaining(), b"tail");
}
