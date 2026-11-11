use std::collections::VecDeque;
use std::future::Future;
use std::io::{ErrorKind, IoSliceMut};
use std::task::Waker;

use super::*;
use crate::runtime::io::{AsyncReadExt, AsyncWriteExt, SliceReader, copy_with_buffer};

struct Buffered {
  bytes: &'static [u8],
  position: usize,
  pending: usize,
  errors: usize,
  calls: usize,
  consumed: usize,
}

impl Buffered {
  fn new(bytes: &'static [u8]) -> Self {
    Self {
      bytes,
      position: 0,
      pending: 0,
      errors: 0,
      calls: 0,
      consumed: 0,
    }
  }

  fn scripted(bytes: &'static [u8], pending: usize, errors: usize) -> Self {
    Self {
      pending,
      errors,
      ..Self::new(bytes)
    }
  }
}

impl AsyncRead for Buffered {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    if output.is_empty() {
      return Poll::Ready(Ok(0));
    }
    match self.as_mut().poll_fill_buf(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(bytes)) => {
        let count = output.len().min(bytes.len());
        output[..count].copy_from_slice(&bytes[..count]);
        self.consume(count);
        Poll::Ready(Ok(count))
      }
    }
  }
}

impl AsyncBufRead for Buffered {
  fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.get_mut();
    this.calls += 1;
    if this.pending != 0 {
      this.pending -= 1;
      return Poll::Pending;
    }
    if this.errors != 0 {
      this.errors -= 1;
      return Poll::Ready(Err(ErrorKind::Interrupted.into()));
    }
    Poll::Ready(Ok(&this.bytes[this.position..]))
  }

  fn consume(self: Pin<&mut Self>, amount: usize) {
    let this = self.get_mut();
    let consumed = amount.min(this.bytes.len() - this.position);
    this.position += consumed;
    this.consumed += consumed;
  }
}

fn fill<R: AsyncBufRead + Unpin>(reader: &mut R) -> Poll<io::Result<&[u8]>> {
  Pin::new(reader).poll_fill_buf(&mut Context::from_waker(Waker::noop()))
}

fn filled<R: AsyncBufRead + Unpin>(reader: &mut R) -> &[u8] {
  match fill(reader) {
    Poll::Ready(Ok(bytes)) => bytes,
    other => panic!("expected ready buffered bytes: {other:?}"),
  }
}

fn read<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Poll<io::Result<usize>> {
  Pin::new(reader).poll_read(&mut Context::from_waker(Waker::noop()), buf)
}

fn count(result: Poll<io::Result<usize>>) -> usize {
  match result {
    Poll::Ready(Ok(count)) => count,
    other => panic!("expected a ready count: {other:?}"),
  }
}

enum Step {
  Pending,
  Error,
  Count(usize),
}

struct Scripted {
  steps: VecDeque<Step>,
  calls: usize,
}

impl Scripted {
  fn new(steps: impl IntoIterator<Item = Step>) -> Self {
    Self {
      steps: steps.into_iter().collect(),
      calls: 0,
    }
  }
}

impl AsyncRead for Scripted {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    this.calls += 1;
    match this.steps.pop_front().expect("unexpected endpoint poll") {
      Step::Pending => Poll::Pending,
      Step::Error => Poll::Ready(Err(ErrorKind::Interrupted.into())),
      Step::Count(count) => Poll::Ready(Ok(count)),
    }
  }
}

#[test]
fn take_caps_reads_and_recovers_unread_bytes() {
  let mut limited = SliceReader::new(b"abcdef").take(3);
  let mut buf = [0; 8];
  assert_eq!(count(read(&mut limited, &mut buf)), 3);
  assert_eq!(&buf[..3], b"abc");
  assert_eq!(limited.limit(), 0);
  assert_eq!(count(read(&mut limited, &mut buf)), 0);
  let mut original = limited.into_inner();
  assert_eq!(count(read(&mut original, &mut buf)), 3);
  assert_eq!(&buf[..3], b"def");
}

#[test]
fn zero_limit_and_empty_read_do_not_poll_the_inner_reader() {
  let mut limited = Scripted::new([]).take(0);
  assert_eq!(count(read(&mut limited, &mut [0; 1])), 0);
  limited.set_limit(u64::MAX);
  assert_eq!(count(read(&mut limited, &mut [])), 0);
  assert_eq!(limited.limit(), u64::MAX);
  assert_eq!(limited.get_ref().calls, 0);
}

#[test]
fn take_pending_error_and_invalid_count_preserve_limit() {
  let mut limited = Scripted::new([Step::Pending, Step::Error, Step::Count(4)]).take(3);
  assert!(read(&mut limited, &mut [0; 8]).is_pending());
  for expected in [ErrorKind::Interrupted, ErrorKind::InvalidData] {
    let Poll::Ready(Err(error)) = read(&mut limited, &mut [0; 8]) else {
      panic!("expected error")
    };
    assert_eq!(error.kind(), expected);
    assert_eq!(limited.limit(), 3);
  }
}

#[test]
fn take_eof_keeps_limit_and_limit_can_be_replaced() {
  let mut eof = empty().take(9);
  assert_eq!(count(read(&mut eof, &mut [0; 2])), 0);
  assert_eq!(eof.limit(), 9);
  let mut limited = repeat(7).take(1);
  assert_eq!(count(read(&mut limited, &mut [0; 3])), 1);
  limited.set_limit(2);
  assert_eq!(count(read(&mut limited, &mut [0; 3])), 2);
}

#[test]
fn canceled_pending_read_does_not_spend_the_take_limit() {
  let mut limited = Scripted::new([Step::Pending, Step::Count(2)]).take(4);
  let mut buf = [0; 4];
  {
    let mut future = limited.read(&mut buf);
    assert!(
      Pin::new(&mut future)
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    );
  }
  assert_eq!(limited.limit(), 4);
  assert_eq!(count(read(&mut limited, &mut buf)), 2);
  assert_eq!(limited.limit(), 2);
}

#[test]
fn chain_empty_read_does_not_switch_and_first_eof_is_sticky() {
  let mut chained = SliceReader::new(b"a").chain(SliceReader::new(b"bc"));
  assert_eq!(count(read(&mut chained, &mut [])), 0);
  let mut buf = [0; 4];
  assert_eq!(count(read(&mut chained, &mut buf)), 1);
  assert_eq!(buf[0], b'a');
  assert_eq!(count(read(&mut chained, &mut buf)), 2);
  assert_eq!(&buf[..2], b"bc");
  *chained.get_mut().0 = SliceReader::new(b"ignored");
  assert_eq!(count(read(&mut chained, &mut buf)), 0);
  let (mut first, mut second) = chained.into_inner();
  assert_eq!(count(read(&mut first, &mut buf)), 4);
  assert_eq!(&buf, b"igno");
  assert_eq!(count(read(&mut second, &mut buf)), 0);
}

#[test]
fn chain_pending_and_error_do_not_consume_the_second_endpoint() {
  let mut chained = Scripted::new([Step::Pending, Step::Error, Step::Count(0)])
    .chain(Scripted::new([Step::Count(1)]));
  assert!(read(&mut chained, &mut [0; 2]).is_pending());
  assert_eq!(chained.get_ref().1.calls, 0);
  assert!(matches!(
    read(&mut chained, &mut [0; 2]),
    Poll::Ready(Err(_))
  ));
  assert_eq!(chained.get_ref().1.calls, 0);
  assert_eq!(count(read(&mut chained, &mut [0; 2])), 1);
  assert_eq!(chained.get_ref().0.calls, 3);
  assert_eq!(chained.get_ref().1.calls, 1);
}

#[test]
fn chain_rejects_oversized_counts_on_both_sides() {
  let mut chained =
    Scripted::new([Step::Count(3), Step::Count(0)]).chain(Scripted::new([Step::Count(3)]));
  for _ in 0..2 {
    let Poll::Ready(Err(error)) = read(&mut chained, &mut [0; 2]) else {
      panic!("expected error")
    };
    assert_eq!(error.kind(), ErrorKind::InvalidData);
  }
  assert_eq!(chained.get_ref().0.calls, 2);
  assert_eq!(chained.get_ref().1.calls, 1);
}

#[test]
fn take_bufread_clamps_visible_bytes_and_consume_to_the_remaining_limit() {
  let mut limited = Buffered::new(b"abcdef").take(3);
  let Poll::Ready(Ok(bytes)) = fill(&mut limited) else {
    panic!("expected buffered bytes")
  };
  assert_eq!(bytes, b"abc");
  Pin::new(&mut limited).consume(2);
  assert_eq!(limited.limit(), 1);

  let Poll::Ready(Ok(bytes)) = fill(&mut limited) else {
    panic!("expected the last allowed byte")
  };
  assert_eq!(bytes, b"c");
  Pin::new(&mut limited).consume(usize::MAX);
  assert_eq!(limited.limit(), 0);
  assert_eq!(limited.get_ref().consumed, 3);

  let calls = limited.get_ref().calls;
  let Poll::Ready(Ok(bytes)) = fill(&mut limited) else {
    panic!("zero limit is ready EOF")
  };
  assert!(bytes.is_empty());
  assert_eq!(limited.get_ref().calls, calls);
  Pin::new(&mut limited).consume(1);
  assert_eq!(limited.get_ref().consumed, 3);

  limited.set_limit(2);
  let Poll::Ready(Ok(bytes)) = fill(&mut limited) else {
    panic!("expected reset limit")
  };
  assert_eq!(bytes, b"de");

  let mut shortened = Buffered::new(b"abcdef").take(4);
  assert_eq!(filled(&mut shortened), b"abcd");
  shortened.set_limit(1);
  assert_eq!(filled(&mut shortened), b"a");
  Pin::new(&mut shortened).consume(usize::MAX);
  assert_eq!(shortened.limit(), 0);
  assert_eq!(shortened.get_ref().consumed, 1);
}

#[test]
fn take_bufread_pending_and_errors_preserve_limit_and_consume_state() {
  let mut limited = Buffered::scripted(b"abc", 1, 1).take(2);
  assert!(fill(&mut limited).is_pending());
  assert_eq!(limited.limit(), 2);
  let Poll::Ready(Err(error)) = fill(&mut limited) else {
    panic!("expected scripted error")
  };
  assert_eq!(error.kind(), ErrorKind::Interrupted);
  assert_eq!(limited.limit(), 2);

  let Poll::Ready(Ok(bytes)) = fill(&mut limited) else {
    panic!("expected buffered bytes")
  };
  assert_eq!(bytes, b"ab");
  Pin::new(&mut limited).consume(usize::MAX);
  assert_eq!(limited.limit(), 0);
  assert_eq!(limited.get_ref().consumed, 2);
}

#[test]
fn chain_bufread_waits_on_first_then_switches_stickily_at_eof() {
  let first = Buffered::scripted(b"x", 1, 1);
  let second = Buffered::scripted(b"yz", 0, 1);
  let mut chained = first.chain(second);

  assert!(fill(&mut chained).is_pending());
  assert_eq!(chained.get_ref().1.calls, 0);
  assert!(matches!(fill(&mut chained), Poll::Ready(Err(_))));
  assert_eq!(chained.get_ref().1.calls, 0);

  let Poll::Ready(Ok(bytes)) = fill(&mut chained) else {
    panic!("expected first endpoint data")
  };
  assert_eq!(bytes, b"x");
  Pin::new(&mut chained).consume(usize::MAX);
  assert_eq!(chained.get_ref().0.consumed, 1);

  let Poll::Ready(Err(error)) = fill(&mut chained) else {
    panic!("expected second endpoint error after sticky first EOF")
  };
  assert_eq!(error.kind(), ErrorKind::Interrupted);
  assert_eq!(chained.get_ref().0.calls, 4);

  let Poll::Ready(Ok(bytes)) = fill(&mut chained) else {
    panic!("expected second endpoint after first EOF")
  };
  assert_eq!(bytes, b"yz");
  Pin::new(&mut chained).consume(1);
  assert_eq!(chained.get_ref().1.consumed, 1);
  chained.get_mut().0.bytes = b"ignored";
  let Poll::Ready(Ok(bytes)) = fill(&mut chained) else {
    panic!("expected remaining second endpoint data")
  };
  assert_eq!(bytes, b"z");
  assert_eq!(chained.get_ref().0.calls, 4);
  assert_eq!(chained.get_ref().1.calls, 3);
  Pin::new(&mut chained).consume(1);
  let Poll::Ready(Ok(bytes)) = fill(&mut chained) else {
    panic!("expected sticky EOF")
  };
  assert!(bytes.is_empty());
  assert_eq!(chained.get_ref().0.calls, 4);
}

#[test]
fn empty_is_a_buffered_reader_stateless_writer_and_zero_position_seek() {
  let mut endpoint = empty();
  let Poll::Ready(Ok(bytes)) = fill(&mut endpoint) else {
    panic!("empty reader must be ready")
  };
  assert!(bytes.is_empty());
  Pin::new(&mut endpoint).consume(usize::MAX);

  let mut cx = Context::from_waker(Waker::noop());
  assert!(endpoint.is_write_vectored());
  assert!(matches!(
    Pin::new(&mut endpoint).poll_write(&mut cx, b"discarded"),
    Poll::Ready(Ok(9))
  ));
  assert!(matches!(
    Pin::new(&mut endpoint)
      .poll_write_vectored(&mut cx, &[IoSlice::new(b"a"), IoSlice::new(b"bc")]),
    Poll::Ready(Ok(3))
  ));
  assert!(matches!(
    Pin::new(&mut endpoint).poll_flush(&mut cx),
    Poll::Ready(Ok(()))
  ));
  assert!(matches!(
    Pin::new(&mut endpoint).poll_shutdown(&mut cx),
    Poll::Ready(Ok(()))
  ));
  assert!(matches!(
    Pin::new(&mut endpoint).poll_write(&mut cx, b"still accepted"),
    Poll::Ready(Ok(14))
  ));
  for position in [
    SeekFrom::Start(99),
    SeekFrom::Current(-12),
    SeekFrom::End(4),
  ] {
    assert!(matches!(
      Pin::new(&mut endpoint).poll_seek(&mut cx, position),
      Poll::Ready(Ok(0))
    ));
  }
}

#[test]
fn vectored_fallback_preserves_cap_and_endpoint_order() {
  let mut chained = repeat(4).take(3).chain(repeat(9).take(2));
  let mut first = [0; 4];
  let mut second = [0; 4];
  let mut slices = [
    IoSliceMut::new(&mut []),
    IoSliceMut::new(&mut first),
    IoSliceMut::new(&mut second),
  ];
  let mut cx = Context::from_waker(Waker::noop());
  assert_eq!(
    count(Pin::new(&mut chained).poll_read_vectored(&mut cx, &mut slices)),
    3
  );
  assert_eq!(
    count(Pin::new(&mut chained).poll_read_vectored(&mut cx, &mut slices)),
    2
  );
  assert_eq!(second, [0; 4]);
  assert_eq!(first, [9, 9, 4, 0]);
}

#[test]
fn bounded_repeat_to_sink_integrates_with_copy() {
  let mut reader = repeat(6).take(200);
  let mut writer = sink();
  let mut scratch = [0; 1];
  let mut future = copy_with_buffer(&mut reader, &mut writer, &mut scratch);
  let mut cx = Context::from_waker(Waker::noop());
  let mut saw_pending = false;
  let mut completed = false;
  for _ in 0..16 {
    match Pin::new(&mut future).poll(&mut cx) {
      Poll::Pending => saw_pending = true,
      Poll::Ready(result) => {
        assert_eq!(result.unwrap(), 200);
        completed = true;
        break;
      }
    }
  }
  assert!(saw_pending && completed);
}

#[test]
fn ready_endpoints_preserve_initialized_bytes_and_vector_counts() {
  let mut buf = [3; 4];
  assert_eq!(count(read(&mut empty(), &mut buf)), 0);
  assert_eq!(buf, [3; 4]);
  assert_eq!(count(read(&mut repeat(17), &mut buf)), 4);
  assert_eq!(buf, [17; 4]);
  let mut output = sink();
  let mut cx = Context::from_waker(Waker::noop());
  assert_eq!(
    count(Pin::new(&mut output).poll_write_vectored(
      &mut cx,
      &[IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"c")]
    )),
    3
  );
  assert!(matches!(
    Pin::new(&mut output).poll_shutdown(&mut cx),
    Poll::Ready(Ok(()))
  ));
  assert_eq!(
    count(Pin::new(&mut output).poll_write(&mut cx, b"later")),
    5
  );
  let mut flush = output.flush();
  assert!(matches!(
    Pin::new(&mut flush).poll(&mut cx),
    Poll::Ready(Ok(()))
  ));
}
