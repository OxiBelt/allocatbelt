use std::future::{self, Future};
use std::io::{self, Write};
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::buffered_io::BufferedReader;
use allocatbelt::runtime::io::{AsyncBufReadExt, AsyncRead, BoundedReadStop};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::net::TcpStream;
use allocatbelt::runtime::oneshot;
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};

const WATCHDOG: Duration = Duration::from_secs(15);
const MANAGED_BUFFER_BYTES: usize = 4;
// More than 64 refills of the four-byte reader buffer are needed for this line.
const HOT_LINE_BYTES: usize = 300;

#[test]
fn managed_buffered_tcp_reader_composes_refill_capacity_and_cancel_paths() {
  within_watchdog(run_buffered_reader);
}

fn within_watchdog(run: fn()) {
  let (done_tx, done_rx) = mpsc::channel();
  let worker = thread::spawn(move || {
    run();
    let _ = done_tx.send(());
  });
  done_rx
    .recv_timeout(WATCHDOG)
    .expect("managed buffered-reader fixture must finish within its watchdog");
  worker.join().expect("fixture worker must not panic");
}

struct ReaderReport {
  cancelled_prefix: Vec<u8>,
  cancelled_filled: usize,
  unread_range: Range<usize>,
  waiters_before_cancel: usize,
  waiters_after_cancel: usize,
  registrations_before_drop: usize,
  registrations_after_drop: usize,
  charged_before_drop: usize,
  managed_memory_after_drop: usize,
  network_ops_after_drop: usize,
}

struct ReleaseSiblingOnRead {
  inner: TcpStream,
  release: Option<oneshot::Sender<()>>,
  polls: usize,
}

impl AsyncRead for ReleaseSiblingOnRead {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    this.polls += 1;
    if this.polls == 8
      && let Some(release) = this.release.take()
    {
      let _ = release.send(());
    }
    Pin::new(&mut this.inner).poll_read(cx, output)
  }
}

fn run_buffered_reader() {
  let listener = StdTcpListener::bind("127.0.0.1:0").expect("loopback listener should bind");
  let address = listener
    .local_addr()
    .expect("listener address should be available");
  let mut peer = StdTcpStream::connect_timeout(&address, Duration::from_secs(2))
    .expect("loopback peer should connect");
  peer
    .set_write_timeout(Some(Duration::from_secs(2)))
    .expect("peer writes should be bounded");
  let (accepted, _) = listener
    .accept()
    .expect("loopback stream should be accepted");
  drop(listener);

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let endpoint = TcpStream::from_std(accepted, &reactor_handle)
    .expect("accepted stream should register with the live reactor");
  assert_eq!(reactor_handle.registrations(), 1);
  assert_eq!(reactor_handle.waiters(), 0);

  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: MANAGED_BUFFER_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let buffer = resources
    .try_alloc_zeroed(MANAGED_BUFFER_BYTES)
    .expect("the exact managed reader buffer should fit");
  let (release_sibling_tx, release_sibling_rx) = oneshot::channel();
  let mut reader = BufferedReader::new(
    ReleaseSiblingOnRead {
      inner: endpoint,
      release: Some(release_sibling_tx),
      polls: 0,
    },
    buffer,
  )
  .expect("uniquely owned managed storage should initialize the reader");
  assert_eq!(resources.snapshot().managed_memory, MANAGED_BUFFER_BYTES);
  let reader_reactor_handle = reactor_handle.clone();
  let reader_resources = resources.clone();

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 3,
    max_scopes: 2,
  })
  .expect("async runtime should start");
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("reader and sibling should share an owned resource scope");

  let (sibling_progress_tx, sibling_progress_rx) = oneshot::channel();
  let sibling_ran = Arc::new(AtomicBool::new(false));
  let sibling_ran_in_task = Arc::clone(&sibling_ran);
  let (sibling_started_tx, sibling_started_rx) = mpsc::channel();
  let sibling = scope
    .spawn(async move {
      sibling_started_tx
        .send(())
        .expect("sibling-start receiver remains live");
      release_sibling_rx
        .await
        .expect("reader should release the queued sibling while its line read is in flight");
      sibling_ran_in_task.store(true, Ordering::Release);
      sibling_progress_tx
        .send(())
        .expect("reader should still be waiting for sibling progress");
    })
    .expect("sibling task should be admitted before the reader task");
  sibling_started_rx
    .recv_timeout(WATCHDOG)
    .expect("sibling should be queued before reader work starts");

  let (first_line_tx, first_line_rx) = oneshot::channel();
  let (utf8_prefix_tx, utf8_prefix_rx) = oneshot::channel();
  let (second_line_tx, second_line_rx) = oneshot::channel();
  let (capacity_tx, capacity_rx) = oneshot::channel();
  let (suffix_tx, suffix_rx) = oneshot::channel();
  let reader_job = scope
    .spawn(async move {
      let mut first = [0_u8; HOT_LINE_BYTES + 1];
      let first_result = reader
        .read_line_bounded(&mut first)
        .await
        .expect("line spanning managed-buffer refills should read");
      first_line_tx
        .send((
          first[..first_result.filled].to_vec(),
          first_result.stop,
          sibling_ran.load(Ordering::Acquire),
        ))
        .expect("first-line receiver remains live");
      sibling_progress_rx
        .await
        .expect("queued sibling should progress before the next line read");

      let mut utf8_line = [0_u8; 16];
      let mut pending_utf8 = Box::pin(reader.read_line_bounded(&mut utf8_line));
      let mut prefix_sender = Some(utf8_prefix_tx);
      let second_result = future::poll_fn(|cx| match pending_utf8.as_mut().poll(cx) {
        std::task::Poll::Pending => {
          if pending_utf8.filled() == MANAGED_BUFFER_BYTES
            && let Some(sender) = prefix_sender.take()
          {
            sender
              .send(pending_utf8.filled())
              .expect("UTF-8 prefix receiver remains live");
          }
          std::task::Poll::Pending
        }
        result => result,
      })
      .await
      .expect("UTF-8 line split across the managed refill should validate");
      drop(pending_utf8);
      second_line_tx
        .send((
          utf8_line[..second_result.filled].to_vec(),
          second_result.stop,
        ))
        .expect("second-line receiver remains live");

      let mut limited = [0_u8; 3];
      let limited_result = reader
        .read_line_bounded(&mut limited)
        .await
        .expect("bounded output should stop without consuming the unread suffix");
      capacity_tx
        .send((
          limited[..limited_result.filled].to_vec(),
          limited_result.stop,
          reader.buffered().to_vec(),
        ))
        .expect("capacity receiver remains live");

      let mut suffix = [0_u8; 8];
      let suffix_result = reader
        .read_line_bounded(&mut suffix)
        .await
        .expect("next bounded read should recover the unread line suffix");
      suffix_tx
        .send((suffix[..suffix_result.filled].to_vec(), suffix_result.stop))
        .expect("suffix receiver remains live");

      let mut cancelled_prefix = [0_u8; 8];
      let mut pending_line = Box::pin(reader.read_line_bounded(&mut cancelled_prefix));
      let prefix_pending = future::poll_fn(|cx| match pending_line.as_mut().poll(cx) {
        std::task::Poll::Pending if pending_line.filled() == 3 => std::task::Poll::Ready(true),
        std::task::Poll::Pending => std::task::Poll::Pending,
        std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
      })
      .await;
      assert!(
        prefix_pending,
        "partial line should be pending without a delimiter"
      );
      let cancelled_filled = pending_line.filled();
      drop(pending_line);
      assert_eq!(cancelled_filled, 3);
      assert_eq!(&cancelled_prefix[..cancelled_filled], b"pre");

      let (mut endpoint, buffer, unread_range) = reader.into_parts();
      let waiters_before_cancel = reader_reactor_handle.waiters();
      endpoint.inner.cancel_io_waits();
      let waiters_after_cancel = reader_reactor_handle.waiters();
      let registrations_before_drop = reader_reactor_handle.registrations();
      let charged_before_drop = buffer.charged_bytes();
      drop(endpoint);
      let registrations_after_drop = reader_reactor_handle.registrations();
      drop(buffer);
      let snapshot = reader_resources.snapshot();
      ReaderReport {
        cancelled_prefix: cancelled_prefix[..cancelled_filled].to_vec(),
        cancelled_filled,
        unread_range,
        waiters_before_cancel,
        waiters_after_cancel,
        registrations_before_drop,
        registrations_after_drop,
        charged_before_drop,
        managed_memory_after_drop: snapshot.managed_memory,
        network_ops_after_drop: snapshot.network_ops,
      }
    })
    .expect("reader task should be admitted into the owned scope");

  let report = runtime
    .block_on(async move {
      let mut hot_line = vec![b'x'; HOT_LINE_BYTES];
      hot_line.push(b'\n');
      peer
        .write_all(&hot_line)
        .expect("first line should be written");
      let (first, first_stop, sibling_progressed) = first_line_rx
        .await
        .expect("reader should report first line");
      assert_eq!(first, hot_line);
      assert_eq!(first_stop, BoundedReadStop::Delimiter);
      assert!(
        sibling_progressed,
        "queued sibling should run before the bounded hot read completes"
      );

      // The four-byte managed buffer receives exactly the first four bytes;
      // the last byte of the three-byte scalar arrives only after the reader
      // confirms it copied this prefix and is pending for more input.
      peer
        .write_all(b"ab\xE2\x82")
        .expect("UTF-8 prefix should be written");
      let prefix_filled = utf8_prefix_rx
        .await
        .expect("reader should expose the pending UTF-8 prefix length");
      assert_eq!(prefix_filled, MANAGED_BUFFER_BYTES);
      peer
        .write_all(b"\xAC\n")
        .expect("UTF-8 completion should be written");
      let (second, second_stop) = second_line_rx
        .await
        .expect("reader should report the completed UTF-8 line");
      assert_eq!(second, "ab€\n".as_bytes());
      assert_eq!(second_stop, BoundedReadStop::Delimiter);

      peer
        .write_all(b"tail\n")
        .expect("capacity-limited line should be written");
      let (limited, limited_stop, buffered) = capacity_rx
        .await
        .expect("reader should report bounded output exhaustion");
      assert_eq!(limited, b"tai");
      assert_eq!(limited_stop, BoundedReadStop::Capacity);
      assert!(
        buffered.is_empty() || buffered == b"l",
        "bounded output leaves only the unread byte from the current refill"
      );
      let (suffix, suffix_stop) = suffix_rx
        .await
        .expect("reader should report the retained suffix");
      assert_eq!(suffix, b"l\n");
      assert_eq!(suffix_stop, BoundedReadStop::Delimiter);

      peer
        .write_all(b"pre")
        .expect("unterminated prefix should be written");
      let report = reader_job.await.expect("reader task should finish");
      sibling.await.expect("sibling task should finish");
      report
    })
    .expect("fixture root future should complete");

  assert_eq!(report.cancelled_prefix, b"pre");
  assert_eq!(report.cancelled_filled, 3);
  assert!(report.unread_range.is_empty());
  assert_eq!(report.waiters_before_cancel, 1);
  assert_eq!(report.waiters_after_cancel, 0);
  assert_eq!(report.registrations_before_drop, 1);
  assert_eq!(report.registrations_after_drop, 0);
  assert_eq!(report.charged_before_drop, MANAGED_BUFFER_BYTES);
  assert_eq!(report.managed_memory_after_drop, 0);
  assert_eq!(report.network_ops_after_drop, 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(scope.snapshot().active_tasks, 0);
  runtime
    .block_on(scope.close())
    .expect("owned reader scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}
