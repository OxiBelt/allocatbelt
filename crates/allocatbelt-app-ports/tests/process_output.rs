//! Bounded application acceptance draft for `OutputFuture`, an owned async
//! scope, a caller-owned reactor, a managed resource ledger, and the process
//! reaper.
//!
//! Output helper children are this test executable, re-entered through the
//! ignored `process_output_helper_child` test. The parent selects it with
//! `--exact`, runs it with `--nocapture` so it writes uncaptured output, and
//! sets its mode through `ALLOCATBELT_PROCESS_OUTPUT_HELPER_MODE`. Without
//! that variable the helper returns immediately, so ordinary and
//! `--ignored` runs stay finite.
//!
//! The libtest harness in the helper writes its own preamble to stdout. To
//! keep collected payloads exact, the helper writes a ready marker to both
//! streams and then blocks on an explicit gate. The parent reads both
//! endpoints one byte at a time up to the marker and only then starts
//! collection. Gates are pipes, never sleeps:
//!
//! - In burst, exact, and either ReturnPartial overflow mode, the helper waits
//!   for EOF on its piped stdin. Constructing `OutputFuture` closes the
//!   `ProcessChild` stdin and releases it.
//! - In detached, held-burst, and KillAndWait modes, stdin is a separate
//!   `std::io::pipe`. Collector construction cannot release that gate; the
//!   test writes it only after the intended pending/sibling/kill witness.
//! - In budget-read and hot-read modes, the helper writes a finite stdout
//!   payload, reports completion through a private datagram socket, then waits
//!   on stdin. Budget-write and backpressure modes use a separate datagram
//!   control gate before reading stdin, so the parent can measure writes while
//!   the child is not consuming them.
//!
//! After writing finite payloads, the helper calls `std::process::exit`, so no
//! trailing harness output reaches the pipes. Hang and process-group cleanup
//! belong to the external watchdog. These tests do not assume the library
//! provides any I/O deadline.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown, consume_budget,
};
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::oneshot;
use allocatbelt::runtime::process::output::{
  CollectedOutput, OutputFailureKind, OutputFuture, OutputInputs, OutputLimitPolicy, OutputParts,
  OutputStream,
};
use allocatbelt::runtime::process::pipe::{AsyncChildStderr, AsyncChildStdin, AsyncChildStdout};
use allocatbelt::runtime::process::{ProcessDriver, ProcessShutdownMode};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig, ReactorHandle};
use allocatbelt::runtime::time::TimerDriver;

const HELPER_TEST: &str = "process_output_helper_child";
const HELPER_MODE_ENV: &str = "ALLOCATBELT_PROCESS_OUTPUT_HELPER_MODE";
const HELPER_NOTIFY_ENV: &str = "ALLOCATBELT_PROCESS_OUTPUT_NOTIFY_PATH";
const HELPER_CONTROL_ENV: &str = "ALLOCATBELT_PROCESS_OUTPUT_CONTROL_PATH";
const MODE_BURST: &str = "burst";
const MODE_EXACT: &str = "exact";
const MODE_OVERFLOW: &str = "overflow";
const MODE_OVERFLOW_STDERR: &str = "overflow-stderr";
const MODE_DETACHED: &str = "detached";
const MODE_BURST_HOLD: &str = "burst-hold";
const MODE_KILL_OVERFLOW: &str = "kill-overflow";
const MODE_HOLD: &str = "hold";
const MODE_BUDGET_READ: &str = "budget-read";
const MODE_BUDGET_WRITE: &str = "budget-write";
const MODE_HOT_READ: &str = "hot-read";
const MODE_BACKPRESSURE: &str = "backpressure";

const READY_MARKER: &[u8] = b"\0allocatbelt-process-output-ready\0";
const MAX_PREAMBLE_BYTES: usize = 4096;

const STDOUT_SEED: u64 = 0x5d0f_17a3;
const STDERR_SEED: u64 = 0xe44c_9b21;

// Fixed finite payloads exercise simultaneous collection and bounded storage.
// No host pipe-capacity value is assumed by this portable fixture.
const BURST_STDOUT_BYTES: usize = 256 * 1024 + 13;
const BURST_STDERR_BYTES: usize = 192 * 1024 + 7;
const BURST_SLACK_BYTES: usize = 4096;
const INTERLEAVE_CHUNK: usize = 4093;

const LIMIT_STDOUT_BYTES: usize = 257;
const LIMIT_STDERR_BYTES: usize = 193;
const KILL_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const BUDGET_PATTERN_SEED: u64 = 0x8b27_19df;
const BUDGET_PAYLOAD_BYTES: usize = 16;
const HOT_PAYLOAD_BYTES: usize = 256;
const BACKPRESSURE_BYTE_CEILING: usize = 1024 * 1024;
const BACKPRESSURE_MAX_ATTEMPTS: usize = 1024;
const BACKPRESSURE_CHUNK_BYTES: usize = 16 * 1024;
const PIPE_PATTERN_SEED: u64 = 0xf154_83a2;
const WITNESS_RETRY_LIMIT: usize = 512;
const WITNESS_TIMEOUT: Duration = Duration::from_secs(5);

const DETACHED_BUFFER_BYTES: usize = 256;
const WATCHDOG: Duration = Duration::from_secs(45);
const CANCEL_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(1);

fn pattern_byte(seed: u64, index: usize) -> u8 {
  ((index as u64) ^ seed)
    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
    .to_be_bytes()[0]
}

fn patterned(seed: u64, len: usize) -> Vec<u8> {
  (0..len).map(|index| pattern_byte(seed, index)).collect()
}

fn first_mismatch(actual: &[u8], expected: &[u8]) -> Option<usize> {
  actual
    .iter()
    .zip(expected)
    .position(|(left, right)| left != right)
    .or_else(|| (actual.len() != expected.len()).then_some(actual.len().min(expected.len())))
}

fn helper_command(mode: &str, stdin: Stdio) -> Command {
  let executable = std::env::current_exe().expect("test executable path should be available");
  let mut command = Command::new(executable);
  command
    .args([
      "--exact",
      HELPER_TEST,
      "--ignored",
      "--nocapture",
      "--test-threads=1",
    ])
    .env(HELPER_MODE_ENV, mode)
    .env_remove(HELPER_NOTIFY_ENV)
    .env_remove(HELPER_CONTROL_ENV)
    .stdin(stdin)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  command
}

fn async_runtime() -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 2,
  })
  .expect("async runtime should start")
}

fn ledger(managed_memory: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  })
}

struct PrivateSocketDir(PathBuf);

impl PrivateSocketDir {
  fn create() -> Self {
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-process-output-v4-{}-{}",
      std::process::id(),
      NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let mut builder = fs::DirBuilder::new();
    builder
      .mode(0o700)
      .create(&path)
      .expect("private socket directory should be created");
    Self(path)
  }

  fn path(&self, name: &str) -> PathBuf {
    self.0.join(name)
  }
}

impl Drop for PrivateSocketDir {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

struct ChildGate(Option<std::process::ChildStdin>);

impl ChildGate {
  fn release(&mut self) {
    if let Some(mut writer) = self.0.take() {
      writer.write_all(&[1]).expect("child exit gate should open");
    }
  }
}

impl Drop for ChildGate {
  fn drop(&mut self) {
    if let Some(mut writer) = self.0.take() {
      let _ = writer.write(&[1]);
    }
  }
}

struct DatagramGate {
  path: PathBuf,
  expected_len: usize,
  released: bool,
}

impl DatagramGate {
  fn release(&mut self) {
    if self.released {
      return;
    }
    let socket = UnixDatagram::unbound().expect("control release socket should open");
    let command = format!("go:{}", self.expected_len);
    socket
      .send_to(command.as_bytes(), &self.path)
      .expect("child input gate should open");
    self.released = true;
  }
}

impl Drop for DatagramGate {
  fn drop(&mut self) {
    if !self.released
      && let Ok(socket) = UnixDatagram::unbound()
    {
      let command = format!("go:{}", self.expected_len);
      let _ = socket.send_to(command.as_bytes(), &self.path);
    }
  }
}

fn parent_notification_socket(directory: &PrivateSocketDir) -> UnixDatagram {
  let socket = UnixDatagram::bind(directory.path("parent.sock"))
    .expect("parent notification socket should bind");
  socket
    .set_read_timeout(Some(WATCHDOG))
    .expect("parent notification wait should be bounded");
  socket
}

fn receive_notification(socket: &UnixDatagram) -> Vec<u8> {
  let mut bytes = [0_u8; 128];
  let count = socket
    .recv(&mut bytes)
    .expect("bounded child notification should arrive");
  bytes[..count].to_vec()
}

fn control_helper_command(mode: &str, parent_socket: &Path, child_socket: &Path) -> Command {
  let mut command = helper_command(mode, Stdio::piped());
  command
    .env(HELPER_NOTIFY_ENV, parent_socket)
    .env(HELPER_CONTROL_ENV, child_socket)
    .stdout(Stdio::null())
    .stderr(Stdio::null());
  command
}

fn poll_read_shape<R: AsyncRead + Unpin>(
  reader: &mut R,
  context: &mut std::task::Context<'_>,
  output: &mut [u8],
  vectored: bool,
) -> Poll<io::Result<usize>> {
  if !vectored {
    return Pin::new(reader).poll_read(context, output);
  }
  let split = output.len() / 2;
  let (left, right) = output.split_at_mut(split);
  let mut buffers = [IoSliceMut::new(left), IoSliceMut::new(right)];
  Pin::new(reader).poll_read_vectored(context, &mut buffers)
}

fn poll_write_shape<W: AsyncWrite + Unpin>(
  writer: &mut W,
  context: &mut std::task::Context<'_>,
  input: &[u8],
  vectored: bool,
) -> Poll<io::Result<usize>> {
  if !vectored {
    return Pin::new(writer).poll_write(context, input);
  }
  let split = input.len() / 2;
  let buffers = [IoSlice::new(&input[..split]), IoSlice::new(&input[split..])];
  Pin::new(writer).poll_write_vectored(context, &buffers)
}

fn assert_sixty_three_checkpoints_then_pending(context: &mut std::task::Context<'_>) {
  for _ in 0..63 {
    let mut checkpoint = std::pin::pin!(consume_budget());
    assert!(checkpoint.as_mut().poll(context).is_ready());
  }
  let mut exhausted = std::pin::pin!(consume_budget());
  assert!(exhausted.as_mut().poll(context).is_pending());
}

fn assert_sixty_four_checkpoints_then_pending(context: &mut std::task::Context<'_>) {
  for _ in 0..64 {
    let mut checkpoint = std::pin::pin!(consume_budget());
    assert!(checkpoint.as_mut().poll(context).is_ready());
  }
  let mut exhausted = std::pin::pin!(consume_budget());
  assert!(exhausted.as_mut().poll(context).is_pending());
}

enum ReadBudgetEvent {
  Charged {
    poll_sequence: usize,
    count: usize,
    bytes: Vec<u8>,
    ready_checkpoints: usize,
    checkpoint_pending: bool,
  },
  Gated {
    poll_sequence: usize,
    waiters_before: usize,
    waiters_after: usize,
    buffer_before: Vec<u8>,
    buffer_after: Vec<u8>,
    ready_checkpoints: usize,
    checkpoint_pending: bool,
  },
}

enum WriteBudgetEvent {
  Charged {
    poll_sequence: usize,
    count: usize,
    ready_checkpoints: usize,
    checkpoint_pending: bool,
  },
  Gated {
    poll_sequence: usize,
    offset_before: usize,
    offset_after: usize,
    waiters_before: usize,
    waiters_after: usize,
    writer_before: bool,
    writer_after: bool,
    ready_checkpoints: usize,
    checkpoint_pending: bool,
  },
}

fn run_read_budget_case(vectored: bool) {
  let directory = PrivateSocketDir::create();
  let parent_socket = parent_notification_socket(&directory);
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = async_runtime();
  let resources = ledger(0);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("budget witness scope should open");
  let mut command = helper_command(MODE_BUDGET_READ, Stdio::piped());
  command.env(HELPER_NOTIFY_ENV, directory.path("parent.sock"));
  let mut child = driver.spawn(command).expect("read helper should spawn");
  child.set_kill_on_drop(true);
  let stdout = AsyncChildStdout::from_std(
    child
      .take_stdout()
      .expect("read helper stdout should be piped"),
    &reactor_handle,
  )
  .expect("stdout should register with the reactor");
  let mut stderr = AsyncChildStderr::from_std(
    child
      .take_stderr()
      .expect("read helper stderr should be piped"),
    &reactor_handle,
  )
  .expect("stderr should register with the reactor");
  let mut reader = stdout;
  runtime
    .block_on(async {
      read_past_marker(&mut reader, "stdout").await;
      read_past_marker(&mut stderr, "stderr").await;
    })
    .expect("read marker handshake should complete");
  assert_eq!(receive_notification(&parent_socket), vec![1_u8]);
  drop(stderr);
  let raw_fd = reader
    .get_ref()
    .as_fd()
    .try_clone_to_owned()
    .expect("stdout diagnostic alias should clone safely");
  let mut raw_reader = File::from(raw_fd);
  let mut exit_gate = ChildGate(child.take_stdin());
  let (event_tx, event_rx) = std::sync::mpsc::channel();
  let (resume_tx, resume_rx) = oneshot::channel();
  let task_reactor = reactor_handle.clone();
  let job = scope
    .spawn(async move {
      let mut first = [0_u8; 8];
      let mut zero_buffer = [0xa5_u8; 8];
      let buffer_before = zero_buffer.to_vec();
      let mut first_count = 0;
      let mut phase = 0_u8;
      let mut poll_sequence = 0;
      let mut resume_rx = Box::pin(resume_rx);
      poll_fn(|context| {
        poll_sequence += 1;
        if phase == 0 {
          return match poll_read_shape(&mut reader, context, &mut first, vectored) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) if count > 0 => {
              first_count = count;
              assert_eq!(
                &first[..count],
                &patterned(BUDGET_PATTERN_SEED, BUDGET_PAYLOAD_BYTES)[..count]
              );
              assert_sixty_three_checkpoints_then_pending(context);
              event_tx
                .send(ReadBudgetEvent::Charged {
                  poll_sequence,
                  count,
                  bytes: first[..count].to_vec(),
                  ready_checkpoints: 63,
                  checkpoint_pending: true,
                })
                .expect("parent waits for the charged read witness");
              phase = 1;
              Poll::Pending
            }
            Poll::Ready(Ok(count)) => {
              assert_eq!(count, 0, "unexpected read count before the gate");
              panic!("read helper reached EOF before its gate")
            }
            Poll::Ready(Err(error)) => panic!("initial child-pipe read failed: {error}"),
          };
        }
        if phase == 1 {
          assert_sixty_four_checkpoints_then_pending(context);
          let waiters_before = task_reactor.waiters();
          match poll_read_shape(&mut reader, context, &mut zero_buffer, vectored) {
            Poll::Pending => {
              let waiters_after = task_reactor.waiters();
              assert_eq!(zero_buffer.as_slice(), buffer_before.as_slice());
              assert_eq!(waiters_after, waiters_before);
              event_tx
                .send(ReadBudgetEvent::Gated {
                  poll_sequence,
                  waiters_before,
                  waiters_after,
                  buffer_before: buffer_before.clone(),
                  buffer_after: zero_buffer.to_vec(),
                  ready_checkpoints: 64,
                  checkpoint_pending: true,
                })
                .expect("parent waits for the zero-budget read witness");
              phase = 2;
              return Poll::Pending;
            }
            Poll::Ready(Ok(count)) => {
              panic!("zero-budget read mutated the buffer with {count} bytes")
            }
            Poll::Ready(Err(error)) => panic!("zero-budget read failed: {error}"),
          }
        }
        match resume_rx.as_mut().poll(context) {
          Poll::Ready(Ok(())) => Poll::Ready(()),
          Poll::Ready(Err(_)) => panic!("parent resume gate closed unexpectedly"),
          Poll::Pending => Poll::Pending,
        }
      })
      .await;

      let mut remainder = Vec::new();
      let mut chunk = [0_u8; 8];
      loop {
        let count = read_once(&mut reader, &mut chunk).await;
        if count == 0 {
          break;
        }
        remainder.extend_from_slice(&chunk[..count]);
      }
      (first[..first_count].to_vec(), remainder)
    })
    .expect("read budget task should be admitted");

  let charged = event_rx
    .recv_timeout(WATCHDOG)
    .expect("a positive read must reach the measured budget boundary");
  let (first_poll, first_count, first_bytes) = match charged {
    ReadBudgetEvent::Charged {
      poll_sequence,
      count,
      bytes,
      ready_checkpoints,
      checkpoint_pending,
    } => {
      assert_eq!(ready_checkpoints, 63);
      assert!(checkpoint_pending);
      (poll_sequence, count, bytes)
    }
    ReadBudgetEvent::Gated { .. } => panic!("zero gate arrived before positive read"),
  };
  assert!(first_count > 0 && first_count <= 8);
  let gated = event_rx
    .recv_timeout(WATCHDOG)
    .expect("a fresh outer poll must gate the read at zero budget");
  let ReadBudgetEvent::Gated {
    waiters_before,
    waiters_after,
    buffer_before,
    buffer_after,
    ready_checkpoints,
    checkpoint_pending,
    poll_sequence,
  } = gated
  else {
    panic!("second read witness was not the zero-budget gate");
  };
  assert_eq!(waiters_after, waiters_before);
  assert_eq!(buffer_after, buffer_before);
  assert_eq!(ready_checkpoints, 64);
  assert!(checkpoint_pending);
  assert!(
    poll_sequence > first_poll,
    "zero gate must use a fresh outer poll"
  );

  let mut diagnostic = [0_u8; 1];
  assert_eq!(
    raw_reader
      .read(&mut diagnostic)
      .expect("raw alias should confirm unread pipe data"),
    1
  );
  let expected = patterned(BUDGET_PATTERN_SEED, BUDGET_PAYLOAD_BYTES);
  assert_eq!(first_bytes, expected[..first_count]);
  assert_eq!(diagnostic[0], expected[first_count]);
  drop(raw_reader);
  exit_gate.release();
  resume_tx
    .send(())
    .expect("reader task should resume after the diagnostic read");
  let (first, remainder) = runtime
    .block_on(job)
    .expect("read task should join")
    .expect("read task should finish");
  let mut observed = first;
  observed.push(diagnostic[0]);
  observed.extend_from_slice(&remainder);
  assert_eq!(observed, expected);
  let status = runtime
    .block_on(child.wait())
    .expect("read helper root poll should complete")
    .expect("read helper should be reaped");
  assert!(status.success());
  runtime
    .block_on(scope.close())
    .expect("read scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("child driver should stop");
  assert_eq!(driver.active_children(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[test]
fn public_scalar_read_charge_and_zero_budget_gate_preserve_state() {
  run_read_budget_case(false);
}

#[test]
fn public_vectored_read_charge_and_zero_budget_gate_preserve_state() {
  run_read_budget_case(true);
}

fn run_write_budget_case(vectored: bool) {
  let directory = PrivateSocketDir::create();
  let parent_socket = parent_notification_socket(&directory);
  let control_path = directory.path("child-control.sock");
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 1,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = async_runtime();
  let resources = ledger(64);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("write budget witness scope should open");
  let command = control_helper_command(
    MODE_BUDGET_WRITE,
    &directory.path("parent.sock"),
    &control_path,
  );
  let mut child = driver.spawn(command).expect("write helper should spawn");
  child.set_kill_on_drop(true);
  let mut gate = DatagramGate {
    path: control_path,
    expected_len: BUDGET_PAYLOAD_BYTES,
    released: false,
  };
  assert_eq!(receive_notification(&parent_socket), b"ready".to_vec());
  let writer = AsyncChildStdin::from_std(
    child
      .take_stdin()
      .expect("write helper stdin should be piped"),
    &reactor_handle,
  )
  .expect("stdin should register with the reactor");
  let raw_fd = writer
    .get_ref()
    .expect("writer should be open")
    .as_fd()
    .try_clone_to_owned()
    .expect("stdin diagnostic alias should clone safely");
  let mut raw_writer = File::from(raw_fd);
  let payload = patterned(BUDGET_PATTERN_SEED, BUDGET_PAYLOAD_BYTES);
  let task_payload = payload.clone();
  let root_charge = resources
    .try_alloc_zeroed(64)
    .expect("charge witness should fit");
  let task_charge = root_charge.clone();
  let (event_tx, event_rx) = std::sync::mpsc::channel();
  let (resume_tx, resume_rx) = oneshot::channel();
  let task_reactor = reactor_handle.clone();
  let job = scope
    .spawn(async move {
      let mut writer = writer;
      let mut offset = 0;
      let mut phase = 0_u8;
      let mut poll_sequence = 0;
      let mut resume_rx = Box::pin(resume_rx);
      let initial = &task_payload[..task_payload.len() / 2];
      poll_fn(|context| {
        poll_sequence += 1;
        if phase == 0 {
          return match poll_write_shape(&mut writer, context, initial, vectored) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) if count > 0 => {
              assert!(count <= initial.len());
              offset = count;
              assert_sixty_three_checkpoints_then_pending(context);
              event_tx
                .send(WriteBudgetEvent::Charged {
                  poll_sequence,
                  count,
                  ready_checkpoints: 63,
                  checkpoint_pending: true,
                })
                .expect("parent waits for the charged write witness");
              phase = 1;
              Poll::Pending
            }
            Poll::Ready(Ok(count)) => {
              assert_eq!(count, 0, "nonpositive child-pipe write count");
              panic!("positive child-pipe write made no progress")
            }
            Poll::Ready(Err(error)) => panic!("initial child-pipe write failed: {error}"),
          };
        }
        if phase == 1 {
          assert_sixty_four_checkpoints_then_pending(context);
          let waiters_before = task_reactor.waiters();
          let writer_before = writer.get_ref().is_some();
          let offset_before = offset;
          match poll_write_shape(&mut writer, context, &task_payload[offset..], vectored) {
            Poll::Pending => {
              let waiters_after = task_reactor.waiters();
              let writer_after = writer.get_ref().is_some();
              assert_eq!(offset, offset_before);
              assert_eq!(waiters_after, waiters_before);
              assert_eq!(writer_after, writer_before);
              event_tx
                .send(WriteBudgetEvent::Gated {
                  poll_sequence,
                  offset_before,
                  offset_after: offset,
                  waiters_before,
                  waiters_after,
                  writer_before,
                  writer_after,
                  ready_checkpoints: 64,
                  checkpoint_pending: true,
                })
                .expect("parent waits for the zero-budget write witness");
              phase = 2;
              return Poll::Pending;
            }
            Poll::Ready(Ok(count)) => {
              panic!("zero-budget write accepted {count} bytes")
            }
            Poll::Ready(Err(error)) => panic!("zero-budget write failed: {error}"),
          }
        }
        match resume_rx.as_mut().poll(context) {
          Poll::Ready(Ok(())) => Poll::Ready(()),
          Poll::Ready(Err(_)) => panic!("parent resume gate closed unexpectedly"),
          Poll::Pending => Poll::Pending,
        }
      })
      .await;

      let mut cursor = offset + 1;
      while cursor < task_payload.len() {
        let count = poll_fn(|context| {
          poll_write_shape(&mut writer, context, &task_payload[cursor..], vectored)
        })
        .await
        .expect("resumed child-pipe write should succeed");
        assert!(count > 0);
        cursor += count;
      }
      poll_fn(|context| Pin::new(&mut writer).poll_shutdown(context))
        .await
        .expect("writer shutdown should deliver EOF");
      task_charge
    })
    .expect("write budget task should be admitted");
  let charged = event_rx
    .recv_timeout(WATCHDOG)
    .expect("a positive write must reach the measured budget boundary");
  let WriteBudgetEvent::Charged {
    poll_sequence: first_poll,
    count,
    ready_checkpoints,
    checkpoint_pending,
  } = charged
  else {
    panic!("zero gate arrived before positive write");
  };
  assert_eq!(ready_checkpoints, 63);
  assert!(checkpoint_pending);
  assert!(count > 0 && count <= payload.len());
  let gated = event_rx
    .recv_timeout(WATCHDOG)
    .expect("a fresh outer poll must gate the write at zero budget");
  let WriteBudgetEvent::Gated {
    offset_before,
    offset_after,
    waiters_before,
    waiters_after,
    writer_before,
    writer_after,
    ready_checkpoints,
    checkpoint_pending,
    poll_sequence,
  } = gated
  else {
    panic!("second write witness was not the zero-budget gate");
  };
  assert_eq!(offset_before, count);
  assert_eq!(offset_after, count);
  assert_eq!(waiters_after, waiters_before);
  assert!(writer_before && writer_after);
  assert_eq!(ready_checkpoints, 64);
  assert!(checkpoint_pending);
  assert!(
    poll_sequence > first_poll,
    "zero gate must use a fresh outer poll"
  );
  let diagnostic = raw_writer
    .write(&payload[offset_before..offset_before + 1])
    .expect("raw alias should prove the gated pipe remains writable");
  assert_eq!(diagnostic, 1);
  drop(raw_writer);
  gate.release();
  resume_tx
    .send(())
    .expect("writer task should resume after the diagnostic byte");
  let returned_charge = runtime
    .block_on(job)
    .expect("write task should join")
    .expect("write task should finish");
  assert_eq!(returned_charge.charged_bytes(), 64);
  let received = receive_notification(&parent_socket);
  assert_eq!(received, payload);
  let status = runtime
    .block_on(child.wait())
    .expect("write helper root poll should complete")
    .expect("write helper should be reaped");
  assert!(status.success());
  runtime
    .block_on(scope.close())
    .expect("write scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("child driver should stop");
  assert_eq!(driver.active_children(), 0);
  drop(returned_charge);
  assert_eq!(resources.snapshot().managed_memory, 64);
  drop(root_charge);
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[test]
fn public_scalar_write_charge_and_zero_budget_gate_preserve_state() {
  run_write_budget_case(false);
}

#[test]
fn public_vectored_write_charge_and_zero_budget_gate_preserve_state() {
  run_write_budget_case(true);
}

#[derive(Debug)]
struct HotReadWitness {
  outer_poll: usize,
  ready_reads: usize,
  task_bytes_before_pause: usize,
}

#[test]
fn sixty_four_ready_pipe_reads_yield_to_a_gated_single_worker_sibling() {
  let directory = PrivateSocketDir::create();
  let parent_socket = parent_notification_socket(&directory);
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = async_runtime();
  let resources = ledger(0);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("hot-read scope should open");
  let mut command = helper_command(MODE_HOT_READ, Stdio::piped());
  command.env(HELPER_NOTIFY_ENV, directory.path("parent.sock"));
  let mut child = driver.spawn(command).expect("hot-read helper should spawn");
  child.set_kill_on_drop(true);
  let mut reader = AsyncChildStdout::from_std(
    child
      .take_stdout()
      .expect("hot-read stdout should be piped"),
    &reactor_handle,
  )
  .expect("hot-read stdout should register");
  let mut stderr = AsyncChildStderr::from_std(
    child
      .take_stderr()
      .expect("hot-read stderr should be piped"),
    &reactor_handle,
  )
  .expect("hot-read stderr should register");
  runtime
    .block_on(async {
      read_past_marker(&mut reader, "stdout").await;
      read_past_marker(&mut stderr, "stderr").await;
    })
    .expect("hot-read marker handshake should complete");
  drop(stderr);
  assert_eq!(receive_notification(&parent_socket), vec![1_u8]);
  let raw_fd = reader
    .get_ref()
    .as_fd()
    .try_clone_to_owned()
    .expect("hot-read diagnostic alias should clone safely");
  let mut raw_reader = File::from(raw_fd);
  let mut exit_gate = ChildGate(child.take_stdin());

  let (sibling_release_tx, sibling_release_rx) = oneshot::channel();
  let (sibling_started_tx, sibling_started_rx) = std::sync::mpsc::channel();
  let sibling = scope
    .spawn(async move {
      sibling_started_tx
        .send(())
        .expect("parent waits for the gated sibling to start");
      sibling_release_rx
        .await
        .expect("parent releases the sibling after the 64-read witness");
    })
    .expect("single-worker sibling should be admitted first");
  sibling_started_rx
    .recv_timeout(WITNESS_TIMEOUT)
    .expect("sibling should reach its gate before the hot reader starts");

  let (witness_tx, witness_rx) = std::sync::mpsc::channel();
  let (finish_tx, finish_rx) = oneshot::channel();
  let task_reactor = reactor_handle.clone();
  let hot = scope
    .spawn(async move {
      let mut bytes = Vec::with_capacity(HOT_PAYLOAD_BYTES);
      let mut phase = 0_u8;
      let mut outer_poll = 0_usize;
      let started = Instant::now();
      let mut finish_rx = Box::pin(finish_rx);
      poll_fn(|context| {
        if phase == 0 {
          outer_poll += 1;
          assert!(
            outer_poll <= WITNESS_RETRY_LIMIT,
            "hot read witness retry bound exceeded"
          );
          assert!(
            started.elapsed() < WITNESS_TIMEOUT,
            "hot read witness timed out"
          );
          let mut ready_reads = 0;
          loop {
            if ready_reads == 64 {
              let mut probe = [0xa5_u8; 1];
              return match Pin::new(&mut reader).poll_read(context, &mut probe) {
                Poll::Pending => {
                  assert_eq!(probe, [0xa5]);
                  assert!(
                    bytes.len() < HOT_PAYLOAD_BYTES,
                    "hot payload was fully read before witness"
                  );
                  let witness = HotReadWitness {
                    outer_poll,
                    ready_reads,
                    task_bytes_before_pause: bytes.len(),
                  };
                  witness_tx
                    .send(witness)
                    .expect("parent waits for the exhausted-poll witness");
                  phase = 1;
                  Poll::Pending
                }
                Poll::Ready(Ok(count)) => {
                  panic!("read after 64 ready reads accepted {count} bytes")
                }
                Poll::Ready(Err(error)) => panic!("post-boundary read failed: {error}"),
              };
            }
            let mut byte = [0_u8; 1];
            match Pin::new(&mut reader).poll_read(context, &mut byte) {
              Poll::Pending => return Poll::Pending,
              Poll::Ready(Ok(1)) => {
                bytes.push(byte[0]);
                ready_reads += 1;
              }
              Poll::Ready(Ok(0)) => panic!("gated hot helper reached EOF before release"),
              Poll::Ready(Ok(count)) => panic!("one-byte read returned {count}"),
              Poll::Ready(Err(error)) => panic!("hot child-pipe read failed: {error}"),
            }
            assert!(bytes.len() <= HOT_PAYLOAD_BYTES);
          }
        }
        match finish_rx.as_mut().poll(context) {
          Poll::Ready(Ok(())) => Poll::Ready(()),
          Poll::Ready(Err(_)) => panic!("parent hot-reader gate closed unexpectedly"),
          Poll::Pending => Poll::Pending,
        }
      })
      .await;
      let mut chunk = [0_u8; 32];
      loop {
        let count = read_once(&mut reader, &mut chunk).await;
        if count == 0 {
          break;
        }
        bytes.extend_from_slice(&chunk[..count]);
      }
      (bytes, outer_poll, task_reactor.waiters())
    })
    .expect("hot pipe reader should be admitted beside the sibling");

  let witness = witness_rx
    .recv_timeout(WITNESS_TIMEOUT)
    .expect("hot reader should reach one full 64-operation outer poll");
  assert_eq!(witness.ready_reads, 64);
  assert!(witness.outer_poll <= WITNESS_RETRY_LIMIT);
  let expected = patterned(BUDGET_PATTERN_SEED, HOT_PAYLOAD_BYTES);
  let mut diagnostic = [0_u8; 1];
  assert_eq!(
    raw_reader
      .read(&mut diagnostic)
      .expect("raw alias should prove bytes remain after the exhausted poll"),
    1
  );
  assert_eq!(diagnostic[0], expected[witness.task_bytes_before_pause]);
  drop(raw_reader);

  sibling_release_tx
    .send(())
    .expect("single-worker sibling release should succeed");
  runtime
    .block_on(sibling)
    .expect("sibling join should complete")
    .expect("gated sibling should finish before either hot gate opens");
  finish_tx
    .send(())
    .expect("hot reader should resume after sibling completion");
  exit_gate.release();
  let (mut observed, polls, waiters) = runtime
    .block_on(hot)
    .expect("hot reader task should join")
    .expect("hot reader should drain after release");
  observed.insert(witness.task_bytes_before_pause, diagnostic[0]);
  assert_eq!(observed, expected);
  assert!(polls <= WITNESS_RETRY_LIMIT);
  let status = runtime
    .block_on(child.wait())
    .expect("hot-read helper root poll should complete")
    .expect("hot-read helper should be reaped");
  assert!(status.success());
  runtime
    .block_on(scope.close())
    .expect("hot-read scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("child driver should stop");
  assert_eq!(driver.active_children(), 0);
  assert_eq!(waiters, 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawWriteAttempt {
  Written(usize),
  WouldBlock,
}

fn bounded_raw_write(
  writer: &mut File,
  bytes: &[u8],
  attempts: &mut usize,
) -> io::Result<RawWriteAttempt> {
  loop {
    if *attempts >= BACKPRESSURE_MAX_ATTEMPTS {
      return Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "preregistered raw pipe write attempt bound exhausted",
      ));
    }
    *attempts += 1;
    match writer.write(bytes) {
      Ok(count) => return Ok(RawWriteAttempt::Written(count)),
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        return Ok(RawWriteAttempt::WouldBlock);
      }
      Err(error) => return Err(error),
    }
  }
}

#[derive(Debug)]
struct BackpressurePendingWitness {
  bytes_filled: usize,
  raw_syscall_attempts: usize,
  retained_waiters: usize,
  ready_checkpoints: usize,
  checkpoint_pending: bool,
  managed_bytes: usize,
}

#[test]
fn full_child_stdin_pending_cancels_waiter_and_resumes_same_writer_once() {
  let directory = PrivateSocketDir::create();
  let parent_socket = parent_notification_socket(&directory);
  let control_path = directory.path("child-control.sock");
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 1,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = async_runtime();
  let resources = ledger(64);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("backpressure scope should open");
  let command = control_helper_command(
    MODE_BACKPRESSURE,
    &directory.path("parent.sock"),
    &control_path,
  );
  let mut child = driver
    .spawn(command)
    .expect("backpressure helper should spawn");
  child.set_kill_on_drop(true);
  let mut gate = DatagramGate {
    path: control_path,
    expected_len: 0,
    released: false,
  };
  assert_eq!(receive_notification(&parent_socket), b"ready".to_vec());
  let writer = AsyncChildStdin::from_std(
    child
      .take_stdin()
      .expect("backpressure stdin should be piped"),
    &reactor_handle,
  )
  .expect("child stdin should register with the reactor");
  let raw_fd = writer
    .get_ref()
    .expect("child stdin writer should be open")
    .as_fd()
    .try_clone_to_owned()
    .expect("raw pipe writer alias should clone safely");
  let mut raw_writer = File::from(raw_fd);
  let expected = patterned(PIPE_PATTERN_SEED, BACKPRESSURE_BYTE_CEILING + 1);
  let mut bytes_filled = 0;
  let mut raw_syscall_attempts = 0;
  let mut byte_level_full = false;
  while bytes_filled < BACKPRESSURE_BYTE_CEILING {
    let end = (bytes_filled + BACKPRESSURE_CHUNK_BYTES).min(BACKPRESSURE_BYTE_CEILING);
    match bounded_raw_write(
      &mut raw_writer,
      &expected[bytes_filled..end],
      &mut raw_syscall_attempts,
    )
    .expect("bounded raw pipe fill should not hit unrelated I/O errors")
    {
      RawWriteAttempt::Written(count) => {
        assert!(count > 0, "non-empty pipe fill write made no progress");
        bytes_filled += count;
      }
      RawWriteAttempt::WouldBlock => {
        match bounded_raw_write(
          &mut raw_writer,
          &expected[bytes_filled..bytes_filled + 1],
          &mut raw_syscall_attempts,
        )
        .expect("bounded one-byte fullness probe should complete")
        {
          RawWriteAttempt::WouldBlock => {
            byte_level_full = true;
            break;
          }
          RawWriteAttempt::Written(1) => bytes_filled += 1,
          RawWriteAttempt::Written(count) => {
            panic!("one-byte probe accepted {count} bytes")
          }
        }
      }
    }
    assert!(bytes_filled <= BACKPRESSURE_BYTE_CEILING);
  }
  assert!(
    byte_level_full,
    "no one-byte WouldBlock witness before the fixed 1 MiB ceiling"
  );
  assert!(raw_syscall_attempts <= BACKPRESSURE_MAX_ATTEMPTS);
  assert!(bytes_filled < BACKPRESSURE_BYTE_CEILING);
  gate.expected_len = bytes_filled + 1;

  let root_charge = resources
    .try_alloc_zeroed(64)
    .expect("charge witness should fit");
  let task_charge = root_charge.clone();
  let task_reactor = reactor_handle.clone();
  let writer_sentinel = expected[bytes_filled];
  let pending_job = scope
    .spawn(async move {
      let mut writer = writer;
      let mut task_charge = Some(task_charge);
      let witness =
        poll_fn(
          |context| match Pin::new(&mut writer).poll_write(context, &[writer_sentinel]) {
            Poll::Pending => {
              let retained_waiters = task_reactor.waiters();
              assert_eq!(retained_waiters, 1);
              assert_sixty_four_checkpoints_then_pending(context);
              Poll::Ready(BackpressurePendingWitness {
                bytes_filled,
                raw_syscall_attempts,
                retained_waiters,
                ready_checkpoints: 64,
                checkpoint_pending: true,
                managed_bytes: task_charge
                  .as_ref()
                  .expect("task keeps its managed-buffer clone")
                  .charged_bytes(),
              })
            }
            Poll::Ready(Ok(count)) => panic!("full-pipe sentinel accepted {count} bytes"),
            Poll::Ready(Err(error)) => panic!("full-pipe sentinel write failed: {error}"),
          },
        )
        .await;
      (
        witness,
        writer,
        task_charge
          .take()
          .expect("charge clone should remain owned"),
      )
    })
    .expect("full-pipe pending task should be admitted");
  let (witness, mut writer, task_charge) = runtime
    .block_on(pending_job)
    .expect("full-pipe pending task should join")
    .expect("full-pipe pending task should finish its witness");
  assert_eq!(witness.bytes_filled, bytes_filled);
  assert_eq!(witness.raw_syscall_attempts, raw_syscall_attempts);
  assert_eq!(witness.retained_waiters, 1);
  assert_eq!(witness.ready_checkpoints, 64);
  assert!(witness.checkpoint_pending);
  assert_eq!(witness.managed_bytes, 64);
  assert_eq!(reactor_handle.waiters(), 1);
  assert_eq!(resources.snapshot().managed_memory, 64);

  assert_eq!(
    bounded_raw_write(
      &mut raw_writer,
      &expected[bytes_filled..bytes_filled + 1],
      &mut raw_syscall_attempts,
    )
    .expect("post-pending one-byte fullness check should complete"),
    RawWriteAttempt::WouldBlock
  );
  writer.cancel_io_waits();
  assert_eq!(reactor_handle.waiters(), 0);
  drop(raw_writer);
  gate.release();

  let resumed = scope
    .spawn(async move {
      let count = poll_fn(|context| Pin::new(&mut writer).poll_write(context, &[writer_sentinel]))
        .await
        .expect("same writer should accept the one resumed sentinel");
      assert_eq!(count, 1);
      poll_fn(|context| Pin::new(&mut writer).poll_shutdown(context))
        .await
        .expect("same writer should shut down after its sentinel");
      assert!(writer.get_ref().is_none());
      task_charge
    })
    .expect("resumed writer task should be admitted");
  let resumed_charge = runtime
    .block_on(resumed)
    .expect("resumed writer task should join")
    .expect("resumed writer task should finish");
  let child_report = receive_notification(&parent_socket);
  assert_eq!(
    child_report,
    format!("done:{}", bytes_filled + 1).into_bytes()
  );
  let status = runtime
    .block_on(child.wait())
    .expect("backpressure helper root poll should complete")
    .expect("backpressure helper should be reaped");
  assert!(status.success());
  runtime
    .block_on(scope.close())
    .expect("backpressure scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("child driver should stop");
  assert_eq!(driver.active_children(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  drop(resumed_charge);
  assert_eq!(resources.snapshot().managed_memory, 64);
  drop(root_charge);
  assert_eq!(resources.snapshot().managed_memory, 0);
  reactor.shutdown().expect("reactor should stop");
}

fn launch(
  driver: &ProcessDriver,
  reactor: &ReactorHandle,
  resources: &ResourceScope,
  mode: &str,
  stdin: Stdio,
  stdout_capacity: usize,
  stderr_capacity: usize,
) -> OutputInputs {
  launch_command(
    driver,
    reactor,
    resources,
    helper_command(mode, stdin),
    stdout_capacity,
    stderr_capacity,
  )
}

fn launch_command(
  driver: &ProcessDriver,
  reactor: &ReactorHandle,
  resources: &ResourceScope,
  command: Command,
  stdout_capacity: usize,
  stderr_capacity: usize,
) -> OutputInputs {
  let mut child = driver
    .spawn(command)
    .expect("helper child should be admitted and spawned");
  let stdout = AsyncChildStdout::from_std(
    child.take_stdout().expect("helper stdout should be piped"),
    reactor,
  )
  .expect("helper stdout should register with the reactor");
  let stderr = AsyncChildStderr::from_std(
    child.take_stderr().expect("helper stderr should be piped"),
    reactor,
  )
  .expect("helper stderr should register with the reactor");
  let stdout_buffer = resources
    .try_alloc_zeroed(stdout_capacity)
    .expect("stdout managed buffer should fit the ledger");
  let stderr_buffer = resources
    .try_alloc_zeroed(stderr_capacity)
    .expect("stderr managed buffer should fit the ledger");
  OutputInputs {
    child,
    stdout,
    stderr,
    stdout_buffer,
    stderr_buffer,
  }
}

async fn read_once<R: AsyncRead + Unpin>(reader: &mut R, output: &mut [u8]) -> usize {
  poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, &mut *output))
    .await
    .expect("child pipe read should succeed")
}

async fn read_past_marker<R: AsyncRead + Unpin>(reader: &mut R, stream: &'static str) {
  // Single-byte reads cannot consume anything written after the marker.
  let mut seen = Vec::new();
  let mut byte = [0_u8; 1];
  while !seen.ends_with(READY_MARKER) {
    assert!(
      seen.len() < MAX_PREAMBLE_BYTES,
      "helper {stream} marker missing after {} bytes",
      seen.len()
    );
    let count = read_once(reader, &mut byte).await;
    assert_eq!(count, 1, "helper {stream} closed before its ready marker");
    seen.push(byte[0]);
  }
}

async fn handshake(inputs: &mut OutputInputs) {
  read_past_marker(&mut inputs.stdout, "stdout").await;
  read_past_marker(&mut inputs.stderr, "stderr").await;
}

/// Continues a recovered endpoint into its recovered buffer after the
/// collector returned. Returns the new fill and the number of bytes that did
/// not fit, reading until EOF.
async fn continue_into<R: AsyncRead + Unpin>(
  reader: &mut R,
  storage: &mut [u8],
  mut filled: usize,
) -> (usize, usize) {
  let mut excess = 0;
  loop {
    if filled < storage.len() {
      let count = read_once(reader, &mut storage[filled..]).await;
      if count == 0 {
        return (filled, excess);
      }
      filled += count;
    } else {
      let mut probe = [0_u8; 64];
      let count = read_once(reader, &mut probe).await;
      if count == 0 {
        return (filled, excess);
      }
      excess += count;
    }
  }
}

#[test]
fn owned_scope_collects_finite_concurrent_streams_into_exact_managed_prefixes() {
  let expected_stdout = patterned(STDOUT_SEED, BURST_STDOUT_BYTES);
  let expected_stderr = patterned(STDERR_SEED, BURST_STDERR_BYTES);
  let stdout_capacity = BURST_STDOUT_BYTES + BURST_SLACK_BYTES;
  let stderr_capacity = BURST_STDERR_BYTES + BURST_SLACK_BYTES;
  let total = stdout_capacity + stderr_capacity;

  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let resources = ledger(total);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("collector scope should open with the managed ledger");

  let mut inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_BURST,
    Stdio::piped(),
    stdout_capacity,
    stderr_capacity,
  );
  assert_eq!(resources.snapshot().managed_memory, total);
  assert_eq!(reactor_handle.registrations(), 2);

  let job = scope
    .spawn(async move {
      handshake(&mut inputs).await;
      // Constructing the collector closes the helper's stdin gate and starts
      // the finite simultaneous payload.
      OutputFuture::new(inputs, OutputLimitPolicy::ReturnPartial)
        .expect("uniquely owned managed buffers should start collection")
        .await
    })
    .expect("collector task should be admitted");
  let collected = runtime
    .block_on(job)
    .expect("collector root poll should complete")
    .expect("collector task should finish")
    .expect("collection should drain both streams and observe reaping");

  let CollectedOutput { parts, status } = collected;
  assert!(
    status.success(),
    "helper should exit successfully: {status:?}"
  );
  let OutputParts {
    mut child,
    stdout,
    stderr,
    stdout_buffer,
    stderr_buffer,
    stdout_len,
    stderr_len,
    stdout_truncated,
    stderr_truncated,
    stdout_eof,
    stderr_eof,
    overflow_byte,
  } = parts;

  assert_eq!(stdout_len, BURST_STDOUT_BYTES);
  assert_eq!(stderr_len, BURST_STDERR_BYTES);
  assert_eq!(stdout_buffer.len(), stdout_capacity, "buffer must not grow");
  assert_eq!(stderr_buffer.len(), stderr_capacity, "buffer must not grow");
  assert_eq!(
    first_mismatch(&stdout_buffer.as_slice()[..stdout_len], &expected_stdout),
    None,
    "stdout prefix must match the patterned payload exactly"
  );
  assert_eq!(
    first_mismatch(&stderr_buffer.as_slice()[..stderr_len], &expected_stderr),
    None,
    "stderr prefix must match the patterned payload exactly"
  );
  assert!(
    stdout_buffer.as_slice()[stdout_len..]
      .iter()
      .all(|byte| *byte == 0),
    "stdout slack beyond the payload must stay untouched"
  );
  assert!(
    stderr_buffer.as_slice()[stderr_len..]
      .iter()
      .all(|byte| *byte == 0),
    "stderr slack beyond the payload must stay untouched"
  );
  assert!(!stdout_truncated);
  assert!(!stderr_truncated);
  assert!(stdout_eof);
  assert!(stderr_eof);
  assert_eq!(overflow_byte, None);
  assert_eq!(
    child
      .try_wait()
      .expect("cached child status should be available"),
    Some(status)
  );

  let final_stdout_owner = stdout_buffer.clone();
  let final_stderr_owner = stderr_buffer.clone();
  drop((stdout, stderr));
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  drop(child);
  assert_eq!(
    resources.snapshot().managed_memory,
    total,
    "returned output keeps its managed charge until the buffers drop"
  );
  drop((stdout_buffer, stderr_buffer));
  assert_eq!(resources.snapshot().managed_memory, total);
  drop((final_stdout_owner, final_stderr_owner));
  assert_eq!(resources.snapshot().managed_memory, 0);

  runtime
    .block_on(scope.close())
    .expect("collector scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("process driver should stop after reaping");
  assert_eq!(driver.active_children(), 0);
  reactor.shutdown().expect("reactor should stop");
}

struct OverflowReport {
  limit_stream: OutputStream,
  stdout_len_at_limit: usize,
  stderr_len_at_limit: usize,
  stdout_prefix: Vec<u8>,
  overflow_byte: Option<(OutputStream, u8)>,
  stdout_truncated: bool,
  stderr_truncated: bool,
  stdout_eof_at_limit: bool,
  stdout_after_limit: (usize, usize),
  stderr_after_limit: (usize, usize),
  stderr_contents: Vec<u8>,
  status: ExitStatus,
  cached_status: Option<ExitStatus>,
  waiters_after_cancel: usize,
  registrations_before_drop: usize,
  registrations_after_drop: usize,
  charged_bytes: usize,
  memory_with_buffers: usize,
  memory_after_cleanup: usize,
}

#[test]
fn owned_scope_distinguishes_exact_capacity_from_one_byte_overflow_and_recovers_parts() {
  let capacity = LIMIT_STDOUT_BYTES + LIMIT_STDERR_BYTES;
  let expected_stdout = patterned(STDOUT_SEED, LIMIT_STDOUT_BYTES + 1);
  let expected_stderr = patterned(STDERR_SEED, LIMIT_STDERR_BYTES);

  let mut driver = ProcessDriver::new(2).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  // The ledger fits exactly one pair of buffers, so the overflow case can
  // allocate only if the exact case released its charge.
  let resources = ledger(capacity);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("collector scope should open with the managed ledger");

  // Exact capacity: the one-byte probe observes EOF, not overflow.
  let mut exact_inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_EXACT,
    Stdio::piped(),
    LIMIT_STDOUT_BYTES,
    LIMIT_STDERR_BYTES,
  );
  let exact_job = scope
    .spawn(async move {
      handshake(&mut exact_inputs).await;
      OutputFuture::new(exact_inputs, OutputLimitPolicy::ReturnPartial)
        .expect("uniquely owned managed buffers should start collection")
        .await
    })
    .expect("exact-capacity task should be admitted");
  let exact = runtime
    .block_on(exact_job)
    .expect("exact-capacity root poll should complete")
    .expect("exact-capacity task should finish")
    .expect("exact-capacity output must reach EOF instead of LimitReached");
  assert!(
    exact.status.success(),
    "exact helper should exit successfully"
  );
  let parts = exact.parts;
  assert_eq!(parts.stdout_len, LIMIT_STDOUT_BYTES);
  assert_eq!(parts.stderr_len, LIMIT_STDERR_BYTES);
  assert_eq!(
    first_mismatch(
      parts.stdout_buffer.as_slice(),
      &expected_stdout[..LIMIT_STDOUT_BYTES]
    ),
    None
  );
  assert_eq!(
    first_mismatch(parts.stderr_buffer.as_slice(), &expected_stderr),
    None
  );
  assert!(!parts.stdout_truncated);
  assert!(!parts.stderr_truncated);
  assert!(parts.stdout_eof);
  assert!(parts.stderr_eof);
  assert_eq!(parts.overflow_byte, None);
  drop(parts);
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(reactor_handle.registrations(), 0);

  // One byte past the capacity: ReturnPartial hands back the probe byte with
  // every owned part. The caller then continues and cleans up explicitly.
  let mut overflow_inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_OVERFLOW,
    Stdio::piped(),
    LIMIT_STDOUT_BYTES,
    LIMIT_STDERR_BYTES,
  );
  let task_reactor = reactor_handle.clone();
  let task_resources = resources.clone();
  let overflow_job = scope
    .spawn(async move {
      handshake(&mut overflow_inputs).await;
      let failure = match OutputFuture::new(overflow_inputs, OutputLimitPolicy::ReturnPartial)
        .expect("uniquely owned managed buffers should start collection")
        .await
      {
        Ok(collected) => panic!("one byte past capacity must not complete normally: {collected:?}"),
        Err(failure) => failure,
      };
      let limit_stream = match &failure.kind {
        OutputFailureKind::LimitReached(stream) => *stream,
        other => panic!("overflow must report LimitReached, got {other:?}"),
      };
      let mut parts = failure
        .parts
        .expect("ReturnPartial must return every owned part");

      let stdout_len_at_limit = parts.stdout_len;
      let stderr_len_at_limit = parts.stderr_len;
      let stdout_prefix = parts.stdout_buffer.as_slice()[..parts.stdout_len].to_vec();
      let overflow_byte = parts.overflow_byte;
      let stdout_truncated = parts.stdout_truncated;
      let stderr_truncated = parts.stderr_truncated;
      let stdout_eof_at_limit = parts.stdout_eof;

      // Continue on the recovered endpoints. The probe byte lives only in
      // `overflow_byte`. Reading on must reach EOF without re-delivering it.
      let stdout_storage = parts
        .stdout_buffer
        .get_mut()
        .expect("recovered stdout buffer remains uniquely owned");
      let stdout_after_limit =
        continue_into(&mut parts.stdout, stdout_storage, parts.stdout_len).await;
      let stderr_storage = parts
        .stderr_buffer
        .get_mut()
        .expect("recovered stderr buffer remains uniquely owned");
      let stderr_after_limit =
        continue_into(&mut parts.stderr, stderr_storage, parts.stderr_len).await;
      let stderr_contents = parts.stderr_buffer.as_slice()[..stderr_after_limit.0].to_vec();

      let status = parts
        .child
        .wait()
        .await
        .expect("recovered child should be waited explicitly");
      let cached_status = parts
        .child
        .try_wait()
        .expect("cached child status should be available");

      let OutputParts {
        child,
        mut stdout,
        mut stderr,
        stdout_buffer,
        stderr_buffer,
        ..
      } = parts;
      stdout.cancel_io_waits();
      stderr.cancel_io_waits();
      let waiters_after_cancel = task_reactor.waiters();
      let registrations_before_drop = task_reactor.registrations();
      drop((stdout, stderr));
      let registrations_after_drop = task_reactor.registrations();
      drop(child);
      let charged_bytes = stdout_buffer.charged_bytes() + stderr_buffer.charged_bytes();
      let memory_with_buffers = task_resources.snapshot().managed_memory;
      drop((stdout_buffer, stderr_buffer));
      let memory_after_cleanup = task_resources.snapshot().managed_memory;

      OverflowReport {
        limit_stream,
        stdout_len_at_limit,
        stderr_len_at_limit,
        stdout_prefix,
        overflow_byte,
        stdout_truncated,
        stderr_truncated,
        stdout_eof_at_limit,
        stdout_after_limit,
        stderr_after_limit,
        stderr_contents,
        status,
        cached_status,
        waiters_after_cancel,
        registrations_before_drop,
        registrations_after_drop,
        charged_bytes,
        memory_with_buffers,
        memory_after_cleanup,
      }
    })
    .expect("overflow task should be admitted");
  let report = runtime
    .block_on(overflow_job)
    .expect("overflow root poll should complete")
    .expect("overflow task should finish");

  assert_eq!(report.limit_stream, OutputStream::Stdout);
  assert_eq!(report.stdout_len_at_limit, LIMIT_STDOUT_BYTES);
  assert!(report.stderr_len_at_limit <= LIMIT_STDERR_BYTES);
  assert_eq!(
    first_mismatch(
      &report.stdout_prefix,
      &expected_stdout[..LIMIT_STDOUT_BYTES]
    ),
    None
  );
  assert_eq!(
    report.overflow_byte,
    Some((OutputStream::Stdout, expected_stdout[LIMIT_STDOUT_BYTES]))
  );
  assert!(report.stdout_truncated);
  assert!(!report.stderr_truncated);
  assert!(!report.stdout_eof_at_limit);
  assert_eq!(
    report.stdout_after_limit,
    (LIMIT_STDOUT_BYTES, 0),
    "the probe byte must not be replayed and nothing may follow it"
  );
  assert_eq!(report.stderr_after_limit, (LIMIT_STDERR_BYTES, 0));
  assert_eq!(report.stderr_contents, expected_stderr);
  assert!(
    report.status.success(),
    "overflow helper should exit after its final byte is consumed"
  );
  assert_eq!(report.cached_status, Some(report.status));
  assert_eq!(report.waiters_after_cancel, 0);
  assert_eq!(report.registrations_before_drop, 2);
  assert_eq!(report.registrations_after_drop, 0);
  assert_eq!(report.charged_bytes, capacity);
  assert_eq!(report.memory_with_buffers, capacity);
  assert_eq!(report.memory_after_cleanup, 0);

  runtime
    .block_on(scope.close())
    .expect("collector scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("process driver should stop after reaping");
  assert_eq!(driver.active_children(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  reactor.shutdown().expect("reactor should stop");
}

struct CancelReport {
  waiters_while_pending: usize,
  registrations_while_pending: usize,
  memory_while_pending: usize,
  waiters_after_drop: usize,
  registrations_after_drop: usize,
  memory_after_drop: usize,
}

#[test]
fn dropping_pending_collector_cancels_waiters_while_reaper_keeps_detached_child() {
  let buffers = 2 * DETACHED_BUFFER_BYTES;
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let resources = ledger(buffers);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("collector scope should open with the managed ledger");

  // The release gate is a pipe outside ProcessChild. Collector construction
  // closes only ProcessChild stdin, so it cannot release this gate.
  let (gate_reader, mut gate_writer) = io::pipe().expect("gate pipe should open");
  let mut inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_DETACHED,
    Stdio::from(gate_reader),
    DETACHED_BUFFER_BYTES,
    DETACHED_BUFFER_BYTES,
  );
  inputs.child.set_kill_on_drop(false);
  assert!(
    inputs.child.take_stdin().is_none(),
    "the gate is not owned by ProcessChild"
  );
  assert_eq!(resources.snapshot().managed_memory, buffers);

  let task_reactor = reactor_handle.clone();
  let task_resources = resources.clone();
  let job = scope
    .spawn(async move {
      handshake(&mut inputs).await;
      let mut collector = Box::pin(
        OutputFuture::new(inputs, OutputLimitPolicy::ReturnPartial)
          .expect("uniquely owned managed buffers should start collection"),
      );
      // Cancel only after the collector itself returned Pending with both
      // pipe readiness waiters retained. A budget-limited Pending wakes
      // itself, so this task is polled again.
      let observed = poll_fn(|cx| match collector.as_mut().poll(cx) {
        Poll::Pending if task_reactor.waiters() == 2 => Poll::Ready(Ok((
          task_reactor.waiters(),
          task_reactor.registrations(),
          task_resources.snapshot().managed_memory,
        ))),
        Poll::Pending => Poll::Pending,
        Poll::Ready(output) => Poll::Ready(Err(format!("{output:?}"))),
      })
      .await;
      let (waiters_while_pending, registrations_while_pending, memory_while_pending) = observed?;

      // Dropping the pending collector cancels its completion waiter and
      // drops the child handle, endpoints, and managed buffers it owns.
      drop(collector);
      Ok::<CancelReport, String>(CancelReport {
        waiters_while_pending,
        registrations_while_pending,
        memory_while_pending,
        waiters_after_drop: task_reactor.waiters(),
        registrations_after_drop: task_reactor.registrations(),
        memory_after_drop: task_resources.snapshot().managed_memory,
      })
    })
    .expect("cancellation task should be admitted");
  let report = runtime
    .block_on(job)
    .expect("cancellation root poll should complete")
    .expect("cancellation task should finish")
    .unwrap_or_else(|completed| {
      panic!("collector must be pending before cancellation, but completed: {completed}")
    });

  assert_eq!(report.waiters_while_pending, 2);
  assert_eq!(report.registrations_while_pending, 2);
  assert_eq!(
    report.memory_while_pending, buffers,
    "the pending collector owns both managed buffers"
  );
  assert_eq!(report.waiters_after_drop, 0);
  assert_eq!(report.registrations_after_drop, 0);
  assert_eq!(
    report.memory_after_drop, 0,
    "cancellation must release the collector-owned managed buffers"
  );

  // The dropped handle detached the child. The reaper still holds its slot
  // because the child is blocked on the gate and has not exited.
  assert_eq!(driver.active_children(), 1);
  // This write fails with EPIPE unless a live child still holds the gate's
  // read end. Success proves the detach did not kill it (kill_on_drop is off).
  gate_writer
    .write_all(b"g")
    .expect("detached child must still hold the gate after cancellation");
  drop(gate_writer);

  // Gap in the supplied API: once the ProcessChild handle drops with the
  // collector, nothing public exposes that child's exit status. Reaping is
  // shown only by `ProcessDriver::shutdown(Wait)` returning (it waits until
  // the reaper observes termination) and `active_children()` reaching zero.
  // The collector's internal fill counts are private, so the bytes copied
  // before cancellation cannot be observed either.
  runtime
    .block_on(scope.close())
    .expect("collector scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("shutdown must wait for the reaper to observe the detached child exit");
  assert_eq!(driver.active_children(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[test]
fn stderr_overflow_returns_original_parts_and_resumes_without_replaying_probe() {
  let stdout_expected = patterned(STDOUT_SEED, LIMIT_STDOUT_BYTES);
  let stderr_expected = patterned(STDERR_SEED, LIMIT_STDERR_BYTES + 1);
  let capacity = LIMIT_STDOUT_BYTES + LIMIT_STDERR_BYTES;
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let resources = ledger(capacity);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("collector scope should open");
  let inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_OVERFLOW_STDERR,
    Stdio::piped(),
    LIMIT_STDOUT_BYTES,
    LIMIT_STDERR_BYTES,
  );
  let job = scope
    .spawn(async move {
      let mut inputs = inputs;
      handshake(&mut inputs).await;
      let failure = OutputFuture::new(inputs, OutputLimitPolicy::ReturnPartial)
        .expect("output buffers should be unique")
        .await
        .expect_err("stderr's extra byte must be returned with the parts");
      let stream = match failure.kind {
        OutputFailureKind::LimitReached(stream) => stream,
        other => panic!("expected a stream limit, got {other:?}"),
      };
      let mut parts = failure.parts.expect("ReturnPartial retains all owners");
      let stdout_len = parts.stdout_len;
      let stderr_len = parts.stderr_len;
      let stdout_prefix = parts.stdout_buffer.as_slice()[..stdout_len].to_vec();
      let stderr_prefix = parts.stderr_buffer.as_slice()[..stderr_len].to_vec();
      let probe = parts.overflow_byte;
      let stdout_after = {
        let filled = parts.stdout_len;
        let storage = parts
          .stdout_buffer
          .get_mut()
          .expect("stdout owner is unique");
        continue_into(&mut parts.stdout, storage, filled).await
      };
      let stderr_after = {
        let filled = parts.stderr_len;
        let storage = parts
          .stderr_buffer
          .get_mut()
          .expect("stderr owner is unique");
        continue_into(&mut parts.stderr, storage, filled).await
      };
      let stdout_all = parts.stdout_buffer.as_slice()[..stdout_after.0].to_vec();
      let stderr_all = parts.stderr_buffer.as_slice()[..stderr_after.0].to_vec();
      let status = parts
        .child
        .wait()
        .await
        .expect("recovered child should reap");
      (
        stream,
        stdout_len,
        stderr_len,
        stdout_prefix,
        stderr_prefix,
        probe,
        stdout_after,
        stderr_after,
        stdout_all,
        stderr_all,
        status,
      )
    })
    .expect("overflow task should be admitted");
  let report = runtime
    .block_on(job)
    .expect("overflow root poll should complete")
    .expect("overflow task should finish");
  assert_eq!(report.0, OutputStream::Stderr);
  assert!(report.1 <= LIMIT_STDOUT_BYTES);
  assert_eq!(report.2, LIMIT_STDERR_BYTES);
  assert_eq!(report.3, stdout_expected[..report.1]);
  assert_eq!(report.4, stderr_expected[..LIMIT_STDERR_BYTES]);
  assert_eq!(
    report.5,
    Some((OutputStream::Stderr, stderr_expected[LIMIT_STDERR_BYTES]))
  );
  assert_eq!(report.6, (LIMIT_STDOUT_BYTES, 0));
  assert_eq!(report.7, (LIMIT_STDERR_BYTES, 0));
  // The first stderr overflow may be observed before stdout has filled: the
  // collector reads stderr first. The recovered reader must still produce
  // the complete stdout payload when resumed.
  assert_eq!(report.8, stdout_expected);
  assert_eq!(report.9, stderr_expected[..LIMIT_STDERR_BYTES]);
  assert!(report.10.success());
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  runtime
    .block_on(scope.close())
    .expect("scope close witnesses cleanup");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("driver should reap");
  assert_eq!(driver.active_children(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[test]
fn kill_and_wait_overflow_preserves_the_prefix_probe_and_reaps() {
  let capacity = LIMIT_STDOUT_BYTES + LIMIT_STDERR_BYTES;
  let expected_stdout = patterned(STDOUT_SEED, KILL_PAYLOAD_BYTES);
  let expected_stderr = patterned(STDERR_SEED, KILL_PAYLOAD_BYTES);
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let resources = ledger(capacity);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("collector scope should open");
  let (gate_reader, gate_writer) = io::pipe().expect("kill-policy gate should open");
  let mut inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_KILL_OVERFLOW,
    Stdio::from(gate_reader),
    LIMIT_STDOUT_BYTES,
    LIMIT_STDERR_BYTES,
  );
  inputs.child.set_kill_on_drop(true);
  let job = scope
    .spawn(async move {
      handshake(&mut inputs).await;
      OutputFuture::new(inputs, OutputLimitPolicy::KillAndWait)
        .expect("output buffers should be unique")
        .await
        .expect("KillAndWait should drain and retain its completed parts")
    })
    .expect("kill-policy task should be admitted");
  let collected = runtime
    .block_on(job)
    .expect("kill-policy root poll should complete")
    .expect("kill-policy task should finish");
  let CollectedOutput { mut parts, status } = collected;
  assert!(
    !status.success(),
    "large finite overflow should trigger the kill policy"
  );
  assert_eq!(
    parts.overflow_byte,
    Some((OutputStream::Stderr, expected_stderr[LIMIT_STDERR_BYTES]))
  );
  assert!(parts.stdout_len <= LIMIT_STDOUT_BYTES);
  assert!(parts.stderr_len <= LIMIT_STDERR_BYTES);
  assert_eq!(parts.stderr_len, LIMIT_STDERR_BYTES);
  assert_eq!(
    parts.stdout_buffer.as_slice()[..parts.stdout_len],
    expected_stdout[..parts.stdout_len]
  );
  assert_eq!(
    parts.stderr_buffer.as_slice()[..parts.stderr_len],
    expected_stderr[..parts.stderr_len]
  );
  assert!(parts.stderr_truncated);
  assert!(parts.stdout_eof);
  assert!(parts.stderr_eof);
  assert_eq!(
    parts.child.try_wait().expect("cached status is readable"),
    Some(status)
  );
  drop(parts);
  drop(gate_writer);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .block_on(scope.close())
    .expect("scope close witnesses cleanup");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("driver should stop");
  assert_eq!(driver.active_children(), 0);
  reactor.shutdown().expect("reactor should stop");
}

#[test]
fn process_slot_rejection_preserves_and_retries_the_same_command_after_reap() {
  let mut driver = ProcessDriver::new(1).expect("single-child driver should start");
  let runtime = async_runtime();
  let mut first = driver
    .spawn(helper_command(MODE_HOLD, Stdio::piped()))
    .expect("first helper should own the only slot");
  first.set_kill_on_drop(true);
  let mut original = Command::new("/bin/true");
  original.arg("retained-through-full-slot");
  let (recovered, kind) = match driver.spawn(original) {
    Ok(_) => panic!("second command must be rejected while the first slot is live"),
    Err(error) => error.into_parts(),
  };
  assert!(matches!(
    kind,
    allocatbelt::runtime::process::SpawnErrorKind::Full
  ));
  assert_eq!(recovered.get_program(), "/bin/true");
  assert_eq!(
    recovered.get_args().collect::<Vec<_>>(),
    vec![std::ffi::OsStr::new("retained-through-full-slot")]
  );
  assert_eq!(driver.active_children(), 1);
  let first_status = runtime
    .block_on(first.kill_and_wait())
    .expect("first child wait should poll")
    .expect("first child should be reaped");
  assert!(!first_status.success());
  assert_eq!(driver.active_children(), 0);
  let mut retry = driver
    .spawn(recovered)
    .expect("the original rejected command should be retryable");
  assert!(
    runtime
      .block_on(retry.wait())
      .expect("retry wait should poll")
      .expect("retried command should be reaped")
      .success()
  );
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("driver should stop");
  assert_eq!(driver.active_children(), 0);
}

fn run_pending_cancellation(cancel_task: bool, kill_on_drop: bool) {
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let managed = 2 * DETACHED_BUFFER_BYTES + 64;
  let resources = ledger(managed);
  let retained = resources
    .try_alloc_zeroed(64)
    .expect("clone witness should fit");
  let retained_in_task = retained.clone();
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("cancel scope should open");
  let (gate_reader, mut gate_writer) = io::pipe().expect("external child gate should open");
  let mut inputs = launch(
    &driver,
    &reactor_handle,
    &resources,
    MODE_DETACHED,
    Stdio::from(gate_reader),
    DETACHED_BUFFER_BYTES,
    DETACHED_BUFFER_BYTES,
  );
  inputs.child.set_kill_on_drop(kill_on_drop);
  let task_reactor = reactor_handle.clone();
  let task_resources = resources.clone();
  let (pending_tx, pending_rx) = std::sync::mpsc::channel();
  let mut pending_tx = Some(pending_tx);
  let job = scope
    .spawn(async move {
      let retained_clone = retained_in_task;
      handshake(&mut inputs).await;
      let mut collector = Box::pin(
        OutputFuture::new(inputs, OutputLimitPolicy::ReturnPartial)
          .expect("collector buffers are unique"),
      );
      poll_fn(|cx| {
        assert_eq!(retained_clone.charged_bytes(), 64);
        match collector.as_mut().poll(cx) {
          Poll::Pending if task_reactor.waiters() == 2 => {
            if let Some(sender) = pending_tx.take() {
              sender
                .send((
                  task_reactor.registrations(),
                  task_resources.snapshot().managed_memory,
                ))
                .expect("parent remains to cancel the observed pending task");
            }
            Poll::<()>::Pending
          }
          Poll::Pending => Poll::<()>::Pending,
          Poll::Ready(result) => panic!("gated collector completed unexpectedly: {result:?}"),
        }
      })
      .await;
    })
    .expect("pending collector task should be admitted");
  let (registrations_pending, memory_pending) = pending_rx
    .recv_timeout(WATCHDOG)
    .expect("collector must actually observe both pending pipe waiters");
  assert_eq!(registrations_pending, 2);
  assert_eq!(memory_pending, managed);
  let abort_join_result = if cancel_task {
    job.abort();
    let timer = TimerDriver::new(1).expect("abort join timeout driver should start");
    let joined = runtime.block_on(
      timer
        .handle()
        .timeout(CANCEL_JOIN_TIMEOUT, job)
        .expect("abort join timeout should be admitted"),
    );
    timer
      .shutdown()
      .expect("abort join timeout driver should stop");
    Some(joined)
  } else {
    None
  };
  let abort_join_cancelled = abort_join_result
    .as_ref()
    .is_some_and(|joined| matches!(joined, Ok(Ok(Err(AsyncJoinError::Cancelled)))));
  runtime
    .block_on(scope.close())
    .expect("task or scope cancellation must finish future destruction");
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(
    resources.snapshot().managed_memory,
    64,
    "the root clone retains its charge"
  );

  if kill_on_drop {
    driver
      .shutdown(ProcessShutdownMode::Wait)
      .expect("kill-on-drop request must be reaped before shutdown returns");
    match gate_writer.write(b"release") {
      Err(error) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
      Ok(_) => panic!("kill-on-drop must close the blocked helper's gate reader"),
    }
    drop(gate_writer);
  } else {
    assert_eq!(
      driver.active_children(),
      1,
      "detach retains the live process slot"
    );
    gate_writer
      .write_all(b"release")
      .expect("detached child still owns the explicit gate reader");
    drop(gate_writer);
    driver
      .shutdown(ProcessShutdownMode::Wait)
      .expect("reaper must finish the detached child before shutdown returns");
  }
  assert_eq!(driver.active_children(), 0);
  drop(retained);
  assert_eq!(
    resources.snapshot().managed_memory,
    0,
    "final clone returns the charge"
  );
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  reactor.shutdown().expect("reactor should stop");
  if cancel_task {
    assert!(
      abort_join_cancelled,
      "task abort must publish its cancelled join result before scope close: {abort_join_result:?}"
    );
  }
}

#[test]
fn task_and_scope_cancellation_follow_real_pending_output_and_release_waiters() {
  run_pending_cancellation(true, true);
  run_pending_cancellation(false, false);
}

#[test]
fn one_worker_runs_a_gated_sibling_after_producer_completion_while_collector_is_pending() {
  let temporary = std::env::temp_dir().join(format!(
    "allocatbelt-process-output-{}-{}",
    std::process::id(),
    NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
  ));
  std::fs::create_dir(&temporary).expect("unique temporary directory should be created");
  let socket_path = temporary.join("payload-complete.sock");
  let receiver = UnixDatagram::bind(&socket_path).expect("parent event socket should bind");
  receiver
    .set_read_timeout(Some(WATCHDOG))
    .expect("completion event wait should be bounded");
  let mut driver = ProcessDriver::new(1).expect("process driver should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let resources = ledger(BURST_STDOUT_BYTES + BURST_STDERR_BYTES + 64);
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("shared one-worker scope should open");
  let (gate_reader, mut gate_writer) = io::pipe().expect("external gate should open");
  let mut command = helper_command(MODE_BURST_HOLD, Stdio::from(gate_reader));
  command.env(HELPER_NOTIFY_ENV, &socket_path);
  let inputs = launch_command(
    &driver,
    &reactor_handle,
    &resources,
    command,
    BURST_STDOUT_BYTES,
    BURST_STDERR_BYTES,
  );

  let (sibling_release_tx, sibling_release_rx) = oneshot::channel();
  let (sibling_started_tx, sibling_started_rx) = std::sync::mpsc::channel();
  let sibling = scope
    .spawn(async move {
      sibling_started_tx
        .send(())
        .expect("parent tracks sibling admission");
      sibling_release_rx
        .await
        .expect("parent releases sibling after pending-state witness");
    })
    .expect("gated sibling should be admitted first");
  sibling_started_rx
    .recv_timeout(WATCHDOG)
    .expect("sibling must reach its gate before collector admission");

  let task_reactor = reactor_handle.clone();
  let (payload_done_tx, payload_done_rx) = oneshot::channel();
  let (pending_tx, pending_rx) = std::sync::mpsc::channel();
  let output_job = scope
    .spawn(async move {
      let mut inputs = inputs;
      handshake(&mut inputs).await;
      let mut collector = Box::pin(
        OutputFuture::new(inputs, OutputLimitPolicy::ReturnPartial)
          .expect("output buffers should be unique"),
      );
      let mut payload_done = Box::pin(payload_done_rx);
      let mut payload_reported = false;
      let mut pending_report = Some(pending_tx);
      poll_fn(|cx| {
        let result = collector.as_mut().poll(cx);
        if let Poll::Ready(result) = result {
          return Poll::Ready(result.expect("held burst must collect successfully"));
        }
        if !payload_reported && let Poll::Ready(Ok(())) = payload_done.as_mut().poll(cx) {
          payload_reported = true;
        }
        if payload_reported && pending_report.is_some() && task_reactor.waiters() == 2 {
          pending_report
            .take()
            .expect("pending-state sender is present")
            .send(())
            .expect("parent waits for the producer-complete pending state");
        } else if payload_reported && pending_report.is_some() {
          // Keep polling after the producer event until both endpoints have
          // pending registrations. This records a pending state; it does not
          // establish that all bytes already written to the kernel pipes have
          // been drained.
          cx.waker().wake_by_ref();
        }
        Poll::Pending
      })
      .await
    })
    .expect("collector task should be admitted beside the sibling");

  let mut event = [0_u8; 8];
  let (event_bytes, _) = receiver
    .recv_from(&mut event)
    .expect("helper must report that it finished writing both finite payloads");
  assert_eq!(&event[..event_bytes], &[1]);
  payload_done_tx
    .send(())
    .expect("collector task still waits");
  pending_rx
    .recv_timeout(WATCHDOG)
    .expect("after producer completion, collector must reach two pending readers");
  sibling_release_tx
    .send(())
    .expect("sibling is released after the producer-complete pending witness");
  runtime
    .block_on(sibling)
    .expect("sibling join poll should complete")
    .expect("single worker must finish the sibling while child exit remains externally gated");
  gate_writer
    .write_all(b"release")
    .expect("child remains blocked until after sibling completion");
  drop(gate_writer);

  let collected = runtime
    .block_on(output_job)
    .expect("collector root poll should complete")
    .expect("collector task should finish");
  assert!(collected.status.success());
  assert_eq!(collected.parts.stdout_len, BURST_STDOUT_BYTES);
  assert_eq!(collected.parts.stderr_len, BURST_STDERR_BYTES);
  assert_eq!(
    &collected.parts.stdout_buffer.as_slice()[..BURST_STDOUT_BYTES],
    patterned(STDOUT_SEED, BURST_STDOUT_BYTES)
  );
  assert_eq!(
    &collected.parts.stderr_buffer.as_slice()[..BURST_STDERR_BYTES],
    patterned(STDERR_SEED, BURST_STDERR_BYTES)
  );
  drop(collected);
  runtime
    .block_on(scope.close())
    .expect("scope close witnesses task cleanup");
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  driver
    .shutdown(ProcessShutdownMode::Wait)
    .expect("process should be reaped");
  assert_eq!(driver.active_children(), 0);
  reactor.shutdown().expect("reactor should stop");
  drop(receiver);
  std::fs::remove_file(&socket_path).expect("temporary completion socket should be removed");
  std::fs::remove_dir(&temporary).expect("temporary event directory should be removed");
}

#[test]
#[ignore = "re-entered helper child; inert unless ALLOCATBELT_PROCESS_OUTPUT_HELPER_MODE is set"]
fn process_output_helper_child() {
  let Some(mode) = std::env::var_os(HELPER_MODE_ENV) else {
    return;
  };
  let mode = mode
    .into_string()
    .expect("helper mode should be valid UTF-8");
  run_helper(&mode);
}

fn run_helper(mode: &str) -> ! {
  assert!(
    matches!(
      mode,
      MODE_BURST
        | MODE_EXACT
        | MODE_OVERFLOW
        | MODE_OVERFLOW_STDERR
        | MODE_DETACHED
        | MODE_BURST_HOLD
        | MODE_KILL_OVERFLOW
        | MODE_HOLD
        | MODE_BUDGET_READ
        | MODE_BUDGET_WRITE
        | MODE_HOT_READ
        | MODE_BACKPRESSURE
    ),
    "unknown helper mode {mode:?}"
  );
  announce_ready();
  match mode {
    MODE_BURST => {
      wait_for_stdin_eof();
      write_interleaved(
        &patterned(STDOUT_SEED, BURST_STDOUT_BYTES),
        &patterned(STDERR_SEED, BURST_STDERR_BYTES),
      );
    }
    MODE_EXACT => {
      wait_for_stdin_eof();
      write_sequential(
        &patterned(STDOUT_SEED, LIMIT_STDOUT_BYTES),
        &patterned(STDERR_SEED, LIMIT_STDERR_BYTES),
      );
    }
    MODE_OVERFLOW => {
      wait_for_stdin_eof();
      write_sequential(
        &patterned(STDOUT_SEED, LIMIT_STDOUT_BYTES + 1),
        &patterned(STDERR_SEED, LIMIT_STDERR_BYTES),
      );
    }
    MODE_OVERFLOW_STDERR => {
      wait_for_stdin_eof();
      write_sequential(
        &patterned(STDOUT_SEED, LIMIT_STDOUT_BYTES),
        &patterned(STDERR_SEED, LIMIT_STDERR_BYTES + 1),
      );
    }
    MODE_KILL_OVERFLOW => {
      write_sequential(
        &patterned(STDOUT_SEED, KILL_PAYLOAD_BYTES),
        &patterned(STDERR_SEED, KILL_PAYLOAD_BYTES),
      );
      // The parent keeps this distinct stdin gate open. KillAndWait must
      // terminate the helper after the fixed output limit is crossed.
      wait_for_gate_byte();
    }
    MODE_HOLD => wait_for_stdin_eof(),
    MODE_BURST_HOLD => {
      write_interleaved(
        &patterned(STDOUT_SEED, BURST_STDOUT_BYTES),
        &patterned(STDERR_SEED, BURST_STDERR_BYTES),
      );
      notify_payload_complete();
      wait_for_gate_byte();
    }
    MODE_BUDGET_READ => {
      write_sequential(&patterned(BUDGET_PATTERN_SEED, BUDGET_PAYLOAD_BYTES), &[]);
      notify_payload_complete();
      wait_for_gate_byte();
    }
    MODE_HOT_READ => {
      write_sequential(&patterned(BUDGET_PATTERN_SEED, HOT_PAYLOAD_BYTES), &[]);
      notify_payload_complete();
      wait_for_gate_byte();
    }
    MODE_BUDGET_WRITE => run_gated_stdin_report(BUDGET_PATTERN_SEED),
    MODE_BACKPRESSURE => run_gated_stdin_report(PIPE_PATTERN_SEED),
    MODE_DETACHED => wait_for_gate_byte(),
    other => unreachable!("validated helper mode {other:?}"),
  }
  // Exit before libtest can append its result line to the collected pipes.
  std::process::exit(0)
}

fn run_gated_stdin_report(seed: u64) {
  let control_path = std::env::var_os(HELPER_CONTROL_ENV)
    .map(PathBuf::from)
    .expect("gated-input mode requires its control socket path");
  let notify_path = std::env::var_os(HELPER_NOTIFY_ENV)
    .map(PathBuf::from)
    .expect("gated-input mode requires its parent's notification socket");
  let socket = UnixDatagram::bind(control_path).expect("child control socket should bind");
  socket
    .set_read_timeout(Some(WATCHDOG))
    .expect("child control receive should be bounded");
  socket
    .send_to(b"ready", &notify_path)
    .expect("child should report its independent input gate");
  let mut command = [0_u8; 32];
  let command_len = socket
    .recv(&mut command)
    .expect("parent should release the independent input gate");
  let command =
    std::str::from_utf8(&command[..command_len]).expect("control command should be UTF-8");
  let expected_len = command
    .strip_prefix("go:")
    .expect("parent should send a bounded go command")
    .parse::<usize>()
    .expect("expected input length should be an integer");
  assert!(expected_len <= BACKPRESSURE_BYTE_CEILING + 1);

  let mut received = Vec::with_capacity(expected_len);
  let mut chunk = [0_u8; 8192];
  let stdin = io::stdin();
  let mut stdin = stdin.lock();
  loop {
    let count = stdin
      .read(&mut chunk)
      .expect("child stdin should read after its gate opens");
    if count == 0 {
      break;
    }
    assert!(
      received.len() + count <= expected_len,
      "parent wrote extra bytes"
    );
    for byte in &chunk[..count] {
      assert_eq!(*byte, pattern_byte(seed, received.len()));
      received.push(*byte);
    }
  }
  assert_eq!(
    received.len(),
    expected_len,
    "child should receive every accepted byte"
  );
  if seed == BUDGET_PATTERN_SEED {
    socket
      .send_to(&received, &notify_path)
      .expect("child should report the exact small write stream");
  } else {
    let report = format!("done:{}", received.len());
    socket
      .send_to(report.as_bytes(), &notify_path)
      .expect("child should report the exact backpressure byte count");
  }
}

fn notify_payload_complete() {
  let path = std::env::var_os(HELPER_NOTIFY_ENV)
    .expect("held burst mode requires its parent's notification socket");
  let socket = UnixDatagram::unbound().expect("helper notification socket should open");
  socket
    .send_to(&[1], Path::new(&path))
    .expect("payload completion should be reported to the parent");
}

fn announce_ready() {
  let mut stdout = io::stdout().lock();
  stdout
    .write_all(READY_MARKER)
    .expect("helper stdout marker should be written");
  stdout.flush().expect("helper stdout marker should flush");
  drop(stdout);
  let mut stderr = io::stderr().lock();
  stderr
    .write_all(READY_MARKER)
    .expect("helper stderr marker should be written");
  stderr.flush().expect("helper stderr marker should flush");
}

fn wait_for_stdin_eof() {
  let mut unexpected = Vec::new();
  io::stdin()
    .lock()
    .read_to_end(&mut unexpected)
    .expect("helper stdin gate should close cleanly");
  assert!(
    unexpected.is_empty(),
    "the collector must close stdin without writing"
  );
}

fn wait_for_gate_byte() {
  let mut byte = [0_u8; 1];
  let _released = io::stdin()
    .lock()
    .read(&mut byte)
    .expect("helper gate read should succeed");
}

fn write_interleaved(stdout_payload: &[u8], stderr_payload: &[u8]) {
  let mut stdout = io::stdout().lock();
  let mut stderr = io::stderr().lock();
  let mut stdout_written = 0;
  let mut stderr_written = 0;
  while stdout_written < stdout_payload.len() || stderr_written < stderr_payload.len() {
    if stdout_written < stdout_payload.len() {
      let end = (stdout_written + INTERLEAVE_CHUNK).min(stdout_payload.len());
      stdout
        .write_all(&stdout_payload[stdout_written..end])
        .expect("helper stdout chunk should be written");
      stdout.flush().expect("helper stdout chunk should flush");
      stdout_written = end;
    }
    if stderr_written < stderr_payload.len() {
      let end = (stderr_written + INTERLEAVE_CHUNK).min(stderr_payload.len());
      stderr
        .write_all(&stderr_payload[stderr_written..end])
        .expect("helper stderr chunk should be written");
      stderr.flush().expect("helper stderr chunk should flush");
      stderr_written = end;
    }
  }
}

fn write_sequential(stdout_payload: &[u8], stderr_payload: &[u8]) {
  let mut stderr = io::stderr().lock();
  stderr
    .write_all(stderr_payload)
    .expect("helper stderr payload should be written");
  stderr.flush().expect("helper stderr payload should flush");
  drop(stderr);
  let mut stdout = io::stdout().lock();
  stdout
    .write_all(stdout_payload)
    .expect("helper stdout payload should be written");
  stdout.flush().expect("helper stdout payload should flush");
}
