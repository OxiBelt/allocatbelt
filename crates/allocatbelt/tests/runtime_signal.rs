#![cfg(feature = "runtime")]

use std::future::Future;
use std::os::unix::process::ExitStatusExt;
use std::pin::Pin;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::signal::{Signal, SignalDriver, SignalError, SignalKind};

const PROBE_ENV: &str = "ALLOCATBELT_RUNTIME_SIGNAL_PROBE";
const LIMIT: Duration = Duration::from_secs(10);

struct ThreadWake(thread::Thread);
impl Wake for ThreadWake {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }
}

fn await_signal(signal: &mut Signal) {
  let deadline = Instant::now() + LIMIT;
  let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
  let mut cx = Context::from_waker(&waker);
  let mut future = signal.recv();
  loop {
    match Pin::new(&mut future).poll(&mut cx) {
      Poll::Ready(result) => {
        result.unwrap();
        return;
      }
      Poll::Pending => {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "real signal delivery timed out");
        thread::park_timeout(remaining);
      }
    }
  }
}

fn isolated(test: &str, probe: fn()) {
  if std::env::var(PROBE_ENV).as_deref() == Ok(test) {
    probe();
    return;
  }
  let status = subprocess_status(test);
  assert!(status.success(), "signal subprocess failed: {status}");
}

fn subprocess_status(test: &str) -> ExitStatus {
  // Only the subprocess changes dispositions. The test runner's handlers and
  // process-global singleton are never touched by these tests.
  let mut child = Command::new(std::env::current_exe().unwrap())
    .args(["--exact", test, "--nocapture"])
    .env(PROBE_ENV, test)
    .spawn()
    .unwrap();
  let deadline = Instant::now() + LIMIT + Duration::from_secs(5);
  loop {
    if let Some(status) = child.try_wait().unwrap() {
      return status;
    }
    if Instant::now() >= deadline {
      let _ = child.kill();
      let _ = child.wait();
      panic!("signal subprocess timed out");
    }
    thread::sleep(Duration::from_millis(5));
  }
}

#[test]
fn real_signal_reaches_multiple_drivers_and_cancellation_preserves_delivery() {
  isolated(
    "real_signal_reaches_multiple_drivers_and_cancellation_preserves_delivery",
    || {
      let driver = SignalDriver::new(2).unwrap();
      let other = SignalDriver::new(2).unwrap();
      let mut first = driver.subscribe(SignalKind::user_defined1()).unwrap();
      let mut second = other.subscribe(SignalKind::user_defined1()).unwrap();
      let mut cancelled = first.recv();
      assert!(
        Pin::new(&mut cancelled)
          .poll(&mut Context::from_waker(Waker::noop()))
          .is_pending()
      );
      drop(cancelled);
      rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::USR1)
        .unwrap();
      await_signal(&mut first);
      await_signal(&mut second);
      assert_eq!(first.try_recv(), Ok(false));
      assert_eq!(second.try_recv(), Ok(false));
      drop(first);
      drop(second);
      let mut reused = driver.subscribe(SignalKind::user_defined2()).unwrap();
      rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::USR2)
        .unwrap();
      await_signal(&mut reused);
    },
  );
}

#[test]
fn ctrl_c_registration_remains_valid_after_all_handles_drop() {
  isolated(
    "ctrl_c_registration_remains_valid_after_all_handles_drop",
    || {
      {
        let driver = SignalDriver::new(1).unwrap();
        let mut signal = driver.ctrl_c().unwrap();
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
          .unwrap();
        await_signal(&mut signal);
      }
      // Permanent registration suppresses the default termination behavior.
      rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
        .unwrap();
      thread::sleep(Duration::from_millis(20));
      let next = SignalDriver::new(1).unwrap();
      let mut signal = next.ctrl_c().unwrap();
      rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
        .unwrap();
      await_signal(&mut signal);
    },
  );
}

#[test]
fn full_listener_admission_does_not_install_an_unused_signal() {
  let name = "full_listener_admission_does_not_install_an_unused_signal";
  if std::env::var(PROBE_ENV).as_deref() == Ok(name) {
    let driver = SignalDriver::new(1).unwrap();
    let _held = driver.subscribe(SignalKind::user_defined1()).unwrap();
    assert!(matches!(
      driver.subscribe(SignalKind::terminate()),
      Err(SignalError::Full)
    ));
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
      .unwrap();
    panic!("rejected signal admission changed SIGTERM's default action");
  }
  assert_eq!(subprocess_status(name).signal(), Some(15));
}

#[test]
fn signal_driver_capacity_is_fixed_and_invalid_kinds_have_no_side_effects() {
  isolated(
    "signal_driver_capacity_is_fixed_and_invalid_kinds_have_no_side_effects",
    || {
      assert_eq!(SignalKind::from_raw(9), Err(SignalError::InvalidKind));
      assert!(matches!(
        SignalDriver::new(0),
        Err(SignalError::InvalidCapacity)
      ));
      let driver = SignalDriver::new(2).unwrap();
      assert_eq!(driver.max_listeners(), 2);
      assert!(matches!(
        SignalDriver::new(3),
        Err(SignalError::ConfigurationMismatch)
      ));
      assert!(!driver.is_closed());
      let mut signal = driver.subscribe(SignalKind::terminate()).unwrap();
      rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
      await_signal(&mut signal);
    },
  );
}
