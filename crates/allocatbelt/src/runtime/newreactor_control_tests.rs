use super::*;
use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Wake, Waker};
use std::time::Duration;

fn limits(control: usize) -> DomainResources {
  DomainResources::ZERO.with(DomainResource::Control, control)
}

fn controlled_domain(control: usize) -> (ResourceDomain, TenantDomain) {
  let domain = ResourceDomain::new(limits(control.max(1 << 20)), 1).unwrap();
  let tenant = domain.tenant(limits(control)).unwrap();
  (domain, tenant)
}

fn control_used(domain: &ResourceDomain) -> usize {
  domain.snapshot().used.get(DomainResource::Control)
}

#[test]
fn startup_and_registration_control_follow_their_final_owners() {
  let (domain, tenant) = controlled_domain(1 << 20);
  let baseline = control_used(&domain);
  let config = ReactorConfig {
    max_registrations: 2,
    max_waiters: 3,
  };
  let reactor = Reactor::new_in_tenant(config, &tenant).unwrap();
  let shared_control = reactor.shared.control_bytes();
  let owner_control = reactor._owner_control.bytes();
  let service_completion = reactor.thread.as_ref().unwrap().control_bytes();
  let state_payload = {
    let state = lock(&reactor.shared.state);
    state.slots.capacity() * std::mem::size_of::<Slot>()
      + state.free_slots.capacity() * std::mem::size_of::<u32>()
      + state.waiters.table.capacity() * std::mem::size_of::<Waiter>()
      + state.waiters.free.capacity() * std::mem::size_of::<u32>()
  };
  let callback_owner_payload =
    lock(&reactor.shared.callback_owners).capacity() * std::mem::size_of::<CallbackOwner>();
  let scratch_capacity = lock(&reactor.shared.callback_scratch)
    .as_ref()
    .unwrap()
    .capacity();
  let expected_shared = std::mem::size_of::<Shared>()
    + state_payload
    + callback_owner_payload
    + reactor.shared.dispatch_capacity * std::mem::size_of::<Waker>()
    + scratch_capacity * std::mem::size_of::<Waker>()
    + std::mem::size_of::<Vec<Waker>>()
    + 2 * std::mem::size_of::<Arc<Shared>>();
  assert_eq!(shared_control, expected_shared);
  let expected_owner = std::mem::size_of::<Reactor>()
    + reactor.lock_panic_payloads().capacity()
      * std::mem::size_of::<Box<dyn std::any::Any + Send>>()
    + reactor.close_thread_name.capacity()
    + reactor.thread_name_scratch_capacity
    + std::mem::size_of::<thread::Builder>();
  assert_eq!(owner_control, expected_owner);
  let startup = owner_control + shared_control + 2 * service_completion;
  assert_eq!(control_used(&domain), baseline + startup);

  let handle = reactor.handle();
  let handle_clone = handle.clone();
  assert_eq!(control_used(&domain), baseline + startup);
  let (stream, peer) = UnixStream::pair().unwrap();
  let registered = handle.register(stream).unwrap();
  assert_eq!(
    control_used(&domain),
    baseline + startup + std::mem::size_of::<Registration<UnixStream>>()
  );
  let registration_clone = registered.clone();
  drop(registered);
  assert_eq!(
    control_used(&domain),
    baseline + startup + std::mem::size_of::<Registration<UnixStream>>()
  );
  drop(registration_clone);
  assert_eq!(control_used(&domain), baseline + startup);
  drop(peer);
  drop(handle_clone);

  reactor.shutdown().unwrap();
  // The handle owns Shared after Reactor and both completion owners are gone.
  assert_eq!(control_used(&domain), baseline + shared_control);
  drop(handle);
  assert_eq!(control_used(&domain), baseline);
}

#[test]
fn constructor_control_refusal_rolls_back_and_preserves_typed_domain_error() {
  let config = ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  };
  let (roomy_domain, roomy_tenant) = controlled_domain(1 << 20);
  let roomy_baseline = control_used(&roomy_domain);
  let roomy = Reactor::new_in_tenant(config, &roomy_tenant).unwrap();
  let retained_bytes = control_used(&roomy_domain) - roomy_baseline;
  roomy.shutdown().unwrap();
  assert_eq!(control_used(&roomy_domain), roomy_baseline);

  let (domain, tenant) = controlled_domain(retained_bytes.saturating_sub(1));
  let baseline = control_used(&domain);
  let error = Reactor::new_in_tenant(config, &tenant).unwrap_err();
  assert!(matches!(
    ReactorError::of(&error),
    Some(ReactorError::Domain(
      DomainError::AboveCeiling(DomainResource::Control)
        | DomainError::Exhausted(DomainResource::Control)
    ))
  ));
  assert_eq!(control_used(&domain), baseline);

  let (zero_domain, zero_tenant) = controlled_domain(0);
  let zero_baseline = control_used(&zero_domain);
  let error = Reactor::new_in_tenant(config, &zero_tenant).unwrap_err();
  assert_eq!(
    ReactorError::of(&error),
    Some(ReactorError::Domain(DomainError::AboveCeiling(
      DomainResource::Control
    )))
  );
  assert_eq!(control_used(&zero_domain), zero_baseline);
}

#[test]
fn registration_control_refusal_returns_untouched_original_fd() {
  let (domain, tenant) = controlled_domain(1 << 20);
  let baseline = domain.snapshot().used;
  let reactor = Reactor::new_in_tenant(
    ReactorConfig {
      max_registrations: 1,
      max_waiters: 1,
    },
    &tenant,
  )
  .unwrap();
  let handle = reactor.handle();
  let used = tenant.snapshot().unwrap().used.get(DomainResource::Control);
  tenant.set_limits(limits(used)).unwrap();
  let before = domain.snapshot().used;
  let (stream, peer) = UnixStream::pair().unwrap();
  let fd = stream.as_raw_fd();
  let calls = Arc::new(AtomicUsize::new(0));
  assert!(
    !rustix::fs::fcntl_getfl(&stream)
      .unwrap()
      .contains(rustix::fs::OFlags::NONBLOCK)
  );

  let refused = handle
    .register(CountedAsFd {
      stream,
      calls: Arc::clone(&calls),
    })
    .unwrap_err();
  assert_eq!(
    ReactorError::of(refused.error()),
    Some(ReactorError::Domain(DomainError::Exhausted(
      DomainResource::Control
    )))
  );
  let (stream, _) = refused.into_parts();
  assert_eq!(stream.stream.as_raw_fd(), fd);
  assert_eq!(calls.load(Ordering::SeqCst), 0);
  assert!(
    !rustix::fs::fcntl_getfl(&stream.stream)
      .unwrap()
      .contains(rustix::fs::OFlags::NONBLOCK)
  );
  assert_eq!(handle.registrations(), 0);
  assert_eq!(lock(&handle.shared.state).slots[0].generation, 0);
  assert_eq!(domain.snapshot().used, before);

  drop(stream);
  drop(peer);
  reactor.shutdown().unwrap();
  drop(handle);
  assert_eq!(domain.snapshot().used, baseline);
}

struct CountedAsFd {
  stream: UnixStream,
  calls: Arc<AtomicUsize>,
}

impl AsFd for CountedAsFd {
  fn as_fd(&self) -> BorrowedFd<'_> {
    self.calls.fetch_add(1, Ordering::SeqCst);
    self.stream.as_fd()
  }
}

fn claim_callback(shared: &Shared) {
  lock(&shared.state).callbacks_pending += 1;
}

fn callback_done(shared: &Shared) {
  shared.finish_callbacks(1);
}

struct WakeCounter(Arc<AtomicUsize>);

impl Wake for WakeCounter {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

struct RegisterDuringWake {
  handle: ReactorHandle,
  stream: Mutex<Option<UnixStream>>,
  result: mpsc::Sender<bool>,
}

impl Wake for RegisterDuringWake {
  fn wake(self: Arc<Self>) {
    let stream = self.stream.lock().unwrap().take().unwrap();
    let registered = self.handle.register(stream).map(|registered| {
      drop(registered);
      true
    });
    self.result.send(registered.is_ok()).unwrap();
  }
}

#[test]
fn release_batch_returns_registration_slot_before_running_wakers() {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 1,
  })
  .unwrap();
  let handle = reactor.handle();
  let (stream, _peer) = UnixStream::pair().unwrap();
  let fd = handle.register(stream).unwrap();
  let (replacement, _replacement_peer) = UnixStream::pair().unwrap();
  let (result_tx, result_rx) = mpsc::channel();
  let waker = Waker::from(Arc::new(RegisterDuringWake {
    handle: handle.clone(),
    stream: Mutex::new(Some(replacement)),
    result: result_tx,
  }));
  let mut wait = fd.readable();
  let mut context = Context::from_waker(&waker);
  assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
  std::mem::forget(wait);
  drop(waker);

  drop(fd);
  assert!(result_rx.recv_timeout(Duration::from_secs(2)).unwrap());
  assert_eq!(handle.registrations(), 0);
  reactor.shutdown().unwrap();
}

#[test]
fn close_and_release_fallbacks_do_not_allocate_when_batch_scratch_is_leased() {
  let (reactor, handle) = {
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: 2,
      max_waiters: 2,
    })
    .unwrap();
    let handle = reactor.handle();
    (reactor, handle)
  };
  let scratch = reactor.shared.take_callback_scratch().unwrap();
  let (fd, _peer) = UnixStream::pair().unwrap();
  let fd = handle.register(fd).unwrap();
  let wakes = Arc::new(AtomicUsize::new(0));
  let waker = Waker::from(Arc::new(WakeCounter(Arc::clone(&wakes))));
  let mut wait = fd.readable();
  let mut context = Context::from_waker(&waker);
  assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
  std::mem::forget(wait);

  drop(fd);
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert_eq!(handle.waiters(), 0);
  assert_eq!(handle.registrations(), 0);
  reactor.shared.return_callback_scratch(scratch);

  let (fd, _peer) = UnixStream::pair().unwrap();
  let fd = handle.register(fd).unwrap();
  let mut wait = fd.readable();
  assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
  std::mem::forget(wait);
  let scratch = reactor.shared.take_callback_scratch().unwrap();
  reactor.shared.close();
  assert_eq!(wakes.load(Ordering::SeqCst), 2);
  assert_eq!(handle.waiters(), 0);
  assert!(reactor.shared.close_complete());
  reactor.shared.return_callback_scratch(scratch);

  drop(fd);
  reactor.shutdown().unwrap();
}

#[test]
fn bounded_callback_owners_fallback_preserves_self_close_and_external_waits() {
  let mut reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 1,
  })
  .unwrap();
  let shared = Arc::clone(&reactor.shared);
  assert_eq!(lock(&shared.callback_owners).capacity(), 1);

  let (first_entered_tx, first_entered_rx) = mpsc::channel();
  let (first_release_tx, first_release_rx) = mpsc::channel();
  let first_shared = Arc::clone(&shared);
  let first = thread::spawn(move || {
    claim_callback(&first_shared);
    callback_scope(&first_shared, || {
      first_entered_tx.send(()).unwrap();
      first_release_rx.recv().unwrap();
      callback_done(&first_shared);
    });
  });
  first_entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap();
  assert_eq!(lock(&shared.callback_owners).len(), 1);

  let (second_entered_tx, second_entered_rx) = mpsc::channel();
  let (second_release_tx, second_release_rx) = mpsc::channel();
  let second_shared = Arc::clone(&shared);
  let second = thread::spawn(move || {
    claim_callback(&second_shared);
    callback_scope(&second_shared, || {
      assert!(in_callback(&second_shared));
      second_shared.close();
      second_entered_tx.send(()).unwrap();
      second_release_rx.recv().unwrap();
      callback_done(&second_shared);
    });
  });
  second_entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap();
  assert_eq!(lock(&shared.callback_owners).len(), 1);
  assert!(!shared.close_complete());
  assert_eq!(reactor.poll_shutdown(), Ok(false));

  let (external_done_tx, external_done_rx) = mpsc::channel();
  let external_shared = Arc::clone(&shared);
  let external = thread::spawn(move || {
    external_shared.close();
    external_done_tx.send(()).unwrap();
  });
  assert!(
    external_done_rx
      .recv_timeout(Duration::from_millis(50))
      .is_err()
  );

  second_release_tx.send(()).unwrap();
  second.join().unwrap();
  assert!(
    external_done_rx
      .recv_timeout(Duration::from_millis(50))
      .is_err()
  );
  first_release_tx.send(()).unwrap();
  first.join().unwrap();
  external_done_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap();
  external.join().unwrap();
  assert!(shared.close_complete());
  reactor.shutdown().unwrap();
}

fn nested_fallback_close(shared: &Shared, depth: usize) {
  let marker = push_callback_fallback(shared);
  if depth == 0 {
    claim_callback(shared);
    shared.close();
    assert!(!shared.close_complete());
    callback_done(shared);
  } else {
    nested_fallback_close(shared, depth - 1);
  }
  pop_callback_fallback(marker);
}

#[test]
fn callback_fallback_stack_overflow_never_reports_callbacks_complete() {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 1,
  })
  .unwrap();
  nested_fallback_close(&reactor.shared, CALLBACK_FALLBACK_DEPTH + 1);
  assert!(reactor.shared.close_complete());
  reactor.shutdown().unwrap();
}
