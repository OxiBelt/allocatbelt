//! Shared ownership of one pinned, bidirectional I/O endpoint with separate
//! read and write halves.
//!
//! [`split`] pins the endpoint in one `Box` and stores that `Pin<Box<T>>` in
//! private shared state. The returned halves are unique, non-cloneable
//! handles. They may be polled concurrently, but one short state transition
//! moves the pinned box out before calling endpoint code, so endpoint methods,
//! waker callbacks and waker destruction never run under the state mutex. If
//! one half is dropped, the other keeps the endpoint and its owned resources
//! alive. Dropping the final half drops the endpoint; it does not flush or
//! shut down it. Use [`reunite`] with the matching pair to recover the pinned
//! endpoint.
//!
//! This wrapper allocates one ordinary `Box<T>` for pinning and one ordinary
//! `Arc` allocation for its fixed shared state. Those allocations are not
//! charged to a [`ResourceScope`](crate::runtime::managed::ResourceScope).
//! Charges owned by `T`, such as a [`ManagedBuf`](crate::runtime::managed::ManagedBuf),
//! stay with `T` through reunite and remain until `T` releases them, including
//! when dropping the final half drops the endpoint.
//!
//! The wrapper supports borrowed, `!Send`, and `!Unpin` endpoints. It does
//! not require either half to outlive the endpoint's borrows, and it does not
//! add another waiting queue: at most one read waiter and one write waiter
//! can be recorded because neither half is cloneable.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::io::{self, IoSlice, IoSliceMut};
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

use super::io::{AsyncRead, AsyncWrite};
use super::task::drop_contained;

#[cfg(loom)]
use loom::sync::{Arc, Mutex};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex};

/// Splits one owned bidirectional endpoint into a unique read half and write
/// half. The endpoint is pinned once in a heap allocation and stays pinned
/// while the halves operate or until they are reunited.
#[must_use]
pub fn split<T>(endpoint: T) -> (ReadHalf<T>, WriteHalf<T>)
where
  T: AsyncRead + AsyncWrite,
{
  // This capability query is endpoint code, so it runs before the shared
  // state is created and outside its mutex. The answer stays fixed for the
  // lifetime of the writer half.
  let write_vectored = endpoint.is_write_vectored();
  let shared = Arc::new(Shared {
    state: Mutex::new(State {
      endpoint: Some(Box::pin(endpoint)),
      busy: false,
      read_waker: None,
      write_waker: None,
    }),
  });
  (
    ReadHalf {
      shared: Arc::clone(&shared),
    },
    WriteHalf {
      shared,
      write_vectored,
    },
  )
}

struct Shared<T> {
  state: Mutex<State<T>>,
}

struct State<T> {
  endpoint: Option<Pin<Box<T>>>,
  busy: bool,
  read_waker: Option<Waker>,
  write_waker: Option<Waker>,
}

impl<T> Drop for Shared<T> {
  fn drop(&mut self) {
    let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
    let endpoint = state.endpoint.take();
    let read_waker = state.read_waker.take();
    let write_waker = state.write_waker.take();
    drop_contained(read_waker);
    drop_contained(write_waker);
    drop_contained(endpoint);
  }
}

/// The unique read direction of a split endpoint.
pub struct ReadHalf<T> {
  shared: Arc<Shared<T>>,
}

/// The unique write direction of a split endpoint.
pub struct WriteHalf<T> {
  shared: Arc<Shared<T>>,
  write_vectored: bool,
}

impl<T> Drop for ReadHalf<T> {
  fn drop(&mut self) {
    let old = {
      let mut state = self
        .shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      state.read_waker.take()
    };
    drop_contained(old);
  }
}

impl<T> Drop for WriteHalf<T> {
  fn drop(&mut self) {
    let old = {
      let mut state = self
        .shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      state.write_waker.take()
    };
    drop_contained(old);
  }
}

impl<T> std::fmt::Debug for ReadHalf<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ReadHalf").finish_non_exhaustive()
  }
}

impl<T> std::fmt::Debug for WriteHalf<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf")
      .field("write_vectored", &self.write_vectored)
      .finish_non_exhaustive()
  }
}

/// Returns the endpoint from the two halves created by the same [`split`].
///
/// The result remains pinned, so callers can reunite endpoints that are
/// `!Unpin` without moving their pointee. On a mismatch, both halves are
/// returned unchanged in [`ReuniteError`].
pub fn reunite<T>(read: ReadHalf<T>, write: WriteHalf<T>) -> Result<Pin<Box<T>>, ReuniteError<T>>
where
  T: AsyncRead + AsyncWrite,
{
  if !Arc::ptr_eq(&read.shared, &write.shared) {
    return Err(ReuniteError { read, write });
  }

  // Keep one local strong reference, then let each half run its ordinary
  // waiter cleanup. With the matching pair consumed, this is the sole owner.
  let shared = Arc::clone(&read.shared);
  drop(read);
  drop(write);
  let mut shared = match Arc::try_unwrap(shared) {
    Ok(shared) => shared,
    Err(_) => unreachable!("split halves are the only shared-state owners"),
  };
  let state = shared
    .state
    .get_mut()
    .unwrap_or_else(PoisonError::into_inner);
  let endpoint = state.endpoint.take();
  let read_waker = state.read_waker.take();
  let write_waker = state.write_waker.take();
  let busy = state.busy;
  drop_contained(read_waker);
  drop_contained(write_waker);
  match (endpoint, busy) {
    (Some(endpoint), false) => Ok(endpoint),
    _ => unreachable!("matching halves cannot reunite during an endpoint poll"),
  }
}

/// A mismatched pair of split halves. Both original values remain available.
pub struct ReuniteError<T> {
  /// The original read half.
  pub read: ReadHalf<T>,
  /// The original write half.
  pub write: WriteHalf<T>,
}

impl<T> std::fmt::Debug for ReuniteError<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ReuniteError")
      .field("read", &self.read)
      .field("write", &self.write)
      .finish()
  }
}

impl<T> std::fmt::Display for ReuniteError<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("read and write halves came from different endpoints")
  }
}

impl<T> std::error::Error for ReuniteError<T> {}

#[derive(Clone, Copy)]
enum Direction {
  Read,
  Write,
}

impl<T> State<T> {
  fn waiter_mut(&mut self, direction: Direction) -> &mut Option<Waker> {
    match direction {
      Direction::Read => &mut self.read_waker,
      Direction::Write => &mut self.write_waker,
    }
  }
}

enum BeginPoll<'a, T> {
  Busy,
  Missing,
  Lease(EndpointLease<'a, T>),
}

struct EndpointLease<'a, T> {
  shared: &'a Shared<T>,
  endpoint: Option<Pin<Box<T>>>,
}

impl<T> EndpointLease<'_, T> {
  fn endpoint(&mut self) -> Pin<&mut T> {
    match self.endpoint.as_mut() {
      Some(endpoint) => endpoint.as_mut(),
      None => unreachable!("endpoint lease is restored once"),
    }
  }

  fn restore(&mut self) -> (Option<Waker>, Option<Waker>) {
    let Some(endpoint) = self.endpoint.take() else {
      return (None, None);
    };
    let mut state = self
      .shared
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    state.endpoint = Some(endpoint);
    state.busy = false;
    (state.read_waker.take(), state.write_waker.take())
  }
}

impl<T> Drop for EndpointLease<'_, T> {
  fn drop(&mut self) {
    let (read, write) = self.restore();
    wake_contained(read);
    wake_contained(write);
  }
}

fn poll_endpoint<T, R>(
  shared: &Shared<T>,
  direction: Direction,
  cx: &mut Context<'_>,
  poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
) -> Poll<io::Result<R>> {
  let begin = {
    let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
    if state.busy {
      BeginPoll::Busy
    } else if let Some(endpoint) = state.endpoint.take() {
      state.busy = true;
      BeginPoll::Lease(EndpointLease {
        shared,
        endpoint: Some(endpoint),
      })
    } else {
      BeginPoll::Missing
    }
  };

  let mut lease = match begin {
    BeginPoll::Lease(lease) => lease,
    BeginPoll::Missing => {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "split endpoint is unavailable",
      )));
    }
    BeginPoll::Busy => {
      let replacement = match clone_waker(cx.waker()) {
        Ok(waker) => waker,
        Err(error) => return Poll::Ready(Err(error)),
      };
      let mut replacement = Some(replacement);
      let mut old = None;
      let mut lease = None;
      let mut missing = false;
      {
        let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.busy {
          old = state
            .waiter_mut(direction)
            .replace(match replacement.take() {
              Some(waker) => waker,
              None => unreachable!("replacement waker is still owned locally"),
            });
        } else if let Some(endpoint) = state.endpoint.take() {
          state.busy = true;
          lease = Some(EndpointLease {
            shared,
            endpoint: Some(endpoint),
          });
        } else {
          missing = true;
        }
      }
      drop_contained(old);
      drop_contained(replacement);
      if missing {
        return Poll::Ready(Err(io::Error::new(
          io::ErrorKind::BrokenPipe,
          "split endpoint is unavailable",
        )));
      }
      match lease {
        Some(lease) => lease,
        None => return Poll::Pending,
      }
    }
  };

  let outcome = panic::catch_unwind(AssertUnwindSafe(|| poll(lease.endpoint(), cx)));
  let (read_waker, write_waker) = lease.restore();
  wake_contained(read_waker);
  wake_contained(write_waker);
  match outcome {
    Ok(result) => result,
    Err(payload) => panic::resume_unwind(payload),
  }
}

fn clone_waker(waker: &Waker) -> io::Result<Waker> {
  match panic::catch_unwind(AssertUnwindSafe(|| waker.clone())) {
    Ok(waker) => Ok(waker),
    Err(payload) => {
      drop_contained(payload);
      Err(io::Error::other("split I/O waker clone panicked"))
    }
  }
}

fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for ReadHalf<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Read,
      cx,
      |endpoint, cx| endpoint.poll_read(cx, buf),
    )
  }

  fn poll_read_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Read,
      cx,
      |endpoint, cx| endpoint.poll_read_vectored(cx, bufs),
    )
  }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for WriteHalf<T> {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Write,
      cx,
      |endpoint, cx| endpoint.poll_write(cx, buf),
    )
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Write,
      cx,
      |endpoint, cx| endpoint.poll_write_vectored(cx, bufs),
    )
  }

  fn is_write_vectored(&self) -> bool {
    self.write_vectored
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Write,
      cx,
      |endpoint, cx| endpoint.poll_flush(cx),
    )
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    poll_endpoint(
      &self.get_mut().shared,
      Direction::Write,
      cx,
      |endpoint, cx| endpoint.poll_shutdown(cx),
    )
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::cell::{Cell, RefCell};
  use std::io::{self, IoSlice, IoSliceMut};
  use std::marker::PhantomPinned;
  use std::panic::{self, AssertUnwindSafe};
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Condvar, Mutex, Weak};
  use std::task::{Context, Poll, Wake, Waker};
  use std::time::{Duration, Instant};

  use super::*;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};

  struct BorrowedDuplex<'a> {
    input: &'a [u8],
    read_at: Cell<usize>,
    output: RefCell<&'a mut [u8]>,
    write_at: Cell<usize>,
    address: Cell<usize>,
    flushes: Cell<usize>,
    shutdowns: Cell<usize>,
    _not_send: Rc<()>,
    _pin: PhantomPinned,
  }

  fn borrowed_endpoint<'a>(output: &'a mut [u8]) -> BorrowedDuplex<'a> {
    BorrowedDuplex {
      input: b"",
      read_at: Cell::new(0),
      output: RefCell::new(output),
      write_at: Cell::new(0),
      address: Cell::new(0),
      flushes: Cell::new(0),
      shutdowns: Cell::new(0),
      _not_send: Rc::new(()),
      _pin: PhantomPinned,
    }
  }

  impl BorrowedDuplex<'_> {
    fn record_pin(&self) {
      let address = self as *const Self as usize;
      let previous = self.address.get();
      if previous == 0 {
        self.address.set(address);
      } else {
        assert_eq!(previous, address);
      }
    }
  }

  impl AsyncRead for BorrowedDuplex<'_> {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      let remaining = &this.input[this.read_at.get()..];
      let count = remaining.len().min(buf.len());
      buf[..count].copy_from_slice(&remaining[..count]);
      this.read_at.set(this.read_at.get() + count);
      Poll::Ready(Ok(count))
    }

    fn poll_read_vectored(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      let mut total = 0;
      for buf in bufs {
        let at = this.read_at.get();
        let count = (this.input.len() - at).min(buf.len());
        (**buf)[..count].copy_from_slice(&this.input[at..at + count]);
        this.read_at.set(at + count);
        total += count;
        if count < buf.len() {
          break;
        }
      }
      Poll::Ready(Ok(total))
    }
  }

  impl AsyncWrite for BorrowedDuplex<'_> {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      let at = this.write_at.get();
      let mut output = this.output.borrow_mut();
      let count = (output.len() - at).min(buf.len());
      output[at..at + count].copy_from_slice(&buf[..count]);
      this.write_at.set(at + count);
      Poll::Ready(Ok(count))
    }

    fn poll_write_vectored(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      let mut output = this.output.borrow_mut();
      let mut total = 0;
      for buf in bufs {
        let at = this.write_at.get();
        let count = (output.len() - at).min(buf.len());
        output[at..at + count].copy_from_slice(&buf[..count]);
        this.write_at.set(at + count);
        total += count;
        if count < buf.len() {
          break;
        }
      }
      let _ = cx;
      Poll::Ready(Ok(total))
    }

    fn is_write_vectored(&self) -> bool {
      true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      this.flushes.set(this.flushes.get() + 1);
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      let this = self.as_ref().get_ref();
      this.record_pin();
      this.shutdowns.set(this.shutdowns.get() + 1);
      Poll::Ready(Ok(()))
    }
  }

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  #[test]
  fn borrowed_not_send_not_unpin_endpoint_keeps_pin_and_reunites() {
    let mut output = [0u8; 8];
    let endpoint = BorrowedDuplex {
      input: b"abcdef",
      read_at: Cell::new(0),
      output: RefCell::new(&mut output),
      write_at: Cell::new(0),
      address: Cell::new(0),
      flushes: Cell::new(0),
      shutdowns: Cell::new(0),
      _not_send: Rc::new(()),
      _pin: PhantomPinned,
    };
    let (mut read, mut write) = split(endpoint);
    let mut cx = context();
    let mut first = [0u8; 2];
    assert!(matches!(
      Pin::new(&mut read).poll_read(&mut cx, &mut first),
      Poll::Ready(Ok(2))
    ));
    assert_eq!(&first, b"ab");
    let mut next_a = [0u8; 2];
    let mut next_b = [0u8; 2];
    let mut read_slices = [IoSliceMut::new(&mut next_a), IoSliceMut::new(&mut next_b)];
    assert!(matches!(
      Pin::new(&mut read).poll_read_vectored(&mut cx, &mut read_slices),
      Poll::Ready(Ok(4))
    ));
    assert_eq!(&read_slices[0][..], b"cd");
    assert_eq!(&read_slices[1][..], b"ef");

    assert!(write.is_write_vectored());
    let write_slices = [IoSlice::new(b"12"), IoSlice::new(b"345")];
    assert!(matches!(
      Pin::new(&mut write).poll_write_vectored(&mut cx, &write_slices),
      Poll::Ready(Ok(5))
    ));
    assert!(matches!(
      Pin::new(&mut write).poll_flush(&mut cx),
      Poll::Ready(Ok(()))
    ));
    assert!(matches!(
      Pin::new(&mut write).poll_shutdown(&mut cx),
      Poll::Ready(Ok(()))
    ));

    let endpoint = reunite(read, write).unwrap();
    let endpoint_ref = endpoint.as_ref().get_ref();
    assert_eq!(endpoint_ref.read_at.get(), 6);
    assert_eq!(endpoint_ref.write_at.get(), 5);
    assert_eq!(endpoint_ref.flushes.get(), 1);
    assert_eq!(endpoint_ref.shutdowns.get(), 1);
    assert_ne!(endpoint_ref.address.get(), 0);
    drop(endpoint);
    assert_eq!(&output[..5], b"12345");
  }

  #[test]
  fn mismatched_reunite_returns_both_original_halves() {
    let mut output_a = [0u8; 1];
    let mut output_b = [0u8; 1];
    let (read_a, write_a) = split(borrowed_endpoint(&mut output_a));
    let (read_b, write_b) = split(borrowed_endpoint(&mut output_b));
    let read_key = Arc::as_ptr(&read_a.shared);
    let write_key = Arc::as_ptr(&write_b.shared);
    let error = match reunite(read_a, write_b) {
      Err(error) => error,
      Ok(_) => panic!("mismatched halves reunited"),
    };
    assert_eq!(Arc::as_ptr(&error.read.shared), read_key);
    assert_eq!(Arc::as_ptr(&error.write.shared), write_key);
    let first = reunite(error.read, write_a).unwrap();
    let second = reunite(read_b, error.write).unwrap();
    drop(first);
    drop(second);
  }

  struct ChargedEndpoint {
    _buffer: Option<crate::runtime::managed::ManagedBuf>,
    drops: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
  }

  impl Drop for ChargedEndpoint {
    fn drop(&mut self) {
      self.drops.fetch_add(1, Ordering::SeqCst);
    }
  }

  impl AsyncRead for ChargedEndpoint {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      Poll::Ready(Ok(0))
    }
  }

  impl AsyncWrite for ChargedEndpoint {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self
        .as_ref()
        .get_ref()
        .flushes
        .fetch_add(1, Ordering::SeqCst);
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self
        .as_ref()
        .get_ref()
        .shutdowns
        .fetch_add(1, Ordering::SeqCst);
      Poll::Ready(Ok(()))
    }
  }

  #[test]
  fn final_half_drop_releases_endpoint_and_its_managed_charge() {
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 32,
      ..ResourceLimits::default()
    });
    let buffer = scope.try_alloc_zeroed(16).unwrap();
    assert_eq!(scope.snapshot().managed_memory, 16);
    let drops = Arc::new(AtomicUsize::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let (read, write) = split(ChargedEndpoint {
      _buffer: Some(buffer),
      drops: Arc::clone(&drops),
      flushes: Arc::clone(&flushes),
      shutdowns: Arc::clone(&shutdowns),
    });
    drop(read);
    assert_eq!(scope.snapshot().managed_memory, 16);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(write);
    assert_eq!(scope.snapshot().managed_memory, 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(flushes.load(Ordering::SeqCst), 0);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 0);
  }

  struct ReentrantEndpoint {
    panic_read: bool,
  }

  impl AsyncRead for ReentrantEndpoint {
    fn poll_read(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      cx.waker().wake_by_ref();
      if self.as_ref().get_ref().panic_read {
        panic!("primary endpoint poll panic");
      }
      Poll::Ready(Ok(0))
    }
  }

  impl AsyncWrite for ReentrantEndpoint {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  type WriteSlot = Arc<Mutex<Option<WriteHalf<ReentrantEndpoint>>>>;

  struct PollWriterWake {
    writer: WriteSlot,
    pending: AtomicUsize,
    ready: AtomicUsize,
  }

  impl PollWriterWake {
    fn poll_writer(self: &Arc<Self>) {
      let mut slot = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
      if let Some(writer) = slot.as_mut() {
        let waker = Waker::from(Arc::clone(self));
        match Pin::new(writer).poll_write(&mut Context::from_waker(&waker), b"x") {
          Poll::Pending => {
            self.pending.fetch_add(1, Ordering::SeqCst);
          }
          Poll::Ready(Ok(1)) => {
            self.ready.fetch_add(1, Ordering::SeqCst);
          }
          other => panic!("unexpected reentrant writer result: {other:?}"),
        }
      }
    }
  }

  impl Wake for PollWriterWake {
    fn wake(self: Arc<Self>) {
      self.poll_writer();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.poll_writer();
    }
  }

  struct PanicWake;
  impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("secondary waker panic");
    }

    fn wake_by_ref(self: &Arc<Self>) {
      panic!("secondary waker panic");
    }
  }

  struct RegisterWriterWake {
    writer: WriteSlot,
    writer_waker: Waker,
  }

  impl RegisterWriterWake {
    fn register(&self) {
      let mut slot = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
      if let Some(writer) = slot.as_mut() {
        assert!(
          Pin::new(writer)
            .poll_write(&mut Context::from_waker(&self.writer_waker), b"x")
            .is_pending()
        );
      }
    }
  }

  impl Wake for RegisterWriterWake {
    fn wake(self: Arc<Self>) {
      self.register();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.register();
    }
  }

  #[test]
  fn opposite_half_reenters_while_endpoint_poll_is_busy_without_deadlocking() {
    let (read, write) = split(ReentrantEndpoint { panic_read: false });
    let writer: WriteSlot = Arc::new(Mutex::new(Some(write)));
    let poll_writer = Arc::new(PollWriterWake {
      writer: Arc::clone(&writer),
      pending: AtomicUsize::new(0),
      ready: AtomicUsize::new(0),
    });
    let waker = Waker::from(poll_writer.clone());
    let mut cx = Context::from_waker(&waker);
    let mut read = read;
    assert!(matches!(
      Pin::new(&mut read).poll_read(&mut cx, &mut []),
      Poll::Ready(Ok(0))
    ));
    assert_eq!(poll_writer.pending.load(Ordering::SeqCst), 1);
    assert_eq!(poll_writer.ready.load(Ordering::SeqCst), 1);
    let write = writer
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take()
      .unwrap();
    drop(reunite(read, write).unwrap());
  }

  #[test]
  fn poll_panic_restores_pin_and_preserves_primary_panic_over_waker_panic() {
    let (mut read, write) = split(ReentrantEndpoint { panic_read: true });
    let writer: WriteSlot = Arc::new(Mutex::new(Some(write)));
    let register = Waker::from(Arc::new(RegisterWriterWake {
      writer: Arc::clone(&writer),
      writer_waker: Waker::from(Arc::new(PanicWake)),
    }));
    let mut cx = Context::from_waker(&register);
    let panic = panic::catch_unwind(AssertUnwindSafe(|| {
      Pin::new(&mut read).poll_read(&mut cx, &mut [])
    }))
    .unwrap_err();
    assert_eq!(
      panic.downcast_ref::<&str>(),
      Some(&"primary endpoint poll panic")
    );

    let write = writer
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take()
      .unwrap();
    let endpoint = reunite(read, write).unwrap();
    assert!(endpoint.as_ref().get_ref().panic_read);
    drop(endpoint);
  }

  struct BlockingEndpoint {
    entered: Arc<(Mutex<bool>, Condvar)>,
    release: Arc<(Mutex<bool>, Condvar)>,
  }

  impl AsyncRead for BlockingEndpoint {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      *this
        .entered
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = true;
      this.entered.1.notify_all();
      let mut released = this
        .release
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      while !*released {
        released = this
          .release
          .1
          .wait(released)
          .unwrap_or_else(PoisonError::into_inner);
      }
      Poll::Ready(Ok(0))
    }
  }

  impl AsyncWrite for BlockingEndpoint {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  struct DropProbe {
    shared: Weak<Shared<BlockingEndpoint>>,
    drops: Arc<AtomicUsize>,
    state_was_unlocked: Arc<AtomicUsize>,
    wakes: Arc<AtomicUsize>,
  }

  impl Drop for DropProbe {
    fn drop(&mut self) {
      self.drops.fetch_add(1, Ordering::SeqCst);
      if self
        .shared
        .upgrade()
        .is_some_and(|shared| shared.state.try_lock().is_ok())
      {
        self.state_was_unlocked.fetch_add(1, Ordering::SeqCst);
      }
    }
  }

  impl Wake for DropProbe {
    fn wake(self: Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn dropping_waiting_half_removes_its_waker_while_other_poll_is_active() {
    let entered = Arc::new((Mutex::new(false), Condvar::new()));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (read, write) = split(BlockingEndpoint {
      entered: Arc::clone(&entered),
      release: Arc::clone(&release),
    });
    let read_thread = std::thread::spawn(move || {
      let mut read = read;
      let mut cx = Context::from_waker(Waker::noop());
      Pin::new(&mut read).poll_read(&mut cx, &mut [])
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut entered_guard = entered.0.lock().unwrap_or_else(PoisonError::into_inner);
    while !*entered_guard {
      assert!(Instant::now() < deadline, "read poll did not enter");
      let (next, _) = entered
        .1
        .wait_timeout(entered_guard, Duration::from_millis(10))
        .unwrap_or_else(PoisonError::into_inner);
      entered_guard = next;
    }
    drop(entered_guard);

    let drops = Arc::new(AtomicUsize::new(0));
    let state_was_unlocked = Arc::new(AtomicUsize::new(0));
    let wakes = Arc::new(AtomicUsize::new(0));
    let wake = Waker::from(Arc::new(DropProbe {
      shared: Arc::downgrade(&write.shared),
      drops: Arc::clone(&drops),
      state_was_unlocked: Arc::clone(&state_was_unlocked),
      wakes: Arc::clone(&wakes),
    }));
    let mut write = write;
    {
      let mut cx = Context::from_waker(&wake);
      assert!(Pin::new(&mut write).poll_write(&mut cx, b"x").is_pending());
    }
    drop(wake);
    drop(write);
    *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
    release.1.notify_all();
    assert!(matches!(read_thread.join().unwrap(), Poll::Ready(Ok(0))));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(state_was_unlocked.load(Ordering::SeqCst), 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use std::io;
  use std::pin::Pin;
  use std::sync::Arc as StdArc;
  use std::sync::atomic::{AtomicUsize as StdAtomicUsize, Ordering as StdOrdering};
  use std::task::{Context, Poll, Wake, Waker};

  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use loom::thread;

  use super::*;

  struct Interleaved {
    read_entered: Arc<AtomicBool>,
    release_read: Arc<AtomicBool>,
    active_polls: Arc<AtomicUsize>,
  }

  impl Interleaved {
    fn enter(&self) {
      assert_eq!(self.active_polls.fetch_add(1, Ordering::SeqCst), 0);
    }

    fn leave(&self) {
      assert_eq!(self.active_polls.fetch_sub(1, Ordering::SeqCst), 1);
    }
  }

  impl AsyncRead for Interleaved {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.enter();
      this.read_entered.store(true, Ordering::SeqCst);
      while !this.release_read.load(Ordering::SeqCst) {
        thread::yield_now();
      }
      this.leave();
      Poll::Ready(Ok(0))
    }
  }

  impl AsyncWrite for Interleaved {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_ref().get_ref();
      this.enter();
      this.leave();
      Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  struct CountWake {
    calls: StdAtomicUsize,
    unlocked: StdAtomicUsize,
    shared: Arc<Shared<Interleaved>>,
  }
  impl Wake for CountWake {
    fn wake(self: StdArc<Self>) {
      self.calls.fetch_add(1, StdOrdering::SeqCst);
      if self.shared.state.try_lock().is_ok() {
        self.unlocked.fetch_add(1, StdOrdering::SeqCst);
      }
    }

    fn wake_by_ref(self: &StdArc<Self>) {
      self.calls.fetch_add(1, StdOrdering::SeqCst);
      if self.shared.state.try_lock().is_ok() {
        self.unlocked.fetch_add(1, StdOrdering::SeqCst);
      }
    }
  }

  #[test]
  fn actual_endpoint_lease_serializes_competing_halves_and_delivers_waiter_wake() {
    loom::model(|| {
      let read_entered = Arc::new(AtomicBool::new(false));
      let release_read = Arc::new(AtomicBool::new(false));
      let active_polls = Arc::new(AtomicUsize::new(0));
      let (mut read, mut write) = split(Interleaved {
        read_entered: Arc::clone(&read_entered),
        release_read: Arc::clone(&release_read),
        active_polls: Arc::clone(&active_polls),
      });
      let read_thread = thread::spawn(move || {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(&mut read).poll_read(&mut cx, &mut [])
      });
      while !read_entered.load(Ordering::SeqCst) {
        thread::yield_now();
      }

      let wakes = StdArc::new(CountWake {
        calls: StdAtomicUsize::new(0),
        unlocked: StdAtomicUsize::new(0),
        shared: Arc::clone(&write.shared),
      });
      let write_wakes = StdArc::clone(&wakes);
      let write_thread = thread::spawn({
        let release_read = Arc::clone(&release_read);
        move || {
          let write_waker = Waker::from(write_wakes);
          let mut cx = Context::from_waker(&write_waker);
          assert!(Pin::new(&mut write).poll_write(&mut cx, b"x").is_pending());
          assert!(write.shared.state.lock().unwrap().write_waker.is_some());
          release_read.store(true, Ordering::SeqCst);
          write
        }
      });
      assert!(matches!(read_thread.join().unwrap(), Poll::Ready(Ok(0))));
      let write = write_thread.join().unwrap();
      assert_eq!(active_polls.load(Ordering::SeqCst), 0);
      assert_eq!(wakes.calls.load(StdOrdering::SeqCst), 1);
      assert_eq!(wakes.unlocked.load(StdOrdering::SeqCst), 1);
      drop(write);
    });
  }
}
