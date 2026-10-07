//! Runtime-only signal registration, outside allocator hot paths.
//!
//! Installation allocates registry metadata. The permanently retained handler
//! itself performs only a lock-free bit update and async-signal-safe write.

use std::io;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::runtime::signal::SignalKind;

pub(crate) fn register(
  kind: SignalKind,
  pending: &'static AtomicU64,
  descriptor: BorrowedFd<'static>,
) -> io::Result<()> {
  // Validate again before entering the registry's panic-sensitive boundary.
  SignalKind::from_raw(kind.as_raw()).map_err(|_| io::ErrorKind::InvalidInput)?;
  let mask = kind.mask();
  // SAFETY: the callback only uses a lock-free AtomicU64 and rustix's
  // async-signal-safe write syscall. It never allocates, locks, invokes user
  // code or panics. Both captured objects remain valid for the process lifetime,
  // including when registration reports an error after installing an action.
  // The registry chains prior handlers and saves/restores the interrupted errno.
  #[expect(unsafe_code, reason = "permanent async-signal-safe registry callback")]
  let result = unsafe {
    signal_hook_registry::register(kind.as_raw(), move || {
      pending.fetch_or(mask, Ordering::SeqCst);
      while let Err(rustix::io::Errno::INTR) = rustix::io::write(descriptor, &[1]) {}
    })
  };
  result.map(|_| ())
}
