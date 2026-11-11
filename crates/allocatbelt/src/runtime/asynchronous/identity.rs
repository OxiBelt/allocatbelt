//! Process-wide identity for admitted asynchronous tasks.
//!
//! Identifiers use a process-wide standard atomic counter. Loom models of
//! the executor validate task scheduling and cancellation, not numeric ID
//! uniqueness or counter exhaustion.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// A process-wide identifier for one admitted asynchronous task.
///
/// IDs are assigned before a spawned future is consumed and are never reused.
/// A process that exhausts the nonwrapping identifier space rejects further
/// spawns instead of reusing an earlier identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
  #[cfg(test)]
  pub(super) const fn test_sentinel() -> Self {
    Self(0)
  }
}

impl fmt::Display for TaskId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(f)
  }
}

pub(super) fn allocate() -> Option<TaskId> {
  allocate_from(&NEXT_TASK_ID)
}

fn allocate_from(counter: &AtomicU64) -> Option<TaskId> {
  counter
    .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
      next.checked_add(1)
    })
    .ok()
    .map(TaskId)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{TaskId, allocate_from};
  use crate::runtime::asynchronous::entry::{TaskContextGuard, task_id, try_task_id};
  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, LocalConfig, LocalRuntime};
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::AtomicU64;
  use std::sync::mpsc::{self, Sender};
  use std::task::{Context, Poll};

  #[test]
  fn isolated_allocator_exhaustion_does_not_wrap_or_mutate_global_state() {
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_from(&counter), Some(TaskId(u64::MAX - 1)));
    assert_eq!(allocate_from(&counter), None);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), u64::MAX);
  }

  struct ContextProbe(Sender<Option<TaskId>>);

  impl Future for ContextProbe {
    type Output = TaskId;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      Poll::Ready(task_id())
    }
  }

  impl Drop for ContextProbe {
    fn drop(&mut self) {
      let _ = self.0.send(try_task_id());
    }
  }

  struct DropIdFuture(Sender<Option<TaskId>>);

  impl Future for DropIdFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      Poll::Pending
    }
  }

  impl Drop for DropIdFuture {
    fn drop(&mut self) {
      let _ = self.0.send(try_task_id());
    }
  }

  #[test]
  fn native_local_and_cross_thread_tasks_keep_global_ids() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let native_handle = runtime.handle();
    let (native_tx, native_rx) = mpsc::channel();
    let native_job = native_handle.spawn(ContextProbe(native_tx)).unwrap();
    let native_id = native_job.id();
    let native_abort = native_job.abort_handle();
    assert_eq!(native_abort.id(), native_id);
    assert_eq!(runtime.block_on(native_job).unwrap().unwrap(), native_id);
    assert_eq!(native_rx.recv().unwrap(), Some(native_id));
    assert_eq!(native_abort.id(), native_id);
    let (reused_tx, reused_rx) = mpsc::channel();
    let reused_job = native_handle.spawn(ContextProbe(reused_tx)).unwrap();
    let reused_id = reused_job.id();
    assert_ne!(
      native_id, reused_id,
      "native task-slot reuse changed identity"
    );
    assert_eq!(runtime.block_on(reused_job).unwrap().unwrap(), reused_id);
    assert_eq!(reused_rx.recv().unwrap(), Some(reused_id));
    assert_eq!(runtime.block_on(async { try_task_id() }).unwrap(), None);
    let inherited = TaskId(u64::MAX - 2);
    let inherited_guard = TaskContextGuard::enter(Some(inherited));
    assert_eq!(
      native_handle.block_on(async { try_task_id() }).unwrap(),
      None
    );
    assert_eq!(try_task_id(), Some(inherited));
    drop(inherited_guard);
    runtime
      .shutdown(crate::runtime::asynchronous::AsyncShutdown::Drain)
      .unwrap();

    let mut local = LocalRuntime::new(LocalConfig {
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let (local_tx, local_rx) = mpsc::channel();
    let local_job = local.handle().spawn_local(ContextProbe(local_tx)).unwrap();
    let local_id = local_job.id();
    assert_ne!(native_id, local_id);
    let local_abort = local_job.abort_handle();
    assert_eq!(local_abort.id(), local_id);
    assert_eq!(
      local
        .block_on(async move {
          assert_eq!(try_task_id(), None);
          local_job.await.unwrap()
        })
        .unwrap(),
      local_id
    );
    assert_eq!(local_rx.recv().unwrap(), Some(local_id));
    assert_eq!(local_abort.id(), local_id);
    let (reused_tx, reused_rx) = mpsc::channel();
    let reused_local = local.handle().spawn_local(ContextProbe(reused_tx)).unwrap();
    let reused_local_id = reused_local.id();
    assert_ne!(
      local_id, reused_local_id,
      "local task-slot reuse changed identity"
    );
    assert_eq!(
      local.block_on(reused_local).unwrap().unwrap(),
      reused_local_id
    );
    assert_eq!(reused_rx.recv().unwrap(), Some(reused_local_id));

    let (send_tx, send_rx) = mpsc::channel();
    let send_handle = local.send_handle();
    let send_job = std::thread::spawn(move || send_handle.spawn(ContextProbe(send_tx)).unwrap())
      .join()
      .unwrap();
    let send_id = send_job.id();
    assert_ne!(native_id, send_id);
    assert_ne!(local_id, send_id);
    assert_eq!(send_job.abort_handle().id(), send_id);
    assert_eq!(
      local
        .block_on(async move {
          assert_eq!(try_task_id(), None);
          send_job.await.unwrap()
        })
        .unwrap(),
      send_id
    );
    assert_eq!(send_rx.recv().unwrap(), Some(send_id));

    let local_inherited = TaskId(u64::MAX - 2);
    let _outer = TaskContextGuard::enter(Some(local_inherited));
    assert_eq!(
      local.block_on(async { try_task_id() }).unwrap(),
      None,
      "a borrowed root future must not inherit a task identity"
    );
    assert_eq!(try_task_id(), Some(local_inherited));
  }

  #[test]
  fn cancellation_cleanup_observes_the_stable_task_id() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let (native_tx, native_rx) = mpsc::channel();
    let native_job = runtime.handle().spawn(DropIdFuture(native_tx)).unwrap();
    let native_id = native_job.id();
    let native_abort = native_job.abort_handle();
    native_job.abort();
    runtime
      .shutdown(crate::runtime::asynchronous::AsyncShutdown::CancelPending)
      .unwrap();
    assert_eq!(native_rx.recv().unwrap(), Some(native_id));
    assert_eq!(native_abort.id(), native_id);
    drop(native_job);

    let mut local = LocalRuntime::new(LocalConfig {
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let (local_tx, local_rx) = mpsc::channel();
    let local_job = local.handle().spawn_local(DropIdFuture(local_tx)).unwrap();
    let local_id = local_job.id();
    let local_abort = local_job.abort_handle();
    assert_ne!(native_id, local_id);
    local_job.abort();
    assert!(matches!(
      local.block_on(local_job).unwrap(),
      Err(crate::runtime::asynchronous::AsyncJoinError::Cancelled)
    ));
    assert_eq!(local_rx.recv().unwrap(), Some(local_id));
    assert_eq!(local_abort.id(), local_id);
  }

  #[test]
  fn task_context_guard_restores_outer_id_when_nested_poll_unwinds() {
    let outer = TaskId(42);
    let inner = TaskId(43);
    let outer_guard = TaskContextGuard::enter(Some(outer));
    assert_eq!(try_task_id(), Some(outer));
    let unwind = std::panic::catch_unwind(|| {
      let _inner_guard = TaskContextGuard::enter(Some(inner));
      assert_eq!(task_id(), inner);
      panic!("injected nested task panic");
    });
    assert!(unwind.is_err());
    assert_eq!(try_task_id(), Some(outer));
    drop(outer_guard);
    assert_eq!(try_task_id(), None);
  }
}
