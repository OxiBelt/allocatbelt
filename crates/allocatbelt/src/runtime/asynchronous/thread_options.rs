//! Per-thread naming and lifecycle hooks for the asynchronous executor.

use std::fmt;
use std::sync::Arc;

/// The physical kind of executor thread receiving an option or hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsyncThreadRole {
  /// One of the configured threads that normally dispatches work.
  Worker,
  /// A prestarted thread that dispatches while a worker is handed off.
  HandoffHelper,
}

/// Stable identity for one physical executor thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsyncThreadContext {
  /// Whether this is a primary worker or a handoff helper.
  pub role: AsyncThreadRole,
  /// Zero-based index within its role.
  pub index: usize,
  /// Zero-based index across all runtime threads, workers first.
  pub physical_index: usize,
}

pub(super) type ThreadHook = Arc<dyn Fn(AsyncThreadContext) + Send + Sync + 'static>;
type ThreadNameFn = Arc<dyn Fn(AsyncThreadContext) -> String + Send + Sync + 'static>;

/// Additive thread creation and lifecycle settings for [`super::AsyncRuntime`].
///
/// Options are cloned into the runtime. Lifecycle hook panics are contained
/// and counted in runtime metrics. Thread-name callbacks run synchronously
/// during construction; a panic or a name containing NUL returns
/// [`super::AsyncError::InvalidConfig`] before a runtime metrics handle exists.
#[derive(Clone, Default)]
pub struct AsyncThreadOptions {
  name: Option<String>,
  name_fn: Option<ThreadNameFn>,
  stack_size: Option<usize>,
  on_start: Option<ThreadHook>,
  on_stop: Option<ThreadHook>,
  on_park: Option<ThreadHook>,
  on_unpark: Option<ThreadHook>,
}

impl AsyncThreadOptions {
  /// Creates default options, preserving the executor's standard names.
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// Uses `name` for every executor thread. Use [`thread_name_fn`](Self::thread_name_fn)
  /// to include a physical thread's role or index.
  #[must_use]
  pub fn thread_name(mut self, name: impl Into<String>) -> Self {
    self.name = Some(name.into());
    self.name_fn = None;
    self
  }

  /// Computes the full name for each physical thread during construction.
  #[must_use]
  pub fn thread_name_fn(
    mut self,
    name_fn: impl Fn(AsyncThreadContext) -> String + Send + Sync + 'static,
  ) -> Self {
    self.name_fn = Some(Arc::new(name_fn));
    self.name = None;
    self
  }

  /// Sets the requested OS thread stack size. Zero is rejected at startup.
  #[must_use]
  pub fn thread_stack_size(mut self, bytes: usize) -> Self {
    self.stack_size = Some(bytes);
    self
  }

  /// Runs after the runtime context has been installed on a thread.
  #[must_use]
  pub fn on_thread_start(
    mut self,
    hook: impl Fn(AsyncThreadContext) + Send + Sync + 'static,
  ) -> Self {
    self.on_start = Some(Arc::new(hook));
    self
  }

  /// Runs immediately before a thread exits.
  #[must_use]
  pub fn on_thread_stop(
    mut self,
    hook: impl Fn(AsyncThreadContext) + Send + Sync + 'static,
  ) -> Self {
    self.on_stop = Some(Arc::new(hook));
    self
  }

  /// Runs immediately before an executor thread attempts a scheduler wait.
  /// If the wait predicate changes while this hook runs, the attempt is
  /// paired with `on_thread_unpark` without entering the condition wait.
  #[must_use]
  pub fn on_thread_park(
    mut self,
    hook: impl Fn(AsyncThreadContext) + Send + Sync + 'static,
  ) -> Self {
    self.on_park = Some(Arc::new(hook));
    self
  }

  /// Runs after an executor thread returns from a work wait, or after a park
  /// attempt skips waiting because its predicate changed.
  #[must_use]
  pub fn on_thread_unpark(
    mut self,
    hook: impl Fn(AsyncThreadContext) + Send + Sync + 'static,
  ) -> Self {
    self.on_unpark = Some(Arc::new(hook));
    self
  }

  pub(super) fn resolve_name(&self, context: AsyncThreadContext) -> Result<String, ()> {
    let name = if let Some(name_fn) = &self.name_fn {
      name_fn(context)
    } else if let Some(name) = &self.name {
      name.clone()
    } else {
      match context.role {
        AsyncThreadRole::Worker => format!("allocatbelt-async-{}", context.index),
        AsyncThreadRole::HandoffHelper => format!("allocatbelt-async-handoff-{}", context.index),
      }
    };
    if name.as_bytes().contains(&0) {
      Err(())
    } else {
      Ok(name)
    }
  }

  pub(super) fn stack_size(&self) -> Option<usize> {
    self.stack_size
  }
  pub(super) fn start_hook(&self) -> Option<&ThreadHook> {
    self.on_start.as_ref()
  }
  pub(super) fn stop_hook(&self) -> Option<&ThreadHook> {
    self.on_stop.as_ref()
  }
  pub(super) fn park_hook(&self) -> Option<&ThreadHook> {
    self.on_park.as_ref()
  }
  pub(super) fn unpark_hook(&self) -> Option<&ThreadHook> {
    self.on_unpark.as_ref()
  }
}

impl fmt::Debug for AsyncThreadOptions {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncThreadOptions")
      .field("name", &self.name)
      .field("has_name_fn", &self.name_fn.is_some())
      .field("stack_size", &self.stack_size)
      .field("on_start", &self.on_start.is_some())
      .field("on_stop", &self.on_stop.is_some())
      .field("on_park", &self.on_park.is_some())
      .field("on_unpark", &self.on_unpark.is_some())
      .finish()
  }
}
