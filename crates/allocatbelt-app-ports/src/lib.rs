//! Small functional CPU, managed-memory, loopback HTTP and filesystem ports.
//!
//! These are explicit application examples for the optional runtime, not a
//! compatibility layer or performance claim. Workload kernels and wire/file
//! payload functions are kept separate from the allocatbelt drivers so a
//! development-only executor comparison can reuse the same deterministic
//! work without adding Tokio to this package.
//!
//! Resource-backed functional `run` ports take explicit ledger handles and
//! retain their dedicated, otherwise-idle scope checks. The additive
//! `run_operation` kernels used by the development benchmark support shared
//! scopes and report per-operation outputs; benchmark-wide charge assertions
//! belong after all operations and retained outputs have drained. Runtime,
//! reactor and filesystem handles remain caller-owned and must be shut down
//! explicitly.
//! The qualification tests exercise recovered bounded-admission inputs,
//! returned managed-buffer clone lifetime, canceled HTTP server cleanup,
//! detached multi-chunk filesystem work, and explicit process reaping. These
//! tests make no timing or executor-superiority claim.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::error::Error;

pub mod cpu;
pub mod disk;
pub mod http;
pub mod memory;

/// Errors returned by an application port.
pub type PortResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(crate) fn message(message: impl Into<String>) -> std::io::Error {
  std::io::Error::other(message.into())
}

pub(crate) fn join_message(error: impl std::fmt::Display) -> std::io::Error {
  message(error.to_string())
}
