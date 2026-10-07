//! The atomics of the start/cancel transition: `std`'s, or `loom`'s when
//! the protocol is model-checked (`--cfg loom`).

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU8, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicU8, Ordering};
