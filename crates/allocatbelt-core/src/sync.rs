//! The atomics used by [`crate::proto`] and [`crate::lock`]: `core`'s, or
//! `loom`'s when the protocols are model-checked (`--cfg loom`).

#[cfg(not(loom))]
pub(crate) use core::hint::spin_loop;
#[cfg(not(loom))]
pub(crate) use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[cfg(loom)]
pub(crate) use loom::hint::spin_loop;
#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering};
