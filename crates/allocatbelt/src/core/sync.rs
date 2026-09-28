//! The atomics and fences used by [`crate::core::proto`] and [`crate::core::lock`]: `core`'s, or
//! `loom`'s when the protocols are model-checked (`--cfg loom`).

#[cfg(not(loom))]
pub(crate) use core::hint::spin_loop;
#[cfg(not(loom))]
pub(crate) use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

#[cfg(loom)]
pub(crate) use loom::hint::spin_loop;
#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
