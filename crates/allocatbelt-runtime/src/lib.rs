//! Development façade for the optional blocking runtime in `allocatbelt`.
//! The implementation is packaged once, in `allocatbelt::runtime`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(not(loom))]
pub use allocatbelt::runtime::*;

// Compile the identical safe runtime source without the allocator under Loom.
#[cfg(loom)]
#[path = "../../allocatbelt/src/runtime/mod.rs"]
mod runtime;
#[cfg(loom)]
pub use runtime::*;
