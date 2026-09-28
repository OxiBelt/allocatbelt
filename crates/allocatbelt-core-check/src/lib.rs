//! allocatbelt's safe core as a crate of its own (development only, never
//! published).
//!
//! The published `allocatbelt` package holds the core as its module `core`,
//! under `forbid(unsafe_code)`. A module cannot be `#![no_std]`, so this
//! package compiles the same source files as a `#![no_std]` crate: a `std`
//! dependency in the core fails to build here, as it did when the core was
//! the `allocatbelt-core` crate. The module keeps its name and its place
//! under the crate root, so its `crate::core::…` paths resolve the same way
//! in both packages.
//!
//! It is also where the core's tests run (model tests, proptest, loom under
//! `--cfg loom`, and the lock benchmark), and, with the `model` feature, what
//! the fuzz target, the codegen probes and the SIMD benchmarks link against.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, loom, feature = "model"))]
extern crate std;

#[path = "../../allocatbelt/src/core/mod.rs"]
pub mod core;
