//! Runs arbitrary byte strings as programs of heap operations through
//! several thread caches, checking the heap's invariants against the
//! shadow maps of `allocatbelt_core_check::core::model` (see `model::run`).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| allocatbelt_core_check::core::model::run(data));
