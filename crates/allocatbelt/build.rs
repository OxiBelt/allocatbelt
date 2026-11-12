//! Reads whether a riscv64 build enables the V extension, for the platform
//! gate in `src/sys/platform.rs`.
//!
//! `v` is an unstable target feature: stable Rust accepts
//! `-C target-feature=+v` but never reports it to `cfg(target_feature)`, so
//! the gate cannot test it there. This script reads the flags Cargo passes to
//! the compiler instead and sets `allocatbelt_riscv64_without_v` when a
//! riscv64 build does not enable V; the gate turns that into a
//! `compile_error!`. A nightly compiler that does report `v` is accepted too.

use std::env;

#[path = "build/v_flag.rs"]
mod v_flag;

fn main() {
  println!("cargo::rerun-if-changed=build.rs");
  println!("cargo::rerun-if-changed=build/v_flag.rs");
  println!("cargo::rustc-check-cfg=cfg(allocatbelt_riscv64_without_v)");
  // The target's architecture, not the host's: a build script runs on the
  // host, and only the crate it configures is compiled for the target.
  if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("riscv64") {
    return;
  }
  let reported = env::var("CARGO_CFG_TARGET_FEATURE")
    .is_ok_and(|features| features.split(',').any(|feature| feature == "v"));
  let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
  if !(reported || v_flag::enables_v(&flags)) {
    println!("cargo::rustc-cfg=allocatbelt_riscv64_without_v");
  }
}
