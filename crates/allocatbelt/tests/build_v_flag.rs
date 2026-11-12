//! Runs the tests of the flag parser that `build.rs` uses for the riscv64
//! V gate (`build/v_flag.rs`); a build script's own tests never run.

#[path = "../build/v_flag.rs"]
mod v_flag;
