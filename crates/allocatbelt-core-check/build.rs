//! Tells the shared core source (crates/allocatbelt/src/core) that it is
//! being built by this package, where its tests and model belong, rather
//! than inside the published `allocatbelt` package.

fn main() {
  println!("cargo::rustc-cfg=allocatbelt_core_check");
  if std::env::var_os("CARGO_FEATURE_MODEL").is_some() {
    println!("cargo::rustc-cfg=allocatbelt_model");
  }
}
