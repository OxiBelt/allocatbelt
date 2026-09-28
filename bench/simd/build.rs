//! Records the compiler version for the benchmark report, and whether a
//! riscv64 build enables the V extension.

use std::process::Command;

fn main() {
  let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
  let version = Command::new(rustc)
    .arg("--version")
    .output()
    .ok()
    .and_then(|o| String::from_utf8(o.stdout).ok())
    .unwrap_or_else(|| "unknown".into());
  println!(
    "cargo:rustc-env=ALLOCATBELT_RUSTC_VERSION={}",
    version.trim()
  );
  println!("cargo:rerun-if-env-changed=RUSTC");

  // `v` is an unstable target feature, so `cfg!(target_feature = "v")` is
  // false on stable even with `-C target-feature=+v`; read the flags instead.
  println!("cargo::rustc-check-cfg=cfg(allocatbelt_rvv)");
  let riscv64 = std::env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|a| a == "riscv64");
  let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
  let enables_v = flags
    .split('\x1f')
    .filter_map(|f| f.trim_start_matches("-C").strip_prefix("target-feature="))
    .flat_map(|list| list.split(','))
    .fold(false, |on, feature| match feature {
      "+v" => true,
      "-v" => false,
      _ => on,
    });
  if riscv64 && enables_v {
    println!("cargo::rustc-cfg=allocatbelt_rvv");
  }
}
