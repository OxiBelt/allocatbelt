//! The platform contract: which targets allocatbelt builds for.
//!
//! See `docs/platform.md` for the policy these gates implement.

#[cfg(not(target_os = "linux"))]
compile_error!("allocatbelt supports only Linux (7.0 or newer); see docs/platform.md");

#[cfg(not(any(
  target_arch = "x86_64",
  target_arch = "aarch64",
  target_arch = "riscv64"
)))]
compile_error!(
  "allocatbelt supports only x86_64 (x86-64-v3 or newer), aarch64 and riscv64; see docs/platform.md"
);

#[cfg(not(all(target_pointer_width = "64", target_has_atomic = "64")))]
compile_error!(
  "allocatbelt needs 64-bit userspace with 64-bit atomics (x32 and other ILP32 ABIs are not supported); see docs/platform.md"
);

#[cfg(not(target_endian = "little"))]
compile_error!("allocatbelt supports only little-endian targets; see docs/platform.md");

// The x86-64-v3 feature set (and the v2 set it includes), as `rustc --print
// cfg -C target-cpu=x86-64-v3` reports it. A build without it is a generic
// x86-64-v1/v2 artifact, which the contract rules out.
#[cfg(all(
  target_arch = "x86_64",
  not(all(
    target_feature = "avx",
    target_feature = "avx2",
    target_feature = "bmi1",
    target_feature = "bmi2",
    target_feature = "cmpxchg16b",
    target_feature = "f16c",
    target_feature = "fma",
    target_feature = "lzcnt",
    target_feature = "movbe",
    target_feature = "popcnt",
    target_feature = "sse3",
    target_feature = "sse4.1",
    target_feature = "sse4.2",
    target_feature = "ssse3",
    target_feature = "xsave",
  ))
))]
compile_error!(
  "allocatbelt on x86_64 must be built for x86-64-v3 or newer: pass `-C target-cpu=x86-64-v3` (or a newer CPU) in RUSTFLAGS. This repository's `.cargo/config.toml` does so, but a `RUSTFLAGS` environment variable replaces it; see docs/platform.md"
);
