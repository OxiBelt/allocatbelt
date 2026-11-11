//! The platform contract: which targets allocatbelt builds for, and which
//! kernel facilities it checks for before it reserves its arena.
//!
//! See `docs/platform.md` for the policy these gates and probes implement.

use crate::sys::{GRANULE, Region};

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
  "allocatbelt on x86_64 must be built for x86-64-v3 or newer: build the final binary with `-C target-cpu=x86-64-v3` (or a newer CPU), in RUSTFLAGS or your workspace's `.cargo/config.toml`. Cargo does not apply allocatbelt's own `.cargo/config.toml` to crates that depend on it, and a `RUSTFLAGS` environment variable replaces the config's flags; see allocatbelt's README"
);

/// A Linux kernel release as `uname(2)` reports it, for diagnostics.
///
/// The version is not what decides whether allocatbelt runs: the start-up probe
/// checks the facilities themselves (see `docs/platform.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KernelVersion {
  /// Major version (the `7` in `7.0.3`).
  pub major: u32,
  /// Minor version.
  pub minor: u32,
  /// Patch level; `0` when the release string has none.
  pub patch: u32,
}

impl KernelVersion {
  /// The oldest kernel the platform contract supports: Linux 7.0.
  pub const MINIMUM: Self = Self {
    major: 7,
    minor: 0,
    patch: 0,
  };

  /// Parses the leading `major.minor[.patch]` of a release string such as
  /// `7.0.3-1-generic`. Returns `None` when it does not start that way.
  #[must_use]
  pub fn parse(release: &[u8]) -> Option<Self> {
    let mut parts = release
      .split(|&b| b == b'.')
      .map(|part| {
        let mut digits = part.iter().take_while(|b| b.is_ascii_digit());
        digits.try_fold((0u32, 0usize), |(n, len), &d| {
          Some((
            n.checked_mul(10)?.checked_add(u32::from(d - b'0'))?,
            len + 1,
          ))
        })
      })
      .map(|n| n.filter(|&(_, len)| len > 0).map(|(n, _)| n));
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().flatten().unwrap_or(0);
    Some(Self {
      major,
      minor,
      patch,
    })
  }

  /// Whether this release is at least [`KernelVersion::MINIMUM`].
  #[must_use]
  pub fn meets_minimum(self) -> bool {
    self >= Self::MINIMUM
  }
}

/// What the start-up probe found about the running kernel.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
  /// The running kernel's release, if `uname(2)` reports a parseable one.
  pub kernel: Option<KernelVersion>,
  /// Whether `MADV_GUARD_INSTALL` guard markers take effect. Without them
  /// (emulators such as qemu-user) guard pages use `mprotect(PROT_NONE)`.
  pub guard_markers: bool,
  /// Whether `getrandom(2)` returned entropy without blocking. Without it
  /// the placement secret falls back to ASLR and the time.
  pub getrandom: bool,
}

/// A mandatory kernel facility that [`probe`] found missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
  /// `mmap(PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE)` failed.
  Reserve,
  /// `mprotect(PROT_READ | PROT_WRITE)` on a reserved range failed.
  Commit,
  /// `madvise(MADV_DONTNEED)` on committed anonymous memory failed.
  Purge,
  /// `madvise(MADV_DONTNEED)` succeeded but the memory did not read back as
  /// zero, so purged memory could not back `alloc_zeroed`.
  PurgeNotZeroed,
}

impl ProbeError {
  /// A one-line description for the fatal error message.
  #[must_use]
  pub const fn message(self) -> &'static str {
    match self {
      Self::Reserve => {
        "allocatbelt: the kernel refused an anonymous PROT_NONE MAP_NORESERVE mapping; see docs/platform.md"
      }
      Self::Commit => {
        "allocatbelt: the kernel refused mprotect(PROT_READ | PROT_WRITE) on reserved memory; see docs/platform.md"
      }
      Self::Purge => {
        "allocatbelt: the kernel refused madvise(MADV_DONTNEED) on anonymous memory; see docs/platform.md"
      }
      Self::PurgeNotZeroed => {
        "allocatbelt: memory did not read as zero after madvise(MADV_DONTNEED); see docs/platform.md"
      }
    }
  }
}

/// Checks, on a private scratch range, the kernel facilities the allocator
/// cannot run without, and records the optional ones.
///
/// Mandatory: reserving address space, committing it, and `MADV_DONTNEED`
/// returning pages that read back as zero. Optional: guard markers and
/// `getrandom(2)`, which have fallbacks.
///
/// Issues only syscalls and does not allocate. It leaves behind one
/// [`GRANULE`] of `PROT_NONE`, `MAP_NORESERVE` address space, which holds no
/// memory. Call it once, before the arena is reserved.
///
/// # Errors
///
/// Returns the first mandatory facility that is missing.
pub fn probe() -> Result<Capabilities, ProbeError> {
  let kernel = KernelVersion::parse(rustix::system::uname().release().to_bytes());
  let scratch = Region::reserve(GRANULE, GRANULE).ok_or(ProbeError::Reserve)?;
  let byte = scratch.ptr(0).ok_or(ProbeError::Reserve)?.as_ptr();
  if !scratch.commit(0, GRANULE) {
    return Err(ProbeError::Commit);
  }
  // SAFETY: `byte` is the first byte of `scratch`, which was just committed
  // read/write and is private to this function.
  #[expect(unsafe_code, reason = "writing to freshly committed memory")]
  unsafe {
    byte.write_volatile(0xa5);
  }
  // SAFETY: no reference into `scratch` exists; `byte` is a raw pointer
  // that is only read again after the purge.
  #[expect(unsafe_code, reason = "purging memory this function owns")]
  let purged = unsafe { scratch.purge(0, GRANULE) };
  if !purged {
    return Err(ProbeError::Purge);
  }
  // SAFETY: `scratch` is still committed read/write (a purge keeps it
  // accessible), and nothing else accesses it.
  #[expect(unsafe_code, reason = "reading back purged memory")]
  let after = unsafe { byte.read_volatile() };
  if after != 0 {
    return Err(ProbeError::PurgeNotZeroed);
  }
  // SAFETY: nothing accesses `scratch` any more.
  #[expect(unsafe_code, reason = "guarding memory this function owns")]
  let guard_markers = unsafe { scratch.guard_markers(0, GRANULE) };
  scratch.unguard(0, GRANULE);
  // SAFETY: as above. This returns the scratch range to `PROT_NONE`.
  #[expect(unsafe_code, reason = "decommitting memory this function owns")]
  let _ = unsafe { scratch.decommit(0, GRANULE) };
  Ok(Capabilities {
    kernel,
    guard_markers,
    getrandom: crate::sys::random_u64().is_some(),
  })
}

#[cfg(test)]
mod tests {
  use super::{KernelVersion, probe};

  fn v(major: u32, minor: u32, patch: u32) -> Option<KernelVersion> {
    Some(KernelVersion {
      major,
      minor,
      patch,
    })
  }

  #[test]
  fn parses_release_strings() {
    assert_eq!(KernelVersion::parse(b"7.0.3-1-generic"), v(7, 0, 3));
    assert_eq!(KernelVersion::parse(b"7.1"), v(7, 1, 0));
    assert_eq!(KernelVersion::parse(b"7.2-rc1"), v(7, 2, 0));
    assert_eq!(KernelVersion::parse(b"6.18.44-fc-v37"), v(6, 18, 44));
    assert_eq!(KernelVersion::parse(b"10.4.0+"), v(10, 4, 0));
    assert_eq!(KernelVersion::parse(b""), None);
    assert_eq!(KernelVersion::parse(b"7"), None);
    assert_eq!(KernelVersion::parse(b"7.x"), None);
    assert_eq!(KernelVersion::parse(b"generic"), None);
    assert_eq!(KernelVersion::parse(b"99999999999.0"), None);
  }

  #[test]
  fn minimum_is_linux_7_0() {
    assert!(KernelVersion::MINIMUM.meets_minimum());
    assert!(v(7, 0, 0).is_some_and(KernelVersion::meets_minimum));
    assert!(v(7, 1, 2).is_some_and(KernelVersion::meets_minimum));
    assert!(!v(6, 19, 99).is_some_and(KernelVersion::meets_minimum));
  }

  #[test]
  fn mandatory_facilities_are_present() {
    let caps = probe().expect("the test host lacks a mandatory facility");
    assert!(caps.kernel.is_some(), "unparseable kernel release");
  }
}
