//! Whether the compiler flags Cargo passes enable the riscv64 V extension.
//! Shared by `build.rs` and the `build_v_flag` test, which runs its tests.

/// Whether the compiler flags, as Cargo encodes them (separated by `0x1f`),
/// leave the V extension enabled: the last `+v` or `-v` among every
/// `target-feature` list decides, as it does for the compiler. Only an
/// explicit `+v` counts: a `target-cpu` that has V is not read, since the
/// stable compiler does not report the features a CPU implies.
pub fn enables_v(encoded: &str) -> bool {
  let mut args = encoded.split('\x1f').filter(|arg| !arg.is_empty());
  let mut on = false;
  while let Some(arg) = args.next() {
    let option = match arg {
      // `-C target-feature=...` and `--codegen target-feature=...`.
      "-C" | "--codegen" => args.next(),
      // `-Ctarget-feature=...` and `--codegen=target-feature=...`.
      _ => arg
        .strip_prefix("-C")
        .or_else(|| arg.strip_prefix("--codegen=")),
    };
    let Some(list) = option.and_then(|o| o.strip_prefix("target-feature=")) else {
      continue;
    };
    for feature in list.split(',') {
      match feature.trim() {
        "+v" => on = true,
        "-v" => on = false,
        _ => {}
      }
    }
  }
  on
}

#[cfg(test)]
mod tests {
  use super::enables_v;

  fn encoded(args: &[&str]) -> String {
    args.join("\x1f")
  }

  #[test]
  fn reads_every_spelling_of_the_flag() {
    for args in [
      &["-C", "target-feature=+v"][..],
      &["-Ctarget-feature=+v"],
      &["--codegen", "target-feature=+v"],
      &["--codegen=target-feature=+v"],
      &["-C", "target-feature=+zbb,+v"],
      &["-C", "target-feature=+v,+zbb"],
      &["-C", "target-feature=+v", "-C", "target-feature=+zbb"],
      &["-C", "target-cpu=sifive-x280", "-C", "target-feature=+v"],
    ] {
      assert!(enables_v(&encoded(args)), "{args:?}");
    }
  }

  #[test]
  fn rejects_missing_disabled_and_implied_v() {
    for args in [
      &[][..],
      &["-C", "target-feature=+zbb"],
      &["-C", "target-feature=+v,-v"],
      &["-C", "target-feature=+v", "-C", "target-feature=-v"],
      &["-C", "target-feature=+zve64d"],
      &["-C", "target-feature=+vv"],
      &["-C", "target-cpu=sifive-x280"],
      &["--cfg", "target-feature=+v"],
      &["-C"],
    ] {
      assert!(!enables_v(&encoded(args)), "{args:?}");
    }
  }

  #[test]
  fn a_later_plus_v_turns_it_back_on() {
    assert!(enables_v(&encoded(&[
      "-C",
      "target-feature=-v",
      "-C",
      "target-feature=+v"
    ])));
  }
}
