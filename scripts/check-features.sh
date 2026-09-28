#!/usr/bin/env bash
# Builds, lints and tests `allocatbelt` with each supported combination of
# its Cargo features (single-package directive §5, §15.7, §16). Every
# feature is additive and stable, so each combination must build on the
# pinned stable toolchain without warnings and pass its tests; the tests of
# an optional part run only when it is compiled in, and
# `compiled_capabilities_follow_the_features` checks that
# `CompiledCapabilities` reports exactly the features of each build.
#
#   scripts/check-features.sh            # clippy and tests
#   FEATURES_CLIPPY_ONLY=1 scripts/check-features.sh
set -euo pipefail

cd "$(dirname "$0")/.."

combos=(
  "--no-default-features"
  "--no-default-features --features maintenance"
  "--no-default-features --features io-uring"
  "--no-default-features --features experimental-rseq"
  ""
  "--features io-uring"
  "--features experimental-rseq"
  "--no-default-features --features experimental-aarch64-sve"
  "--features experimental-aarch64-sve2"
  "--all-features"
)

for combo in "${combos[@]}"; do
  # shellcheck disable=SC2086 # word splitting of the flags is intended
  {
    echo "== allocatbelt ${combo:-(default features)}"
    cargo clippy -p allocatbelt --all-targets --locked ${combo} -- -D warnings
    if [[ -z "${FEATURES_CLIPPY_ONLY:-}" ]]; then
      cargo test -p allocatbelt --release --locked ${combo}
    fi
  }
done
echo "ok: ${#combos[@]} feature combinations"
