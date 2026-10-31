#!/usr/bin/env bash
# Exercise the opt-in engine through defaults, retaining the normal full run
# for tests whose observations require Strict's global queues.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export ALLOCATBELT_ASYNC_DISPATCH=distributed
timeout 300s cargo test --release --all-features --locked -p allocatbelt --lib runtime -- \
  --skip asynchronous::scheduler::tests
