#!/usr/bin/env bash
# Exercise the opt-in engine through defaults, retaining the normal full run
# for handoffs and tests whose observations require Strict's global queues.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export ALLOCATBELT_ASYNC_DISPATCH=distributed
cargo test --release --all-features --locked -p allocatbelt --lib runtime -- \
  --skip asynchronous::handoff_tests \
  --skip thread_name_callback_gets_physical_roles_and_copied_options \
  --skip busy_duration_excludes_handoff_closure_and_attributes_helper_turns \
  --skip resource_handoff_thread_options_wrapper_keeps_the_root_binding \
  --skip resource_domain_runtime_tests::handed_off_ \
  --skip asynchronous::scheduler::tests \
  --skip ready_queue_rotates_fairly_between_scopes \
  --skip saturated_scope_preserves_fifo_and_cancellation_leapfrogs_queued_work
