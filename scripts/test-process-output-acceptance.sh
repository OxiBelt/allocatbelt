#!/usr/bin/env bash
# Run the focused process-output cases one per externally bounded process.
set -Eeuo pipefail
umask 077

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
command -v cargo >/dev/null
command -v timeout >/dev/null

private_tmp=$(mktemp -d /tmp/ab-process-output-XXXXXXXX)
[[ "$private_tmp" == /tmp/ab-process-output-* ]]
[[ "$(stat -c '%a' "$private_tmp")" == 700 ]]
export TMPDIR="$private_tmp"
test_list="$private_tmp/test-list.txt"
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -f "$test_list" ]]; then rm -- "$test_list"; fi
  rmdir -- "$private_tmp" 2>/dev/null || true
  exit "$result"
}
trap cleanup EXIT

run_bounded() {
  local label=$1 seconds=$2 status
  shift 2
  printf 'START %s\n' "$label"
  if timeout --signal=TERM --kill-after=3s "${seconds}s" "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'EXIT %s %s\n' "$label" "$status"
  return "$status"
}

cases=(
  owned_scope_collects_finite_concurrent_streams_into_exact_managed_prefixes
  owned_scope_distinguishes_exact_capacity_from_one_byte_overflow_and_recovers_parts
  dropping_pending_collector_cancels_waiters_while_reaper_keeps_detached_child
  stderr_overflow_returns_original_parts_and_resumes_without_replaying_probe
  kill_and_wait_overflow_preserves_the_prefix_probe_and_reaps
  process_slot_rejection_preserves_and_retries_the_same_command_after_reap
  task_and_scope_cancellation_follow_real_pending_output_and_release_waiters
  one_worker_runs_a_gated_sibling_after_producer_completion_while_collector_is_pending
  public_scalar_read_charge_and_zero_budget_gate_preserve_state
  public_vectored_read_charge_and_zero_budget_gate_preserve_state
  public_scalar_write_charge_and_zero_budget_gate_preserve_state
  public_vectored_write_charge_and_zero_budget_gate_preserve_state
  sixty_four_ready_pipe_reads_yield_to_a_gated_single_worker_sibling
  full_child_stdin_pending_cancels_waiter_and_resumes_same_writer_once
)
helper=process_output_helper_child
run_bounded test-list 60 cargo test --release --locked -p allocatbelt-app-ports --test process_output -- --list --format terse > "$test_list"
listed=$(grep -Ec ': test$' "$test_list" || true)
[[ "$listed" == 15 ]]
for name in "${cases[@]}" "$helper"; do
  [[ "$(grep -Fxc "$name: test" "$test_list")" == 1 ]]
done
rm -- "$test_list"
for name in "${cases[@]}"; do
  run_bounded "$name" 45 cargo test --release --locked -p allocatbelt-app-ports --test process_output "$name" -- --exact --nocapture
done
