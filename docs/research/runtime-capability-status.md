# Runtime capability and acceptance status

This ledger distinguishes implemented operations from migration acceptance and
release qualification. The [runtime contract](../runtime.md) defines behavior;
the [implementation plan](resource-runtime-plan.md) defines the stable Linux
capability baseline and performance gates. A source or test link establishes
where an implementation or fixture lives. It does not assert that a new
qualification campaign passed.

The published package has allocator-only defaults and optional runtime modules.
Development comparators may use Tokio; published normal/build dependencies must
exclude it. Replacement uses explicit bounded application ports, with rejection
and ownership recovery, rather than exact Tokio API or binary compatibility.

## Operations and acceptance

| Operations | Implemented contract and focused fixtures | Remaining acceptance |
| --- | --- | --- |
| Owned Send tasks, local tasks, entry, joins, task sets and cancellation | [Async runtime](../../crates/allocatbelt/src/runtime/asynchronous/mod.rs), [lifecycle tests](../../crates/allocatbelt/src/runtime/asynchronous/tests.rs), [local tests](../../crates/allocatbelt/src/runtime/asynchronous/local_tests.rs) | Current source qualification; preserve model limits and explicit bounded admission |
| Original-thread blocking handoff | [Handoff](../../crates/allocatbelt/src/runtime/asynchronous/handoff.rs), [handoff tests](../../crates/allocatbelt/src/runtime/asynchronous/handoff_tests.rs) | Migration must retain borrowed and non-Send closures on the calling thread |
| Cooperative task progress | [Cooperative tests](../../crates/allocatbelt/src/runtime/asynchronous/cooperative_tests.rs), [timer cooperation](../../crates/allocatbelt/src/runtime/time_cooperative_tests.rs), [shared readiness I/O gate](../../crates/allocatbelt/src/runtime/readiness_io.rs) | Direct child-pipe and cached buffered operations have native exhausted-budget fixtures; application acceptance must preserve shared budgets and descendant charges |
| Channels, locks, semaphores, notifications, barriers and initialization | [Runtime exports](../../crates/allocatbelt/src/runtime/mod.rs), [same-source managed models](../../crates/allocatbelt/src/runtime/managed_model.rs) | Preserve FIFO, cancellation, retained-message charges and documented model coverage |
| Sleep, timeout, intervals and paused clock | [Time](../../crates/allocatbelt/src/runtime/time.rs) | Preserve deadline/reset generations and missed-tick policies; idle automatic clock advance is outside the contract |
| Readiness, TCP, UDP, Unix sockets, options and DNS | [Reactor](../../crates/allocatbelt/src/runtime/reactor.rs), [network tests](../../crates/allocatbelt/src/runtime/net_tests.rs) | Current lifecycle qualification and realistic application measurements; raw readiness has explicit cooperative-accounting limits |
| Files, directories and owned blocking/standard streams | [Filesystem tests](../../crates/allocatbelt/src/runtime/fs_tests.rs), [blocking-stream tests](../../crates/allocatbelt/src/runtime/blocking_io_tests.rs) | Application acceptance for detached cancellation, recovered inputs and completion-held permits/storage |
| Anonymous pipes and named FIFOs | [Pipe tests](../../crates/allocatbelt/src/runtime/unix_pipe_tests.rs), [FIFO tests](../../crates/allocatbelt/src/runtime/fs_fifo_tests.rs) | Buffered/FIFO migration with backpressure, partial cancellation, peer close and explicit driver cleanup |
| Managed simplex/duplex, buffering and stream utilities | [Managed pipes](../../crates/allocatbelt/src/runtime/io_pipes.rs), [buffered I/O](../../crates/allocatbelt/src/runtime/buffered_io.rs), [bounded-read tests](../../crates/allocatbelt/src/runtime/io_bounded_tests.rs), [bidirectional tests](../../crates/allocatbelt/src/runtime/io_bidirectional_tests.rs) | Application acceptance for exact retained suffixes, permits and cancellation recovery |
| Child lifecycle, pipes, bounded output and signals | [Child pipes and tests](../../crates/allocatbelt/src/runtime/process/pipe.rs), [bounded output](../../crates/allocatbelt/src/runtime/process/output.rs), [process-output acceptance tests](../../crates/allocatbelt-app-ports/tests/process_output.rs), [signal protocol tests](../../crates/allocatbelt/src/runtime/signal/protocol_tests.rs) | Focused process-output cases passed once on Linux; broader platform, lifecycle and release qualification remains open, including explicit ChildWait and SignalRecv accounting limits |
| Heterogeneous join, error-join and selection | [Composition](../../crates/allocatbelt/src/runtime/concurrency_many.rs), [declarative helpers](../../crates/allocatbelt/src/runtime/concurrency_macros.rs) | Preserve borrowing, disabled branches, selection policy and loser cleanup; randomized selection is outside the contract |
| Resource ledgers and explicit cgroup/adaptive controls | [Managed storage](../../crates/allocatbelt/src/runtime/managed.rs), [cgroup controls](../../crates/allocatbelt/src/runtime/cgroup.rs), [adaptive policy](../../crates/allocatbelt/src/runtime/adaptive.rs) | Real-pressure and overload qualification with readback failures; synthetic samples and successful writes establish correctness only |
| Owned-buffer runtime io_uring | [Runtime ring](../../crates/allocatbelt/src/runtime/uring.rs), [ring protocol](../../crates/allocatbelt/src/runtime/uring_protocol.rs) | Supported-kernel qualification, denial and no replay after submission; this additional capability is separate from the stable Tokio baseline |
| CPU, memory, HTTP, relay and disk application ports | [Ports and acceptance fixtures](../../crates/allocatbelt-app-ports/README.md) | HTTP/relay migrations are implemented with focused cancellation, rejection and half-close fixtures; realistic matched comparisons remain pending |

The buffering fixtures already retain the exact unwritten suffix after partial
progress and cancellation, clamp reads to valid buffered bytes, and retain the
managed charge through `into_parts`. Child-pipe fixtures already drain stdout
and stderr concurrently beyond pipe capacity and cover vectored partial reads,
EOF, stdin shutdown and waiter cancellation. These component contracts are the
starting point for the remaining application migrations.

## Qualification still required

The direct child-pipe and cached buffered accounting changes passed a
thirteen-command component check: formatting, Clippy with all targets and
features, release tests with all features, all 17 supported feature combinations,
the packaged consumer check and focused runtime cases. The primary allocator
release suite passed 882 cases with one ignored case. The packaged consumer
check verified that the production dependency graph contains no Tokio. The
same-source runtime Loom run selected three task-admission and cancellation
models; it did not model operating-system drivers or establish complete Loom
coverage. The native release run included 25 cooperative, five child-pipe,
49 network, 29 reactor and nine Unix-pipe cases. The pinned dependency audit
and policy checks also passed for the identical dependency inputs.
These checks establish the component behavior; remaining release checks and
application performance acceptance are still required.

The repaired complete isolated core Miri campaign at signed source revision
`c3ed95db4f9ba9b6ffd9d84d7651a3b5963de2c5` passed 135 tests and retained the
one intentional ignored contention benchmark. All 136 test-process and log-
writer exits were zero; no case timed out or was cancelled. Independent audit
verified the complete manifest, logs and owned-process closure. The current
core and checker sources match that campaign's reviewed source bridge. This
qualifies that core campaign; runtime, platform and performance gates remain
separate.

A subsequent bounded workspace campaign passed formatting, Clippy with all
targets and features, and release tests with all features on materialized source
equivalent to signed revision `282124453db18ee3ff8958388e983aa947d84a32`.
Independent audit verified all 314 materialized source entries, original and protected result equality,
zero command exits and owned-process cleanup. The captured release log contains
1,359 reported passes, zero reported failures and four reported ignored results
across 100 summary reports, including nested child-test runs; these are not distinct
test counts. Later documentation changes are outside that full source bridge.
Feature, package, platform and performance qualification remain separate.

Release requires source-specific ownership and lifecycle review, appropriate
concurrent models, standard checks, the complete isolated core Miri campaign,
supported-platform checks, feature combinations, a packaged consumer, and the
pinned dependency-security checks. Preserve failures, cancellations and explicit
coverage limits. Passing isolated cases or finding an implementation in source
does not establish release readiness.

Allocator, executor and application performance require the preregistered
[per-guest gates](resource-runtime-plan.md#performance-gates), including p99,
throughput, CPU and retained memory. Keep exploratory development separate from
independent confirmation. Rejected arrivals cannot be removed to produce an
all-arrival tail result. Instrumented diagnostic runs identify where time is
spent; they do not qualify an uninstrumented performance improvement.

The [foundation report](runtime-foundation.md) remains a historical milestone.
Its earlier test counts and measurements are not the current release inventory.
Update this ledger when public operations or acceptance fixtures change; publish
only sanitized, source-specific qualification conclusions.

### FIFO application acceptance scope

Five focused [FIFO application cases](../../crates/allocatbelt-app-ports/tests/fifo_pipeline.rs)
passed individually under bounded timeouts. They cover admission and peer
behavior, split UTF-8 buffering, partial writes under kernel backpressure,
cancellation after a committed prefix with exact suffix recovery, and file-
descriptor recovery after registration refusal. The committed-prefix case
keeps the worker permit and managed buffer charged until actual completion and
checks final waiter, registration and scratch cleanup. This is focused Linux
functional evidence; broader migration and performance qualification remain
open.

### Process-output acceptance scope

The focused application acceptance suite has one Linux correctness pass: all
fourteen selected tests passed under individual process-group timeouts, with
the helper child left ignored. Formatting, targeted Clippy, target compilation
and the exact test-list check also passed in that run. This result covers only
that bounded acceptance set and environment; it is not a complete Linux
platform matrix or release qualification.

| Acceptance test | Witness |
| --- | --- |
| `owned_scope_collects_finite_concurrent_streams_into_exact_managed_prefixes` | Concurrent stdout/stderr drain and exact retained prefixes |
| `owned_scope_distinguishes_exact_capacity_from_one_byte_overflow_and_recovers_parts` | Exact-capacity completion, overflow policy and ownership recovery |
| `dropping_pending_collector_cancels_waiters_while_reaper_keeps_detached_child` | Pending collector drop, waiter cancellation and child reaping |
| `stderr_overflow_returns_original_parts_and_resumes_without_replaying_probe` | Partial overflow recovery and resumed stderr without replay |
| `kill_and_wait_overflow_preserves_the_prefix_probe_and_reaps` | Kill-and-wait overflow handling with retained prefix and reaping |
| `process_slot_rejection_preserves_and_retries_the_same_command_after_reap` | Rejected command ownership and retry after actual reap |
| `task_and_scope_cancellation_follow_real_pending_output_and_release_waiters` | Task/scope cancellation after pending output and waiter release |
| `one_worker_runs_a_gated_sibling_after_producer_completion_while_collector_is_pending` | Sibling progress while the collector is pending after producer completion |
| `public_scalar_read_charge_and_zero_budget_gate_preserve_state` | Scalar child-pipe read charge and exhausted-budget state preservation |
| `public_vectored_read_charge_and_zero_budget_gate_preserve_state` | Vectored child-pipe read charge and exhausted-budget state preservation |
| `public_scalar_write_charge_and_zero_budget_gate_preserve_state` | Scalar child-pipe write charge and exhausted-budget state preservation |
| `public_vectored_write_charge_and_zero_budget_gate_preserve_state` | Vectored child-pipe write charge and exhausted-budget state preservation |
| `sixty_four_ready_pipe_reads_yield_to_a_gated_single_worker_sibling` | Sixty-four ready pipe reads followed by sibling progress |
| `full_child_stdin_pending_cancels_waiter_and_resumes_same_writer_once` | Actual full-pipe pending, waiter cancellation and single resumption |

The suite does not establish inherited-grandchild behavior, private partial-byte
recovery after cancellation, the collector's own 64-operation shared-budget
boundary, or complete pipe drain in the sibling-progress case. The ignored
`process_output_helper_child` supports the parent cases but is not an
independently selected acceptance case. These gaps remain for future focused
fixtures and supported-platform qualification.
