# Application ports: nonblocking HTTP migration

The app-ports crate keeps its existing `loopback_transaction` and
`loopback_transaction_with_id` APIs, including their blocking-pool connection
path. The additive `loopback_transaction_nonblocking` and
`loopback_transaction_nonblocking_with_id` APIs reuse the same bounded HTTP
request/response kernels and server join/abort handling, while creating an
explicit IPv4 loopback listener and connecting through the caller's readiness
reactor with one `NetHandle::connect_socket` attempt. They preserve the same
`HttpConfig`, ID, checksum and `PortResult` shape. The required
`BlockingHandle` remains a `NetHandle` construction dependency; this path does
not submit a blocking connect job, resolve names or retry addresses.

The new functions validate body size before socket, listener or task admission.
They create no runtime, reactor, timer or implicit timeout. If a deadline is
needed, callers wrap the whole transaction future (including its server join)
with their own `TimerHandle::timeout_at` or `timeout`. If that wrapper expires
or is dropped, `AbortOnDrop` requests server cancellation; cleanup may still be
in progress. Drop the wrapper before `scope.close()`, then shut down the
caller-owned runtimes and reactor after the close barrier completes. An abort
does not roll back bytes or a TCP handshake already observed by a peer.

The functional `tcp_http` example chooses the new variant and supplies an
explicit 30-second timer policy around the entire transaction. This is an
example caller choice, not a default port policy. The dedicated
`tests/nonblocking_http_port.rs` cases run behind whole-test 45-second
subprocess watchdogs that kill and reap the test process on timeout. Their
scope-task snapshots are read before the consuming `scope.close()` call; the
close barrier is followed by independent resource/reactor checks. The cases
are
`reusable_http_registration_rejection_aborts_server_and_frees_listener`,
`reusable_http_preoccupied_network_admission_is_clean`,
`reusable_http_capacity_one_refuses_two_live_endpoints`,
`reusable_http_rejects_invalid_body_before_listener_registration`,
`reusable_http_full_scope_rejects_server_and_drops_listener`,
`reusable_http_cancellation_after_connect_admission_reclaims_server_task`,
`reusable_http_timer_full_refuses_before_listener_or_task_admission`,
`reusable_http_timeout_cleans_admitted_transaction`, and
`reusable_http_timeout_preserves_timer_closed_error`. Both timeout cases use a
one-slot task scope and prove that a sentinel can reuse the server slot after
the wrapper returns, before consuming the scope in `close()`. The cases cover registration
and resource admission rejection, endpoint permit separation, body-bound
validation, future cancellation at a deterministic cooperative checkpoint,
timer admission refusal, deadline completion and preservation of timer-close
errors. The adapted
`nonblocking_socket_http_progresses_with_a_full_blocking_pool` case exercises
the actual reusable helper with zero and maximum-size bodies and an independent
checksum while the blocking pool is held. Existing low-level socket tests
remain separate because the reusable transaction API intentionally does not
expose its internal client socket.

No performance claim follows from these correctness paths. They do not change
allocator behavior, HTTP framing, admission limits, or the existing comparison
pilots.

# Managed-buffer TCP relay

The additive `relay` module separates a borrowed `relay_io` adapter from a
single-use `RelaySession`. The generic helper delegates to the runtime's
bounded bidirectional-copy state machine and refreshes `RelayProgress` after
each normal poll. `RelaySession::new` checks both scratch buffers and then
atomically acquires two network slots; a refusal returns the original streams
and buffers. The session does not move preexisting buffer charges between
resource ledgers.

Dropping the borrowed `run` future retains the session and its buffers. The
reported unwritten ranges identify initialized source bytes that the
underlying copy had not yet delivered at its last returned poll. A session
that was polled cannot be restarted: it may have consumed bytes, partially
written, flushed or shut down one direction. `finish` is available after the
run future is dropped; it cancels retained readiness waits, drops endpoints,
releases their permit, and returns the original buffers and last progress.
Returned buffers and their clones keep their original managed charge until
the final clone drops. Aborting a task that owns a whole session drops that
session normally and does not return its buffers.

The functional `relay` example uses two loopback connections, deterministic
peer payloads, explicit half-close, bounded scratch and resource limits. Its
managed-memory limit covers the two relay scratch buffers; its network limit
covers the two imported relay endpoints. The standard listeners, peer sockets,
peer threads and payload `Vec`s used for synchronous loopback setup are outside
those ledgers. The example uses finite peer I/O timeouts, while a lost relay
wake still requires an outer process deadline. It does not claim that all
process memory or kernel socket storage is managed.

The `tests/relay.rs` cases have whole-test subprocess watchdogs and cover
constructor recovery, bounded-pipe backpressure with retained suffix bytes,
scripted short-write/Pending/error progress, real TCP half-close/reverse
response, canceled borrowed-run output publication after a positive prefix,
no-restart refusal, and final buffer-clone charge lifetime. The suite is
source-only in this candidate; no native test or build has been run.

The relay suite includes `generic_buffer_validation_precedes_endpoint_polls`,
`generic_relay_reports_bounded_duplex_backpressure`,
`tcp_half_close_delivers_reverse_reply`,
`cancellation_returns_suffix_and_forbids_restart`,
`finished_output_clone_retains_only_its_buffer_charge`, and
`canceled_borrowed_run_publishes_positive_prefix_and_charge`,
`owned_task_abort_drops_session_instead_of_returning_output`, and
`relay_error_preserves_short_write_suffix_progress`. An aborted
whole-session task drops its owned session and scratch charges; only a task
that completes normally can publish `RelayOutput`.
