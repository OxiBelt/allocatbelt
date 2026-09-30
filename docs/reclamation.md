# Reclamation: when freed memory goes back to the OS

Freed page runs stay resident as *dirty* pages, so that a program that frees and allocates again reuses them without a system call. This page describes when they are purged (`MADV_DONTNEED`, or the opt-in io_uring backend) and how much work that may cost the thread that does it. None of the numbers below was tuned by measurement: **performance not measured; benchmark gate intentionally disabled** (see [research/theory-driven-implementation-status.md](research/theory-driven-implementation-status.md)).

## Thresholds

`ReclaimTargets` holds three thresholds on the dirty pages the allocator tracks, in 64 KiB allocator pages, with `low < trigger <= emergency`:

| Threshold | Default | What happens |
|---|---|---|
| low target | 0 | a budget cycle purges until at most this many pages are dirty |
| trigger | 512 pages (32 MiB) | a free that takes the count above it starts a budget cycle |
| emergency | 1024 pages (64 MiB) | a free above it reclaims itself, in larger slices, even with a maintenance thread |

`Allocatbelt::set_reclaim_targets` changes them at run time (`ReclaimTargets::new` in pages, `from_bytes` in bytes rounded down to pages; both refuse a zero trigger, a wrong order and values larger than the arena). The defaults keep what the allocator did before these thresholds existed: past 32 MiB, purge everything dirty; past 64 MiB with a maintenance thread, a freeing thread steps in. A low target above 0 keeps that much freed memory for reuse after a cycle.

The thresholds bound **tracked dirty pages**, not the process's RSS, which also holds live and cached blocks, metadata and whatever the OS keeps resident. Dirty memory can pass every threshold when the program frees faster than reclamation runs, or when the OS refuses purges.

## Sweeps and slices

Every kind of pass is a *sweep* over the heap: first trimming each shard (releasing small pages whose blocks are all free, returning segments that stayed empty for the purge delay, keeping one per shard), then claiming and purging the dirty pages of every owned segment.

| Sweep | Purges | Started by |
|---|---|---|
| decay | pages dirty for the purge delay | the decay schedule (every quarter delay) |
| budget | dirty pages regardless of age, down to the low target | the trigger |
| force | everything, and every empty segment but one per shard | `purge()`, `request_purge()` |

Trimming finds fully free small pages through **empty-page candidates**: the free that returns a page's last block marks the page in its segment's candidate word, and trimming, under the shard's lock, takes the word and checks each marked page's free count before it releases the page. It does not check every small page of every segment. A candidate is a request to look, never permission to release: a page claimed from again since then is left alone (`stale_empty_candidates`). Force sweeps, and every 16th decay sweep (by decay epoch), also check every small page: a bounded reconciliation that would find a fully free page whose candidate was lost (`reconciled_pages`, expected to stay 0). Releasing a page takes it off its shard's page list for its class and drops the shard's cursor for the class if it was on that page; trimming keeps every other cursor.

A sweep runs in **slices**. A slice stops once it has spent its work limit, counted in units of what it inspects and attempts: shards (busy ones included), segments visited, small pages checked, bitmap words scanned, runs submitted to the OS (refused ones included). So a slice is bounded even when every purge fails or there is nothing to purge. The step that crosses the limit finishes, which adds at most one segment's work (64 pages, 32 runs). A slice completes every purge it submitted before it returns; no page stays claimed between slices. Between slices the sweep's position is kept (a segment index for the purge phase, the last segment kept in the current shard for the trim), and resuming re-reads what it finds there, so segments returned or reused meanwhile are handled as what they are now.

A sweep keeps the decay epoch, age and cutoff it started with. Decay epochs advance on the schedule only, never per slice, so a sweep that takes many slices does not age pages faster; a new purge delay applies from the next sweep.

## Budget cycles

- A cycle starts when a free takes the dirty count above the trigger.
- It stays pending when the count drops below the trigger, until the count is at or below the low target (checked after each purged segment) or a full sweep has been made.
- After a full sweep it starts again only if the count is still above the trigger, so frees that race the sweep are not chased below it.
- A full sweep that made no progress (nothing purged or released, no segment returned) while above the low target **stalls** the cycle: `stalled_cycles` counts it, `reclaim_status().budget_deferred` shows it, and new cycles wait for the next decay epoch. Past the emergency threshold, freeing threads still run emergency slices.

## Who runs the slices

**With the maintenance thread** (`start_maintenance_thread`): frees only record a request and wake it; the thread runs one slice per round, of the most urgent work (force, then budget, then decay), and sleeps when nothing is due. It releases the purge lock between slices, so a force purge can go ahead of a long budget sweep. A deferred budget request stays recorded while the thread sleeps, and any other request still wakes it. A free past the emergency threshold runs an emergency slice itself (`hard_limit_slices`).

**Without it**, the allocating threads run the slices:

- the free that starts a cycle runs its first slice;
- every page-run free while a cycle is pending runs another;
- allocation slow paths (every 16th, as they read the clock) start decay sweeps when due and continue whatever sweep or cycle is pending.

These calls are the only opportunities: a process that stops calling the allocator stops reclaiming too. A slice that finds the purge lock taken is skipped (`skipped_passes`), not waited for.

**Explicit calls** run to the end on the calling thread. `purge()` flushes the caller's cache, replaces any sweep in progress with a force sweep and runs it to its end; it respects busy shards and the one empty segment each shard keeps, and does not chase frees that race it. `decay()` advances the epoch and runs a decay sweep to its end (after the sweep in progress, if any).

**Priority.** A force sweep replaces any other. A budget cycle continues a budget or force sweep and turns a decay sweep into a budget sweep from where it is. A decay sweep starts only when nothing is in progress; a decay epoch that falls due meanwhile still advances and is owed (`reclaim_status().decay_owed`), so budget work cannot hold decay's bookkeeping back.

## Adaptive retention (opt-in)

`Allocatbelt::set_retention(Retention::Adaptive)` lets decay keep freed pages longer while they keep being reused, between the purge delay and 4 times it (`MAX_RETENTION`). Once per decay epoch it compares the dirty pages that page-run allocations reused (`SearchStats::dirty_reused_pages`) with the pages purged since the last epoch. The share is smoothed (a quarter weight per epoch), with hysteresis: retention goes up one step above 3/4 reuse and down one step below 1/4, at most one step per purge delay. An epoch with neither reuse nor purges counts as idle and lowers the share.

- A force purge, a purge request or a purge delay of 0 resets retention to the delay.
- `Retention::Fixed` (the default) pins it to the delay.
- The thresholds apply either way, so a longer retention never lets tracked dirty memory pass the trigger unanswered.

The signal is an allocator-level estimate of reuse, not a measurement of page faults. The controller reads no clock beyond the decay schedule, no file and no `/proc`, and does nothing per allocation or free.

## Complexity

- **Slice.** O(limit) work units, plus at most one segment. The limit is 4096 units (16384 for an emergency slice).
- **Sweep.** O(shards + segments in use + small pages + 256 bitmap words) units in total, spread over slices.
- **State.**
  - Sweep position, thresholds and controller: about 25 words in the heap, once.
  - Cost on frees: the page-run free path reads the packed thresholds and the pending flag (two relaxed loads). Small-block frees are unchanged.
  - One more per-shard counter (`dirty_reused_pages`), bumped under the shard lock on page-run allocations.
- **Not bounded.** Explicit `purge()` and `decay()` run their sweep to the end. The thread that runs a slice pays for its system calls; slices bound how many it submits, not how long the kernel takes.
