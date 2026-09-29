# Thread caches: batching frees and returning idle caches

Each thread that allocates has a cache of its own: one claimed bitmap word per size class (small blocks, up to 8 KiB), which allocations pop without atomics, and a buffer of frees not yet returned to the shared bitmaps. This page describes the buffer and how a cache gives back what it holds. None of it was tuned by measurement: **performance not measured; benchmark gate intentionally disabled** (see [research/theory-driven-implementation-status.md](research/theory-driven-implementation-status.md)).

## The free buffer

A small free sets a bit in the buffer. The buffer has 64 slots, in 32 sets of 2 ways; each slot holds the freed blocks of one bitmap word (up to 64). When a slot is written back, one atomic `fetch_or` returns all of its blocks, so the cost of the shared update is spread over the blocks the slot collected.

- A free goes to the set its word hashes to: into the way that already holds the word, else an empty way, else it evicts the older of the two ways (round robin per set). The evicted word goes back in one update (`CacheStats::evictions`).
- A word is in at most one slot. A second free of a block still buffered, in either way, or of a block the thread claimed but has not handed out, aborts with "double free". Frees of the same block from two threads are caught when the second reaches the shared bitmap.
- Before a size class would take a new page, the thread writes back its buffered frees of that class and tries again (`refill_flushes`), so buffering never grows the heap.
- With a direct-mapped buffer, two words hashing to the same slot evicted each other on every alternating free. Two ways keep both words; a third word in the same set is needed to evict.

The buffer holds at most 64 words, 4096 blocks, per thread. Frees from other threads are not queued to the block's owner: the shared bitmap is the transfer, and a thread's buffer holds whatever it freed, whoever allocated it.

## Returning a cache

What a cache holds (the rest of each claimed word, and the buffered frees) is unavailable to other threads until it goes back. It goes back:

- at thread exit, by the thread-local destructor (as before);
- when the thread calls `Allocatbelt::flush_thread_cache()`: everything, at once;
- when the thread calls `Allocatbelt::purge()`, which flushes the caller's cache first;
- cooperatively, after `Allocatbelt::request_cache_return()`.

### `flush_thread_cache`

Returns every block the calling thread's cache holds, with one atomic update per word: at most 64 buffered words and one claimed word per size class. The cache stays attached and usable. It purges nothing, and it does not initialise the allocator, attach a cache that was never used, or allocate. It is not async-signal-safe: do not call it from a signal handler.

### `request_cache_return`

Bumps a process-wide generation and returns at once (one atomic add). Each attached cache compares the generation with the last one it drained for at **sampled points of its own slow paths**:

- a cache refill (a claimed word ran out);
- a page-run or huge allocation, or a free of one;
- a free that needs a new slot of the buffer.

When it sees a new generation it drains itself completely (the same work as `flush_thread_cache`), records the generation and counts it (`CacheStats::pressure_returns`). A thread that only frees reaches a new slot within 4096 small frees: a slot takes at most 64 frees of its word, and there are 64 slots. A cache created after a request owes nothing for it; a cache being attached, or retired at thread exit, is never asked.

Only the owner thread ever touches its cache. So a thread that sleeps, blocks in a system call, or stops calling the allocator does not drain, and nothing can drain it from outside: there is **no time bound** on a cache return without the thread's cooperation. The generation is a `u32` compared for equality, so it wraps harmlessly; a cache that misses exactly 2^32 requests misses one drain.

### Worker integration pattern

A worker thread of a pool, an executor or a request loop should flush before it goes to sleep:

```rust
use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

fn worker(jobs: std::sync::mpsc::Receiver<Box<dyn FnOnce() + Send>>) {
  loop {
    // Drain what is ready, then return this thread's cache before parking.
    while let Ok(job) = jobs.try_recv() {
      job();
    }
    GLOBAL.flush_thread_cache();
    match jobs.recv() {
      Ok(job) => job(),
      Err(_) => return,
    }
  }
}
```

Executors that have a hook for "about to park" or "idle" (for example a thread-pool callback) can call `flush_thread_cache` there; allocatbelt depends on no executor. A memory-pressure handler can call `request_cache_return` together with `request_purge`: running threads return their caches soon after, parked ones as they wake, and parked workers that follow the pattern above hold nothing.

## After `fork`

The child has only the thread that forked. Its cache works as before; the caches of the parent's other threads are gone with them, and the blocks they held stay allocated in the child (a few words per size class and up to 64 buffered words per thread). Nothing in the child waits for them: `request_cache_return` and `flush_thread_cache` return at once, and the child's own cache drains as usual.

## Costs

- **Free fast path.** One more comparison: the word is looked up in both ways of its set. The key encoding, the per-class masks of occupied slots and the flush path are unchanged.
- **State.** Three `Cell`s more per cache (a 32-bit mask of which way each set evicts next, the last generation drained for, and the drain counter). One `AtomicU32` in the heap.
- **Sampled checks.** One relaxed load and a comparison at each sampled point, none on the allocation and free fast paths.
