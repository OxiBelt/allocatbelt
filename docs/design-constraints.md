# Design constraints

Rules that changes to allocatbelt must keep. They come from a freedom-to-operate review of the design, which is kept outside this repository; a change that would break one of them needs that review first, whatever it would gain. The code states each rule where it applies, and the tests named here fail if the behaviour they describe changes.

## Randomized choice of a set bit

Randomized placement (refills, the order a thread hands out blocks, where new segments go) picks among the set bits of a word by **rank**: `bits::pick_bit` ranks the set bits from the lowest and takes the one whose rank the random number selects (`bits::select_bit`). It does not rotate the word or scan from a random starting position. Besides the review, the rank selection gives every free block the same chance, where a scan from a random start favours blocks that follow long runs of taken ones.

Tests: `pick_ranks`, `select_every_rank`, `select_prop`, `pick_prop` (`core/bits/tests.rs`), and the mutation campaign over `bits.rs`.

## Page runs and segments change under a lock

A segment's page words (`SEG_PAGES`, occupancy; `SEG_DIRTY`, freed but not purged) change only under the lock of the shard that owns the segment, and the arena's segment words (`seg_used`) only under `seg_lock`. Every change is a plain load and store under that lock, never a compare-and-swap or another read-modify-write instruction on those words; other threads read them only as hints. Page-run allocation, in-place growth, page-run frees, the claims and ends of a purge, and trimming all take the owner's lock (`core/proto.rs`, "Page runs"). A purge holds it only to claim pages and to give them back, not while the `madvise` is in flight.

Small blocks are different and stay lock-free on the free side: frees set bitmap bits with `fetch_or` from any thread, and the owner claims a whole bitmap word at a time under its shard lock. A refill takes every free block of the word it claims, whatever the request, and the thread then hands blocks out one by one from its own cache without atomics.

Tests: the loom models `page_runs_race_purge`, `async_purge_with_failure` and `grow_races_trim` (`core/proto.rs`) run every page-run transition under the owner's lock; the model tests exercise every caller.

## No allocation in one atomic step

No allocation path completes in a single atomic read-modify-write that both checks the allocation state and yields the address, such as a `fetch_add` bump of a shared offset word. Regions (`Region`) bump through `Cell`s on one thread and never share their cursor; they stay that way.

## Free pages are chosen by position

A page run is taken first fit by position in the shard's segments (`proto::claim_run`, `find_run_aligned`), then from a new segment. The choice does not rank free pages by their history: pages that were used and freed (dirty), purged pages and never-used pages are taken where they lie. The heap keeps no per-page record of whether a page was ever used, and must not start choosing by it.

Test: `free_page_choice_ignores_page_history` (`core/tests.rs`).

## Frees are not sorted by owner

A free is not classified by which thread allocated the block. A thread's free buffer collects frees per bitmap word, whoever allocated them, and returns them to the page's shared bitmap when a set of the buffer is full, on a flush or on a cache-return request, never to a particular thread and not on a count of "foreign" frees. There are no per-thread lists of remote frees handed back to their allocating thread.

## Shards are a first choice, not a rotation

An attaching thread cache gets a shard as a first choice for its refills, from a counter advanced with a plain load and store (two threads attaching at once may share one); `experimental-rseq` can use `mm_cid` instead. Allocations and frees do not rotate among shards through an atomic counter, and an empty shard takes a new segment rather than guaranteeing to find free blocks in other shards.
