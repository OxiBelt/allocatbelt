# Design constraints

Rules that changes to allocatbelt must keep. They come from a preliminary patent screen and technical design review, kept outside this repository; they do not establish freedom to operate or legal non-infringement. A change that would break one of them needs that review repeated first, whatever it would gain. The code states each rule where it applies, and the tests named here fail if the behaviour they describe changes.

## Randomized choice of a set bit

Randomized placement among the set bits of a word (where new segments go) picks by **rank**: `bits::pick_bit` ranks the set bits from the lowest and takes the one whose rank the random number selects (`bits::select_bit`). It does not rotate the word or scan from a random starting position. A refill picks the bitmap word it claims the same way, by rank among the page's non-zero words (`proto::pick_word`, for `claim_word` and `claim_block`), and a thread cache picks the next block uniformly from its list (see below), which has no bits to rotate. Besides the review, the rank selection gives every free block the same chance, where a scan from a random start favours blocks that follow long runs of taken ones.

Tests: `pick_ranks`, `select_every_rank`, `select_prop`, `pick_prop` (`core/bits/tests.rs`), and the mutation campaign over `bits.rs`.

## Allocation state changes under a lock

A small page's bitmap words and free counter, a segment's words (`SEG_PAGES`, occupancy; `SEG_DIRTY`, freed but not purged; `SEG_EMPTY`, empty-page candidates; `SEG_CLS`, the pages of each class), the shard's segment list, its search bounds and the newest page of each class change only under the lock of the shard that owns the segment, and the arena's segment words (`seg_used`) only under `seg_lock`. Every change is a plain load and store under that lock, never a compare-and-swap, `swap`, `fetch_or` or another read-modify-write instruction on those words; other threads read them only as hints. Small-block claims and frees (a thread cache writing back a buffered word included), page-run allocation, in-place growth, page-run frees, the claims and ends of a purge, and trimming all take the owner's lock (`core/proto.rs`, "Block bitmaps" and "Page runs"). A purge holds it only to claim pages and to give them back, not while the `madvise` is in flight, except for the one-page purge of a kept newest page (below), which has no claim to protect it. A free checks and clears a page run's header under the owner's lock, and a huge block's segment header under `seg_lock`, with a load and a store.

A refill takes every free block of the word it claims, whatever the request, and the thread then hands blocks out one by one from its own cache without atomics; an uncached small allocation claims a single block under the lock.

Tests: the loom models `frees_race_claims`, `two_freers_one_word`, `last_free_publishes_a_candidate`, `a_claim_racing_the_last_free_loses_no_candidate`, `racing_double_free_is_caught`, `page_runs_race_purge`, `async_purge_with_failure` and `grow_races_trim` (`core/proto.rs`) run the transitions under the owner's lock; `Heap::check_indexes` checks that every small page's counter matches its bitmap; the model tests exercise every caller.

## No allocation in one atomic step

No allocation path completes in a single atomic read-modify-write that both checks the allocation state and yields the address, such as a `fetch_add` bump of a shared offset word, and no allocation or free changes allocation state with an atomic read-modify-write at all (see above). The read-modify-write instructions left in the heap are the locks' own, the dirty-page count, statistics, the maintenance request word and the cache-return generation. Regions (`Region`) bump through `Cell`s on one thread and never share their cursor; they stay that way.

## Pages are chosen by address

A shard lists its segments in address order. A page run is taken first fit by address in them (`proto::claim_run`, `find_run_aligned`), then from a new segment. A refill of a size class takes the lowest page by address, among the shard's pages of the class with free blocks and its free pages, and a free page it takes becomes a page of the class (`Heap::find_page`); with neither, it takes the first page of a new segment. Candidates are not ranked by their state: a partly used page is not preferred to a free page or the other way round, and free pages are not ranked by their history (used and freed, purged, never used). The heap keeps no per-page record of whether a page was ever used, keeps no list, queue or bit vector that groups pages by state (partly used, full, empty, dirty, clean), and must not start choosing by any of these. A refill that must not grow the heap (the thread still buffers frees of the class) stops when the lowest candidate is a free page, writes back those frees and searches again.

Tests: `free_page_choice_ignores_page_history` and `the_lowest_page_is_taken_whether_free_or_partly_used` (`core/tests.rs`).

## Frees are not sorted by owner

A free is not classified by which thread allocated the block. A thread's free buffer collects frees per bitmap word, whoever allocated them, and returns them to the page's shared bitmap when a set of the buffer is full, on a flush or on a cache-return request, never to a particular thread and not on a count of "foreign" frees. There are no per-thread lists of remote frees handed back to their allocating thread.

## Shards are a first choice, not a rotation

An attaching thread cache gets a shard as a first choice for its refills, from a counter advanced with a plain load and store (two threads attaching at once may share one); `experimental-rseq` can use `mm_cid` instead. Allocations and frees do not rotate among shards through an atomic counter, and an empty shard takes a new segment rather than guaranteeing to find free blocks in other shards.

## Thread caches keep block lists, not bitmap words

A refill claims one bitmap word, found by reading the page's bitmap words, and unpacks its bits into a list of block numbers in the thread's cache; the cache hands blocks out from the list (a uniformly chosen entry when randomized) and never stores the claimed word's bits. Returning the cache packs the list back into a mask for the shared bitmap.

Test: `a_seeded_cache_hands_out_each_claimed_block_once` (`core/tests.rs`).

## No summary bits over the bitmaps

Small blocks are found without summary bits. A refill searches the shard's segments in address order, reads the free counter of each page of the class it passes, and reads the bitmap words of the page it stops at to pick one to claim. No bit vector records which bitmap words of a page, which pages of a segment or which segments of a shard have free blocks, and none is to be added. The segment's word of its pages of each class (`SEG_CLS`) marks what the pages are, never whether they have free blocks. The search starts from two lower bounds per shard, one per class and one for free pages: page numbers below which nothing qualifies, which searches raise and frees lower, not records of which pages have free blocks.

Test: `Heap::check_indexes`, which the model tests and the fuzz programs run after their operations.

## The newest page of a class stays

Trimming returns a small page whose blocks are all free to its segment, except the page its shard set up last for that class (`newest` in the shard's class state, set by `Heap::new_small_page`). That page stays a page of its class, whether or not its blocks are all free, until the shard sets up a newer page of the class; it then becomes an empty-page candidate again if its blocks are all free, and a later sweep releases it. Only trimming returns small pages, and no sweep, force and emergency sweeps included, releases a class's newest page; no path that does is to be added. The kept page is purged instead: once it has been kept fully free for the purge delay (at once in force and budget sweeps), trimming returns its memory to the OS with `Os::purge`, under the shard's lock, and it stays a page of its class. That is not a release to the segment: its blocks stay free blocks of the class, and the next claim from it clears its age.

The cost is at most one 64 KiB page per shard and size class, 64 × 32 pages at the very most, and in practice one page per class each active shard has used. Kept pages are resident until their purge. Each also keeps its segment owned, so a shard that has used many classes can hold several mostly purged segments where it held one empty segment before: address space and segment metadata, not resident memory. `MaintenanceStats::kept_newest_pages` counts the fully free pages trimming checked and kept, and `purged_pages` includes those it purged.

Tests: `trimming_keeps_the_newest_page_of_a_class` and `a_kept_page_is_purged_once_it_has_been_kept_for_the_delay` (`core/tests.rs`); `Heap::check_indexes`, which checks that each class's newest page is a page of the class; and the end of every model program, where only the newest pages stay.

## Addresses carry positions only

An address locates its segment, page and block; nothing else is encoded in it (no size class, CPU or thread number, signature or random offset). Size classes and the rest live in the page metadata. The guard page of a segment stays at a fixed position.

## One heap for all types

Size classes are chosen by size and alignment only. There are no heaps, allocators or regions specific to a data type, and a region frees only as a whole.

## Cache capacity is not a randomization setting

The number of blocks a thread cache holds follows from the bitmap word it claimed, not from a configurable randomization entropy; free buffers are shared by all size classes.
