//! x86-64-v4 kernels: AVX-512 F, BW, CD, DQ and VL over x86-64-v3 (AVX2,
//! BMI1, BMI2, LZCNT, POPCNT). Self-contained: no `crate::` paths, so the
//! benchmark crate can include this file too.
//!
//! The kernels stay at 256 bits (EVEX forms on ymm16 to ymm20, opmasks k1
//! and k2). No instruction touches a zmm register, so a build at this level
//! takes no 512-bit frequency licence on the Intel cores that have one, and
//! the registers above 15 are outside the SSE/AVX transition state, so the
//! callers need no `vzeroupper` (which does not modify zmm16 to zmm31).
//! Measured on Zen 5, the 512-bit forms save two instructions and under
//! half a cycle in `list_holds`, about four cycles of a refill in
//! `unpack_blocks` (`vpcompressd` on four 16-entry chunks), one or two
//! cycles of a claim from a page of 16 to 64 bitmap words in
//! `nonzero_words` (none below) and about five cycles of a 64-entry
//! `pack_blocks` (one and a half of a 32-entry one).

use core::arch::asm;
use core::cell::Cell;

#[cfg(not(all(
  target_feature = "avx512f",
  target_feature = "avx512bw",
  target_feature = "avx512dq",
  target_feature = "avx512vl",
  target_feature = "bmi2",
  target_feature = "lzcnt",
  target_feature = "popcnt"
)))]
compile_error!("the x86-64-v4 kernels need AVX-512 F, BW, DQ and VL, BMI2, LZCNT and POPCNT");

/// Reported by the tests and the benchmark.
#[allow(
  dead_code,
  reason = "read by the allocator's tests and by the benchmark that includes this file"
)]
pub(crate) const NAME: &str = "x86_64_v4 (256-bit EVEX: vpcmpeqb+kunpckdq+bzhi; vpmovm2b+pext, lzcnt loop \
   when sparse; vpcmpneqq+kmovb, cmp+adc below 8 words; vpmovzxbq+vprolvq)";

/// Whether block number `i` is among the first `len` entries of `blocks`.
///
/// Six instructions: `i` broadcast to 32 bytes, one compare per half of
/// the list into an opmask, the two masks joined (`kunpckdq`: k1 keeps
/// entries 0 to 31, entries 32 to 63 come from k2) and moved to a general
/// register, and `bzhi` to drop the entries at or past `len`. `bzhi` reads
/// its index from bits 7:0 of the register and leaves the source whole
/// when the index is 64 or more, so `len == 64` keeps every entry and the
/// upper bits of the register do not matter. The caller tests the result.
#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  let hits: u64;
  // SAFETY: `blocks` borrows 64 initialized bytes (`Cell<u8>` has the
  // layout of `u8`), and the two unaligned 32-byte loads read exactly
  // bytes 0..32 and 32..64 through its pointer. Nothing is written and the
  // stack is not used. The block clobbers `hits`, ymm16, k1, k2 and the
  // flags, all declared (flags by default). Every build that compiles
  // this file has the instructions (checked above).
  unsafe {
    asm!(
      "vpbroadcastb ymm16, {i:e}",
      "vpcmpeqb k1, ymm16, ymmword ptr [{p}]",
      "vpcmpeqb k2, ymm16, ymmword ptr [{p} + 32]",
      "kunpckdq k1, k2, k1",
      "kmovq {hits}, k1",
      "bzhi {hits}, {hits}, {len:r}",
      p = in(reg) blocks.as_ptr(),
      i = in(reg) u32::from(i),
      len = in(reg) u32::from(len),
      hits = out(reg) hits,
      out("ymm16") _,
      out("k1") _,
      out("k2") _,
      options(pure, readonly, nostack),
    );
  }
  hits != 0
}

/// `vpshufb` control that reverses the 16 bytes of each 128-bit lane.
#[repr(C, align(16))]
struct Reverse([u8; 16]);

static REVERSE: Reverse = Reverse([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// Writes the numbers of the set bits of `bits` to `blocks`, highest
/// first, and returns their count.
///
/// Words with more than six set bits take the vector path, which costs
/// the same whatever the word. `kmovq` and `vpmovm2b` turn the word into
/// 64 bytes of all ones or zeros, one per bit, and `vpshufb` reverses each
/// 16 of them, so that every quadword stands for one byte of the word with
/// its highest bit in the lowest byte. For each byte of the word, from the
/// highest, `pext` packs the bytes of a constant of block numbers that the
/// quadword selects, and an eight-byte store puts them after the entries
/// of the higher bytes (`popcnt` of the bits above gives the offset); its
/// unused upper bytes are zero and the next store overwrites them.
///
/// Sparse words take a scalar loop instead (`lzcnt`, a byte store, `bzhi`
/// to clear the bit): it is cheaper up to about six blocks. So do words
/// of up to 24 blocks whose list straddles a page boundary, because each
/// eight-byte store across the boundary costs about 20 cycles (Zen 5).
///
/// Only registers hold values derived from `bits`; the stack is not used.
#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let n: u64;
  // SAFETY: `blocks` borrows 64 bytes that may be written through a shared
  // reference (`Cell<u8>` has the layout of `u8`), and every store is
  // inside them. The scalar loop stores one byte at each offset below the
  // number of set bits, 64 at most. The vector path stores eight bytes at
  // the offset of each byte of the word, which is the number of set bits
  // above that byte: at most 8 * (7 - c) for byte c, so a store ends at
  // offset 64 at most. The only load is of the 16 bytes of `REVERSE`. The
  // stack is not used. The block clobbers `b` (the count on exit), `idx`,
  // `step`, `m`, `t`, ymm16 to ymm18, k1, k2 and the flags, all declared
  // (flags by default). Every build that compiles this file has the
  // instructions (checked above).
  unsafe {
    asm!(
      "mov {idx}, {b}",
      "popcnt {idx}, {idx}",
      "cmp {idx:e}, 6",
      "jbe 4f",
      // Nonzero above bit 11: the first and last entry are on two pages.
      "lea {t}, [{p} + 63]",
      "xor {t}, {p}",
      "test {t}, -4096",
      "jnz 7f",
      "2:",
      // Byte j of ymm16 is all ones if bit j is set, of ymm17 if bit
      // 32 + j is; reversed within each lane, quadword 2 of ymm17 holds
      // bits 63..56 from its lowest byte up, then quadwords 3, 0 and 1
      // hold bits 55..48, 47..40 and 39..32, and ymm16 the same of the
      // low half.
      "kmovq k1, {b}",
      "kshiftrq k2, k1, 32",
      "vpmovm2b ymm16, k1",
      "vpmovm2b ymm17, k2",
      "vbroadcasti32x4 ymm18, xmmword ptr [rip + {reverse}]",
      "vpshufb ymm16, ymm16, ymm18",
      "vpshufb ymm17, ymm17, ymm18",
      // Block numbers 63..56 from the lowest byte up, and 8 in each byte.
      "movabs {idx}, 0x38393a3b3c3d3e3f",
      "movabs {step}, 0x0808080808080808",
      // Bits 63..56.
      "vextracti32x4 xmm18, ymm17, 1",
      "vmovq {m}, xmm18",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p}], {m}",
      // Bits 55..48.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 56",
      "popcnt {t}, {t}",
      "vpextrq {m}, xmm18, 1",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 47..40.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 48",
      "popcnt {t}, {t}",
      "vmovq {m}, xmm17",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 39..32.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 40",
      "popcnt {t}, {t}",
      "vpextrq {m}, xmm17, 1",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 31..24.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 32",
      "popcnt {t}, {t}",
      "vextracti32x4 xmm18, ymm16, 1",
      "vmovq {m}, xmm18",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 23..16.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 24",
      "popcnt {t}, {t}",
      "vpextrq {m}, xmm18, 1",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 15..8.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 16",
      "popcnt {t}, {t}",
      "vmovq {m}, xmm16",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      // Bits 7..0.
      "sub {idx}, {step}",
      "mov {t}, {b}",
      "shr {t}, 8",
      "popcnt {t}, {t}",
      "vpextrq {m}, xmm16, 1",
      "pext {m}, {idx}, {m}",
      "mov qword ptr [{p} + {t}], {m}",
      "popcnt {b}, {b}",
      "jmp 3f",
      // A list on two pages: byte stores unless the word is dense.
      "7:",
      "cmp {idx:e}, 24",
      "ja 2b",
      // `lzcnt` is at most 63 here, so `t` is the highest set bit; `bzhi`
      // clears the bits from `t` up, which is that bit alone, and sets ZF
      // once none is left.
      "4:",
      "xor {m:e}, {m:e}",
      "test {b}, {b}",
      "jz 6f",
      "5:",
      "lzcnt {t}, {b}",
      "xor {t:e}, 63",
      "mov byte ptr [{p} + {m}], {t:l}",
      "inc {m:e}",
      "bzhi {b}, {b}, {t}",
      "jnz 5b",
      "6:",
      "mov {b}, {m}",
      "3:",
      b = inout(reg) bits => n,
      p = in(reg) blocks.as_ptr(),
      idx = out(reg) _,
      step = out(reg) _,
      m = out(reg) _,
      t = out(reg) _,
      reverse = sym REVERSE,
      out("ymm16") _,
      out("ymm17") _,
      out("ymm18") _,
      out("k1") _,
      out("k2") _,
      options(nostack),
    );
  }
  n as u8
}

/// Which of `words` (at most 64) are non-zero: bit `i` is set iff
/// `words[i]` is. The caller holds the lock under which the words change,
/// so they are read with plain loads.
///
/// Eight words or more are compared four at a time with a zero register
/// (`vpcmpneqq` into an opmask, which has one bit per 64-bit word and
/// zeros above the four of a ymm compare); `kmovb` moves the four bits to a
/// general register and `shlx` shifts them to the index of the vector's
/// first word. The two vectors that end at the end of the slice go first,
/// then pairs of vectors from the start, as long as a pair starts more
/// than eight words before the end. When the length is not a multiple of
/// eight the last pair overlaps the two end vectors, which sets the same
/// bits twice. No load is masked: every vector lies inside the slice. (A
/// masked load is not needed for the tail, and one whose masked-off words
/// lie on a page that is not present takes about 550 cycles on Zen 5 every
/// time, since the suppressed fault never brings the page in.) A page's
/// bitmap starts 32 bytes into a cache line or at the start of one (its
/// segment's header is 320 bytes and a page's metadata 544, of which 32
/// come first), so the pairs from the start never straddle a line there;
/// 64-byte loads would on every other page.
///
/// Fewer than eight words take a scalar loop from the last word down:
/// `cmp` of a zero register with the word borrows exactly when the word is
/// non-zero, and `adc` shifts the carry into the mask. From the address to
/// the mask this is about six cycles and one more per word on Zen 5,
/// where a load, a compare into an opmask and `kmovb` take thirteen. In
/// the benchmark's claim loop the scalar loop is four cycles ahead of a
/// masked vector at two words and level with it at four, and one or two
/// behind the vectors at eight.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[core::sync::atomic::AtomicU64]) -> u64 {
  let mask: u64;
  // SAFETY: `words` borrows `n = words.len()` initialized 64-bit words
  // (`AtomicU64` has the layout of `u64`), and every load is inside them,
  // whatever `n` is (past 64 words only the mask is meaningless). With
  // `n >= 8`, the two 32-byte loads at `8 * n - 64` and `8 * n - 32` bytes
  // read words `n - 8..n`, and the loop runs while `i < n - 8`, so its
  // loads at words `i` and `i + 4` read words `i..i + 8`, which end before
  // `n`. With `n < 8`, the scalar loop reads the 8 bytes of each of words
  // `n - 1` down to 0, and none when `n` is 0. Nothing is written (the
  // loads race with no store: the caller holds the lock under which these
  // words change) and the stack is not used. The block clobbers `n`,
  // `mask`, `i`, `j`, `t`, `u`, ymm16, k1, k2 and the flags, all declared
  // (flags by default). Every build that compiles this file has the
  // instructions (checked above).
  unsafe {
    asm!(
      "xor {r:e}, {r:e}",
      "cmp {n}, 8",
      "jb 5f",
      "vpxord xmm16, xmm16, xmm16",
      // Words n - 8..n: bits n - 8..n - 4 from k1 and n - 4..n from k2.
      "vpcmpneqq k1, ymm16, ymmword ptr [{p} + 8*{n} - 64]",
      "vpcmpneqq k2, ymm16, ymmword ptr [{p} + 8*{n} - 32]",
      "lea {j}, [{n} - 4]",
      "sub {n}, 8",
      "kmovb {t:e}, k1",
      "kmovb {u:e}, k2",
      "shlx {r}, {t}, {n}",
      "shlx {u}, {u}, {j}",
      "or {r}, {u}",
      "test {n}, {n}",
      "jz 7f",
      // Words i..i + 8 while i < n - 8 (`n` holds n - 8, `j` is i + 4).
      "xor {i:e}, {i:e}",
      "mov {j:e}, 4",
      "2:",
      "vpcmpneqq k1, ymm16, ymmword ptr [{p} + 8*{i}]",
      "vpcmpneqq k2, ymm16, ymmword ptr [{p} + 8*{j}]",
      "kmovb {t:e}, k1",
      "kmovb {u:e}, k2",
      "shlx {t}, {t}, {i}",
      "shlx {u}, {u}, {j}",
      "or {t}, {u}",
      "or {r}, {t}",
      "add {i:e}, 8",
      "add {j:e}, 8",
      "cmp {i}, {n}",
      "jb 2b",
      "jmp 7f",
      // Fewer than eight words, from the last down: 0 - word borrows iff
      // the word is non-zero, and `adc` shifts the carry in from below.
      "5:",
      "test {n}, {n}",
      "jz 7f",
      "xor {i:e}, {i:e}",
      "6:",
      "cmp {i}, qword ptr [{p} + 8*{n} - 8]",
      "adc {r:e}, {r:e}",
      "sub {n:e}, 1",
      "jnz 6b",
      "7:",
      p = in(reg) words.as_ptr(),
      n = inout(reg) words.len() => _,
      r = out(reg) mask,
      i = out(reg) _,
      j = out(reg) _,
      t = out(reg) _,
      u = out(reg) _,
      out("ymm16") _,
      out("k1") _,
      out("k2") _,
      options(pure, readonly, nostack),
    );
  }
  mask
}

/// The mask of the block numbers (each below 64) in the first `len` (at
/// most 64) entries of `blocks`.
///
/// Four entries at a time: `vpmovzxbq` widens four bytes to the four
/// 64-bit lanes of a ymm register and `vprolvq` rotates a one in each lane
/// left by its entry (the count is taken modulo 64), which is the entry's
/// bit. The one is the absolute value of minus one (`vpabsq`), which
/// needs no shift. One group runs up from the first entry and one down
/// from the last four, each into its own accumulator, until the two meet;
/// when they overlap, or `len` is four and they are the same group, the
/// same bits are set twice. No group reaches past `len`, so the stale
/// entries are never loaded and nothing is masked. The four lanes are then
/// folded into one. Fewer than four entries take a scalar loop (`shlx` of
/// a one, whose count is also taken modulo 64).
///
/// This is the shape the compiler gives the portable loop, which it also
/// vectorizes four entries at a time: on Zen 5 the widening and the
/// variable shift or rotate share two execution ports, which bounds both
/// forms at two entries per cycle. The kernel is two cycles ahead at 64
/// entries (15.6 against 17.5), level at 32 and not measurably different
/// below, except at exactly four entries, where its two groups are the
/// same one and it is a cycle behind. Its branches that depend on `len`
/// are fewer: the length tests, one per eight entries, and the scalar
/// loop's.
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  // The portable loop's slice of the first `len` entries panics here too.
  assert!(len <= 64, "more entries than a list holds");
  let bits: u64;
  // SAFETY: `blocks` borrows 64 initialized bytes (`Cell<u8>` has the
  // layout of `u8`), and every load is inside its first `len` (at most 64,
  // checked above). With `len >= 4`, the first two loads are of the 4
  // bytes at 0 and the 4 at `len - 4`. From `i = 0` and `j = len - 4`, a
  // further pass loads the 4 bytes at `i + 4` and the 4 at `j - 4`, and it
  // runs only when `i + 4` is below `j`: then `i + 4` is at most `len - 5`
  // and `j - 4` at least 1, so both groups of four are inside the entries
  // again. With `len < 4`, the scalar loop loads the bytes `len - 1` down
  // to 0, and none when `len` is 0. Nothing is written and the stack is
  // not used. The block clobbers `len`, `bits`, `i`, `t`, ymm16 to ymm20
  // and the flags, all declared (flags by default). Every build that
  // compiles this file has the instructions (checked above).
  unsafe {
    asm!(
      "xor {r:e}, {r:e}",
      "cmp {len:e}, 4",
      "jb 5f",
      // A one in each 64-bit lane: the absolute value of minus one.
      "vpternlogd ymm18, ymm18, ymm18, 0xff",
      "vpabsq ymm18, ymm18",
      // Entries 0..4 and len - 4..len start the two accumulators.
      "vpmovzxbq ymm16, dword ptr [{p}]",
      "vpmovzxbq ymm17, dword ptr [{p} + {len} - 4]",
      "vprolvq ymm16, ymm18, ymm16",
      "vprolvq ymm17, ymm18, ymm17",
      // Entries i..i + 4 and j..j + 4 while i is below the j before (`len`
      // holds j); `lea` keeps the flags of that compare.
      "mov {i:e}, 4",
      "sub {len:e}, 4",
      "cmp {i:e}, {len:e}",
      "lea {len:e}, [{len} - 4]",
      "jae 3f",
      "2:",
      "vpmovzxbq ymm19, dword ptr [{p} + {i}]",
      "vpmovzxbq ymm20, dword ptr [{p} + {len}]",
      "vprolvq ymm19, ymm18, ymm19",
      "vprolvq ymm20, ymm18, ymm20",
      "vporq ymm16, ymm16, ymm19",
      "vporq ymm17, ymm17, ymm20",
      "add {i:e}, 4",
      "cmp {i:e}, {len:e}",
      "lea {len:e}, [{len} - 4]",
      "jb 2b",
      "3:",
      "vporq ymm16, ymm16, ymm17",
      "vextracti64x2 xmm17, ymm16, 1",
      "vporq xmm16, xmm16, xmm17",
      "vpshufd xmm17, xmm16, 0xee",
      "vporq xmm16, xmm16, xmm17",
      "vmovq {r}, xmm16",
      "jmp 7f",
      // Fewer than four entries, from the last down.
      "5:",
      "test {len:e}, {len:e}",
      "jz 7f",
      "mov {i:e}, 1",
      "6:",
      "movzx {t:e}, byte ptr [{p} + {len} - 1]",
      "shlx {t}, {i}, {t}",
      "or {r}, {t}",
      "sub {len:e}, 1",
      "jnz 6b",
      "7:",
      p = in(reg) blocks.as_ptr(),
      len = inout(reg) u64::from(len) => _,
      r = out(reg) bits,
      i = out(reg) _,
      t = out(reg) _,
      out("ymm16") _,
      out("ymm17") _,
      out("ymm18") _,
      out("ymm19") _,
      out("ymm20") _,
      options(pure, readonly, nostack),
    );
  }
  bits
}
