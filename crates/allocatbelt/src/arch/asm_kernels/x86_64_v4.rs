//! x86-64-v4 kernels: AVX-512 F, BW, CD, DQ and VL over x86-64-v3 (AVX2,
//! BMI1, BMI2, LZCNT, POPCNT). Self-contained: no `crate::` paths, so the
//! benchmark crate can include this file too.
//!
//! Both kernels stay at 256 bits (EVEX forms on ymm16 to ymm18, opmasks k1
//! and k2). No instruction touches a zmm register, so a build at this level
//! takes no 512-bit frequency licence on the Intel cores that have one, and
//! the registers above 15 are outside the SSE/AVX transition state, so the
//! callers need no `vzeroupper` (which does not modify zmm16 to zmm31).
//! Measured on Zen 5, the 512-bit forms save two instructions and under
//! half a cycle in `list_holds`, and about four cycles of a refill in
//! `unpack_blocks` (`vpcompressd` on four 16-entry chunks).

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
pub(crate) const NAME: &str =
  "x86_64_v4 (256-bit EVEX: vpcmpeqb+kunpckdq+bzhi; vpmovm2b+pext, lzcnt loop when sparse)";

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

/// PLACEHOLDER (portable loop), to be replaced by assembly: bit `i` is set
/// iff `words[i]` is non-zero. `words.len()` is at most 64.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[core::sync::atomic::AtomicU64]) -> u64 {
  let mut mask = 0;
  for (i, w) in words.iter().enumerate() {
    mask |= u64::from(w.load(core::sync::atomic::Ordering::Relaxed) != 0) << i;
  }
  mask
}

/// PLACEHOLDER (portable loop), to be replaced by assembly: the mask of the
/// block numbers (each below 64) in the first `len` (at most 64) entries.
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  blocks[..usize::from(len)]
    .iter()
    .fold(0, |m, b| m | 1 << b.get())
}
