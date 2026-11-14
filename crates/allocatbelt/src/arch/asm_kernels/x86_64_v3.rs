//! Block-list kernels for x86-64-v3 (AVX2, BMI1, BMI2, LZCNT, POPCNT).
//! Self-contained: no `crate::` paths, so the benchmark crate can include
//! this file too.
//!
//! Neither kernel uses PDEP or PEXT: they are microcoded and slow on AMD
//! Zen 1 and Zen 2, which are x86-64-v3 processors, and nothing here is
//! selected at run time. A PDEP/PEXT form of `unpack_blocks` was also the
//! slower one on a processor where they are fast (Zen 5: 21 cycles a word
//! against 13).
//!
//! Both kernels use ymm registers and run VZEROUPPER after them, which
//! zeroes bits 128 and up of ymm0 to ymm15, so both declare all sixteen
//! clobbered. The compiler does not see the 256-bit use inside an `asm!`
//! block and inserts no VZEROUPPER for it; without one, the caller would
//! return with the upper halves in use.

use core::arch::asm;
use core::cell::Cell;

// The instructions below are assembled whatever the target features are;
// this makes a build that could not run them fail instead.
const _: () = assert!(
  cfg!(all(
    target_feature = "avx2",
    target_feature = "bmi1",
    target_feature = "bmi2",
    target_feature = "lzcnt",
    target_feature = "popcnt"
  )),
  "the x86-64-v3 kernels need AVX2, BMI1, BMI2, LZCNT and POPCNT"
);

/// Reported by the tests and the benchmark.
#[allow(
  dead_code,
  reason = "read by the allocator's tests and by the benchmark that includes this file"
)]
pub(crate) const NAME: &str = "x86_64_v3 (list_holds: 2x ymm vpcmpeqb + vpmovmskb + bzhi; \
   unpack_blocks: lzcnt/bzhi up to 4 blocks, else vpshufb nibble tables + vpsllvq)";

/// Whether block number `i` is among the first `len` entries of `blocks`.
///
/// Compares all 64 entries with `i` in two 32-byte halves, gathers the 64
/// results into one mask (VPMOVMSKB), and keeps the low `len` bits of it
/// with BZHI, whose index is bits 7:0 of its last operand and which clears
/// nothing when that is 64 or more: a full list keeps every bit. No table,
/// no branch, 10 instructions.
#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  let hits: u64;
  // SAFETY: `blocks` is a shared borrow of 64 `Cell<u8>`, which have the
  // layout of `u8`: the two compares read bytes 0..32 and 32..64 of it
  // through its pointer (VEX memory operands need no alignment), and the
  // block writes no memory and uses no stack. It changes the flags, the two
  // general registers it is given and ymm0 and ymm1; VZEROUPPER also zeroes
  // the upper halves of ymm0 to ymm15, so every xmm register is declared
  // clobbered. AVX2 and BMI2 are present (asserted above).
  unsafe {
    asm!(
      "vmovd xmm0, {i:e}",
      "vpbroadcastb ymm0, xmm0",
      "vpcmpeqb ymm1, ymm0, ymmword ptr [{p}]",
      "vpcmpeqb ymm0, ymm0, ymmword ptr [{p} + 32]",
      // VPMOVMSKB to a 32-bit register zeroes bits 63:32 of the full one.
      "vpmovmskb {lo:e}, ymm1",
      "vpmovmskb {hi:e}, ymm0",
      "vzeroupper",
      "shl {hi}, 32",
      "or {lo}, {hi}",
      "bzhi {lo}, {lo}, {len}",
      p = in(reg) blocks.as_ptr(),
      i = in(reg) u32::from(i),
      len = in(reg) u64::from(len),
      lo = out(reg) hits,
      hi = out(reg) _,
      out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
      out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
      out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
      out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
      options(pure, readonly, nostack),
    );
  }
  hits != 0
}

/// Tables of [`unpack_blocks`], indexed by a nibble of the word (VPSHUFB)
/// or by the nibble's place in it: 96 bytes in two cache lines, read once
/// per refill of more than four blocks. Measured against the forms without
/// a table (a TZCNT/BLSR loop, PDEP/PEXT per byte): faster than both with
/// the tables in L1, and level with the faster of them with the tables
/// out of L1 (in L2).
#[repr(C, align(64))]
struct NibbleTables {
  /// Keeps the low four bits of each byte.
  low: [u8; 16],
  /// Number of the lowest bit of each nibble, in the order the kernel lays
  /// the nibbles out: the high nibbles of bytes 0 to 7, then the low ones.
  base: [u8; 16],
  /// `set[k][v]`: place in nibble `v` of its `k`-th highest set bit; 0 when
  /// it has no such bit.
  set: [[u8; 16]; 3],
  /// `shift[v]`: bits the blocks of a nibble `v` occupy in the list, eight
  /// per set bit.
  shift: [u8; 16],
}

/// Place in `nibble` of its `k`-th highest set bit, 0 when there is none.
const fn kth_highest(nibble: usize, k: usize) -> u8 {
  let mut seen = 0;
  let mut bit = 4;
  while bit > 0 {
    bit -= 1;
    if nibble >> bit & 1 == 1 {
      if seen == k {
        return bit;
      }
      seen += 1;
    }
  }
  0
}

static NIBBLES: NibbleTables = {
  let mut t = NibbleTables {
    low: [0x0f; 16],
    base: [0; 16],
    set: [[0; 16]; 3],
    shift: [0; 16],
  };
  let mut byte = 0;
  while byte < 8 {
    t.base[byte] = 8 * byte as u8 + 4;
    t.base[8 + byte] = 8 * byte as u8;
    byte += 1;
  }
  let mut v = 0;
  while v < 16 {
    t.set[0][v] = kth_highest(v, 0);
    t.set[1][v] = kth_highest(v, 1);
    t.set[2][v] = kth_highest(v, 2);
    t.shift[v] = 8 * v.count_ones() as u8;
    v += 1;
  }
  t
};

/// Writes the numbers of the set bits of `bits` to `blocks`, highest first,
/// and returns their count.
///
/// **Up to four blocks**: four steps of LZCNT (the highest set bit), a
/// store, and BZHI at that bit (which clears it, the bits above being
/// clear already). The steps past the count find no bit: LZCNT of zero is
/// 64, the entry written is 127, and BZHI with an index of 64 or more
/// clears nothing of the zero. Entries 0 to 3 are written whatever the
/// count is, so the path has no loop and no branch on the count.
///
/// **More**: a fixed sequence for any word, 71 instructions and no branch.
/// The sixteen nibbles of the word index three tables (VPSHUFB) that give
/// the places of a nibble's highest, second and third set bits; with the
/// nibble's lowest bit as the fourth, and that bit's number added to each,
/// a nibble has its block numbers as the low bytes of a dword, highest
/// first. A byte of the word then has its blocks as a qword: those of its
/// low nibble shifted left (VPSLLVQ) past those of its high nibble, eight
/// bits per block. The eight qwords are stored highest byte first, each
/// where the blocks of the bytes above it end (POPCNT of the bits above).
/// A store's bytes past its blocks are overwritten by the next store; those
/// of the last one lie past the count and are zero.
#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let n: u64;
  // SAFETY: `blocks` is a shared borrow of 64 `Cell<u8>`, which have the
  // layout of `u8` and may be written through it. The short path writes
  // bytes 0..4. The other makes eight 8-byte stores, the one for byte `j`
  // of the word at the number of set bits above that byte, at most
  // `8 * (7 - j)`, so each ends at or before byte 64. Nothing else is
  // written and no memory but the 96 bytes of `NIBBLES` is read (aligned
  // to 64, so VMOVDQA may load from it); the stack is not used. The block
  // changes the flags, the three general registers it is given besides the
  // pointer, and ymm0 to ymm8; VZEROUPPER also zeroes the upper halves of
  // ymm0 to ymm15, so every xmm register is declared clobbered. AVX2, BMI2,
  // LZCNT and POPCNT are present (asserted above).
  unsafe {
    asm!(
      "popcnt {n}, {b}",
      "cmp {n:e}, 4",
      "jbe 2f",
      // xmm0: the nibbles. Byte k < 8 is the high nibble of byte k of the
      // word, byte 8 + k its low nibble.
      "vmovq xmm0, {b}",
      "vpsrlw xmm1, xmm0, 4",
      "vpunpcklqdq xmm0, xmm1, xmm0",
      "vpand xmm0, xmm0, xmmword ptr [rip + {t}]",
      "vmovdqa xmm4, xmmword ptr [rip + {t} + 16]",
      "vmovdqa xmm1, xmmword ptr [rip + {t} + 32]",
      "vmovdqa xmm2, xmmword ptr [rip + {t} + 48]",
      "vmovdqa xmm3, xmmword ptr [rip + {t} + 64]",
      "vmovdqa xmm6, xmmword ptr [rip + {t} + 80]",
      // xmm1 to xmm4: each nibble's first to fourth block number.
      "vpshufb xmm1, xmm1, xmm0",
      "vpshufb xmm2, xmm2, xmm0",
      "vpshufb xmm3, xmm3, xmm0",
      "vpshufb xmm6, xmm6, xmm0",
      "vpaddb xmm1, xmm1, xmm4",
      "vpaddb xmm2, xmm2, xmm4",
      "vpaddb xmm3, xmm3, xmm4",
      // Interleaved to a dword per nibble: xmm4 and xmm5 the high nibbles
      // of bytes 0..4 and 4..8, xmm2 and xmm1 the low ones.
      "vpunpcklbw xmm5, xmm1, xmm2",
      "vpunpckhbw xmm1, xmm1, xmm2",
      "vpunpcklbw xmm2, xmm3, xmm4",
      "vpunpckhbw xmm3, xmm3, xmm4",
      "vpunpcklwd xmm4, xmm5, xmm2",
      "vpunpckhwd xmm5, xmm5, xmm2",
      "vpunpcklwd xmm2, xmm1, xmm3",
      "vpunpckhwd xmm1, xmm1, xmm3",
      // ymm7 and ymm6: per byte of the word, as qwords, the bits its high
      // nibble's blocks take.
      "vpmovzxbq ymm7, xmm6",
      "vpsrldq xmm6, xmm6, 4",
      "vpmovzxbq ymm6, xmm6",
      "vpcmpeqd ymm8, ymm8, ymm8",
      // ymm4: bytes 0..4 of the word, a qword each. The low nibble's
      // dword moves up past the high nibble's blocks and replaces what is
      // above them (VPBLENDVB takes the second source where the mask byte
      // has its top bit set).
      "vpmovzxdq ymm4, xmm4",
      "vpmovzxdq ymm2, xmm2",
      "vpsllvq ymm2, ymm2, ymm7",
      "vpsllvq ymm7, ymm8, ymm7",
      "vpblendvb ymm4, ymm4, ymm2, ymm7",
      // ymm5: bytes 4..8, the same way.
      "vpmovzxdq ymm5, xmm5",
      "vpmovzxdq ymm1, xmm1",
      "vpsllvq ymm1, ymm1, ymm6",
      "vpsllvq ymm6, ymm8, ymm6",
      "vpblendvb ymm5, ymm5, ymm1, ymm6",
      // Stores, byte 7 of the word first.
      "vextracti128 xmm1, ymm5, 1",
      "vmovhps qword ptr [{p}], xmm1",
      "mov {k}, {b}",
      "shr {k}, 56",
      "popcnt {k}, {k}",
      "vmovq qword ptr [{p} + {k}], xmm1",
      "mov {k}, {b}",
      "shr {k}, 48",
      "popcnt {k}, {k}",
      "vmovhps qword ptr [{p} + {k}], xmm5",
      "mov {k}, {b}",
      "shr {k}, 40",
      "popcnt {k}, {k}",
      "vmovq qword ptr [{p} + {k}], xmm5",
      "vextracti128 xmm1, ymm4, 1",
      "mov {k}, {b}",
      "shr {k}, 32",
      "popcnt {k}, {k}",
      "vmovhps qword ptr [{p} + {k}], xmm1",
      "mov {k}, {b}",
      "shr {k}, 24",
      "popcnt {k}, {k}",
      "vmovq qword ptr [{p} + {k}], xmm1",
      "mov {k}, {b}",
      "shr {k}, 16",
      "popcnt {k}, {k}",
      "vmovhps qword ptr [{p} + {k}], xmm4",
      "mov {k}, {b}",
      "shr {k}, 8",
      "popcnt {k}, {k}",
      "vmovq qword ptr [{p} + {k}], xmm4",
      "vzeroupper",
      "jmp 3f",
      // Up to four blocks.
      "2:",
      "lzcnt {k}, {b}",
      "xor {k:e}, 63",
      "mov byte ptr [{p}], {k:l}",
      "bzhi {b}, {b}, {k}",
      "lzcnt {k}, {b}",
      "xor {k:e}, 63",
      "mov byte ptr [{p} + 1], {k:l}",
      "bzhi {b}, {b}, {k}",
      "lzcnt {k}, {b}",
      "xor {k:e}, 63",
      "mov byte ptr [{p} + 2], {k:l}",
      "bzhi {b}, {b}, {k}",
      "lzcnt {k}, {b}",
      "xor {k:e}, 63",
      "mov byte ptr [{p} + 3], {k:l}",
      "3:",
      p = in(reg) blocks.as_ptr(),
      t = sym NIBBLES,
      b = inout(reg) bits => _,
      n = out(reg) n,
      k = out(reg) _,
      out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
      out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
      out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
      out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
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
