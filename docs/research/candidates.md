# OxiBelt용 Pure-Rust Global Allocator 후보 조사

조사일: 2026-09-27 · 대상: Linux x86_64, tokio multi-thread, 오래 실행되는 edge reverse proxy (RSS가 중요)
현재 상태: secure mimalloc (C, `cc`로 빌드)를 `#[global_allocator]`로 사용 중

## 방법과 주의사항

- **버전, 날짜, 라이선스, 다운로드 수**는 2026-09-27에 crates.io API(`/api/v1/crates/<name>`)에서 가져왔습니다. **Stars와 마지막 push 날짜**는 GitHub REST API에서 가져왔습니다.
- **Unsafe 양**은 crates.io의 최신 `.crate` 소스를 받아 `src/`에 grep을 돌려 셌습니다.
  - `LOC`: 주석과 빈 줄을 뺀 줄 수
  - `unsafe{}`: `unsafe {` 블록 개수
  - `unsafe fn`: `unsafe fn` 선언 개수
  - 대략적인 수치이고 tests/benches 폴더는 포함하지 않았습니다. 테스트 모듈이 `src/` 안에 있는 crate는 그 부분도 수치에 들어갑니다.
- **벤치마크**는 거의 모두 저자가 직접 측정한 것입니다. 이번 조사에서 제가 다시 돌려보지 않았습니다. 확인하지 못한 항목에는 **(unverified)**를 붙였습니다.

---

## 요약 결론 (TL;DR)

1. **mimalloc, jemalloc 수준에서 바로 교체할 수 있는 성숙한 pure-Rust 범용 allocator는 2026-09 현재 없습니다.** 멀티스레드 서버용 설계(thread-local heap 또는 lock-free, mmap 직접 사용, OS에 메모리 반환)를 갖춘 후보는 세 개뿐이고, 모두 나온 지 1년 안팎입니다.
   - **smalloc** (`smmalloc` crate)
   - **rallocator** (Microsoft Oxidizer)
   - **rusty_alloc** (mimalloc v2.4.5를 Rust로 다시 만든 것)
2. 그 밖의 유명한 crate는 **전역 lock 하나 + 호출자가 넘겨주는 arena** 방식의 `no_std`/embedded/wasm용입니다. talc, rlsf, buddy_system_allocator, linked_list_allocator, good_memory_allocator, dlmalloc-rs, galloc가 여기에 속합니다. 코어가 여러 개인 tokio 서버에서는 lock 경합으로 성능이 무너집니다. talc 저자도 README에서 "hosted 환경에서는 jemalloc이나 mimalloc을 쓰라"고 명시합니다.
3. **ralloc (Redox)는 사실상 죽은 프로젝트입니다.** 2016년에 나온 1.0.0이 마지막이고, 이미 제거된 nightly feature에 의존합니다. ferroc은 nightly가 필요하고 crate 업데이트가 멈췄습니다(2024-05).
4. OxiBelt 관점에서 PoC로 벤치마크해볼 만한 순서:
   - **rallocator**: per-thread heap, `MADV_DONTNEED` purge, THP. Microsoft가 관리하고 lint 정책도 엄격합니다. 다만 0.1.0이고 공개된 비교 벤치마크가 없습니다.
   - **smalloc**: lock-free이고 단순합니다(core 약 400줄). EPYC에서 저자가 잰 수치는 mimalloc과 비슷합니다. 대신 **free한 메모리를 OS에 돌려주지 않고**(RSS가 최고치에 머묾), hardening이 없고, 한 번에 최대 2 GiB까지만 할당할 수 있습니다.
   - **rusty_alloc**: mimalloc 구조를 따르고 `secure` feature와 double-free abort가 있습니다. 하지만 7주 만에 0.1-alpha에서 2.2.1까지 올라왔고, 0.3.x 이하에서 UAF 3건이 있었으며, star 3개에 사실상 저자 한 명입니다. 성숙도 위험이 큽니다.
   - 세 후보 모두 **secure mimalloc 수준의 hardening(guard page, 암호화된 free list, 무작위화)을 기본으로 켜진 상태로 갖추지 못했습니다.** rusty_alloc만 opt-in으로 일부를 제공합니다.

---

## 비교표

| Crate (latest, date) | License | Maintenance | Thread model | OS memory | OS 반환 (RSS) | Unsafe (approx, src/) | Hardening | no_std | OxiBelt 적합도 |
|---|---|---|---|---|---|---|---|---|---|
| **talc** 5.1.1 (2026-09-09) | MIT | Active (561★) | 전역 `lock_api` Mutex (`TalcLock<R,S>`) | 기본값은 호출자가 넘긴 arena(`Claim`/`Manual`). OS용 `vheaps`/`Os` source는 **주석 처리돼 미완성** ("UNFINISHED") | `GlobalAllocSource`처럼 다른 allocator에 기대는 방식만 가능 | LOC≈3500, unsafe{}≈112, unsafe fn≈93 | 없음 (MIRI, fuzzing으로 정확성만 검증) | Yes (주 대상) | 낮음: 전역 lock, OS 연동 없음 |
| **rlsf** 0.2.3 (2026-07-27) | MIT/Apache-2.0 | 느리지만 유지 중 (127★) | `GlobalTlsf`: 전역 `pthread_mutex` 1개 | unix에서는 `mmap`으로 직접 확보 (Linux는 `MAP_FIXED_NOREPLACE`로 제자리 확장) | **반환하지 않음** (문서에 명시) | LOC≈2729, unsafe{}≈65, unsafe fn≈54 | 없음 | Yes | 낮음: O(1) real-time용, 전역 lock, RSS가 줄지 않음 |
| **smalloc** (`smmalloc` 7.6.13, 2026-08-08). crates.io의 `smalloc`은 다른 crate(0.1.2, 2022) | MIT OR Apache-2.0 OR TGPPL-1.0 (+Bootstrap OSL) | Active (125★, 2025-03 생성) | **Lock-free**: slab마다 CAS free list, 크기 class마다 slab 64개, thread별 slab 번호 | 약 48-bit VA를 `mmap`(rustix)으로 미리 예약 | **반환하지 않음** (madvise는 "open question") | LOC≈916 (core 약 406), unsafe{}≈48 | **없음** (README에 명시) | No (std, Linux/macOS/Windows) | 중간: 속도와 확장성은 좋음. RSS, hardening, 2 GiB 제한이 걸림 |
| **frusa** 0.1.3 (2025-11-22), motor-os 안의 crate | MIT OR Apache-2.0 | 저활동 (crate 기준) | 자체 spin RwLock + slab | **Fallback `GlobalAlloc`이 반드시 필요** (큰 할당과 page 공급을 여기에 맡김) | `reclaim()`을 직접 불러야 함 | LOC≈957, unsafe{}≈63 | 없음 | Yes | 낮음: 자체 벤치에서 8 thread 1339 ns/op, System은 27 ns |
| **buddy_system_allocator** 0.13.0 (2026-03-30) | MIT | 유지 중 (rCore, 145★) | 전역 `spin::Mutex` | 호출자가 `init(start,size)`로 arena를 넘김. `LockedHeapWithRescue`로 확장 가능 | 없음 | LOC≈776, unsafe{}≈28 | 없음 | Yes | 매우 낮음 (kernel용) |
| **linked_list_allocator** 0.10.6 (2026-04-14) | Apache-2.0/MIT | 유지 중 (rust-osdev, 242★) | 전역 spinlock (`spinning_top`) | 호출자가 arena를 넘김 (`unsafe init`) | 없음 | LOC≈1159, unsafe{}≈74 | 없음. 과거에 RUSTSEC-2022-0063 (OOB write, 0.10.2 이상에서 수정: 수정 버전은 unverified) | Yes | 매우 낮음: O(n), talc 저자도 "훨씬 느리다"고 적음 |
| **ralloc** 1.0.0 (2016-12-21) | MIT | **Dead**: GitHub 마지막 push 2020-12, GitLab mirror | thread-local cache + 전역 bookkeeper (global-local 모델) | `brk` 기반 | 부분적 (memtrim) | LOC≈1662 | 없음 (valgrind 연동만) | — | **사용 불가**: 제거된 nightly feature(`optin_builtin_traits`, `type_ascription`, `nonzero` 등)에 의존 |
| **galloc** 2.0.0 (2026-06-30), gear-tech | **GPL-3.0**(+Classpath exc.) | Gear 블록체인 전용 | `gear-dlmalloc` 래퍼 (wasm) | wasm | — | 20줄짜리 wrapper | 없음 | Yes | 해당 없음 (wasm, GPL) |
| **good_memory_allocator** 0.1.7 (2022-11-09). repo 이름이 `MaderNoob/galloc` | MIT | **정체**: 마지막 push 2022-11 | 전역 spinlock (`SpinLockedAllocator`) | 호출자가 arena를 넘김 (`unsafe init`) | 없음 | LOC≈2088, unsafe{}≈87, unsafe fn≈61 | 없음 (fuzz 테스트만) | Yes | 매우 낮음 |
| **rallocator** 0.1.0 (2026-08-13), Microsoft Oxidizer | MIT | Active (Oxidizer 177★, 2026-09-26 push). 성능 PR #764는 draft | **per-thread implicit heap**, cross-thread free는 owner queue로 보냄, explicit/bump heap 지원 (`allocation_hints`) | 1 GiB region을 `mmap(PROT_NONE)`로 예약하고 `mprotect`로 commit, `MADV_HUGEPAGE` 적용 | `MADV_DONTNEED`. 1 GiB 넘는 direct mapping은 `munmap` | LOC≈10.7k, unsafe{}≈1045, unsafe fn≈140 (많음) | 문서화된 hardening 없음 (unverified). 대신 telemetry와 caller tracking 제공 | No (Linux/Windows만. 그 외 OS는 컴파일 실패) | **중상**: 설계는 서버용에 맞음. 공개 벤치 없음, 0.1 단계 |
| **rusty_alloc** 2.2.1 (2026-09-25) + `rusty_alloc-api` | MIT | 매우 활발하지만 신생 (3★, 2026-08 생성, 사실상 저자 1인) | mimalloc v2 구조: per-thread heap, lock-free cross-thread free (loom 검증을 주장) | mmap, 32 MiB segment | `MADV_DONTNEED`/`MADV_FREE`. **purge는 기본 비활성**, `purge_delay>=0` 권장 | LOC≈8.7k, unsafe{}≈322, unsafe fn≈142. `undocumented_unsafe_blocks = deny` | double-free abort (기본). opt-in `secure`(free list link 암호화), `blockmap` | Yes (`ra_single_threaded` cfg) | 중간: 기능은 가장 가깝지만 성숙도 위험이 매우 큼 |
| **ferroc** 1.0.0-pre.3 (2024-05-13) | MIT OR Apache-2.0 | 저활동 (마지막 push 2025-09) | lock-free, mimalloc 계열, per-thread heap | `Mmap` base (libc, `MADV_DONTNEED`) | 있음 | LOC≈3641, unsafe{}≈214 | 없음 (valgrind tracking만) | Yes | 낮음: **latest nightly 전용** ("many unstable features") |
| **rsbmalloc** 0.4.4 (2024-04-23) | MIT OR Apache-2.0 | 정체 (8★) | 첫 할당 때 CPU 수×4개의 cache를 만들고, cache 자체도 동기화됨 | mmap. 16 KiB 넘는 할당은 직접 mmap/munmap | bin page는 **반환하지 않음** | LOC≈698 | 없음 | 부분적 | 낮음: 저자 표현으로 MT는 "quite a bit slower" |
| **dlmalloc** (dlmalloc-rs) 0.2.14 (2026-05-16) | MIT/Apache-2.0 | 유지 중 (Rust wasm std 기본 allocator) | 전역 lock | unix에서 mmap/munmap | 일부 (trim) | LOC≈2389, unsafe fn≈99 | 없음 | Yes | 낮음: 전역 lock |
| **Oxidalloc** (Metehan120) | ? | **확인 불가**: GitHub repo가 404이고 crates.io에도 없음 | per-CPU cache (검색 결과 설명 기준) | 자체 VA 관리 | trim | — | hardened mode (주장) | — | 제외: 소스를 확인하지 못함 (unverified) |
| **zeropool** 0.7.0 | MIT OR Apache-2.0 | Active | TLS + lock-free 큐 | — | — | — | — | — | 해당 없음: `GlobalAlloc`이 아니고 byte buffer pool |

### Non-pure 기준선 (C/C++ binding)

| Crate | Latest (date) | License | 비고 |
|---|---|---|---|
| **mimalloc** 0.1.52 (2026-05-22) / libmimalloc-sys 0.1.49 | MIT | 현재 OxiBelt가 쓰는 것. feature: `secure`, `v2`, `no_thp`, `local_dynamic_tls` 등. `v2`가 opt-in feature이므로 기본값은 v3로 추정 (**unverified**) |
| **mimalloc-safe** 0.1.67 (2026-09-14) | MIT | napi-rs가 만든 mimalloc fork binding. 업데이트가 더 잦음 |
| **tikv-jemallocator** 0.7.0 (2026-05-25) | MIT/Apache-2.0 | 서버 표준. background purge, 프로파일링 |
| **snmalloc-rs** 0.7.5 (2026-08-12) | MIT | C++ (cmake 또는 `build_cc`). message-passing 기반 free, `check` 옵션으로 hardening |
| **rpmalloc** 0.2.2 (2021-05-17) | MIT OR Apache-2.0 | Embark binding. crate 업데이트가 멈춤 |
| tcmalloc-better 0.1.19, scudo 0.1.3 | MIT / Apache-2.0 | 참고용. scudo는 hardened allocator binding (2022년 이후 업데이트 없음) |

---

## 후보별 상세

### 1. talc (SFBdragon/talc)
- **알고리즘**: dlmalloc 방식의 boundary tag와 binning을 쓰는 linked-list allocator입니다. TLSF와 비슷하며, 할당은 최악 O(n)이지만 실제로는 거의 O(1)입니다.
- **스레드 모델**: `TalcLock<R: lock_api::RawMutex, S: Source>` 하나에 전역 mutex 하나가 걸려 있습니다. per-thread cache는 없습니다. realloc 경로에는 `RELEASE_LOCK_ON_REALLOC_LIMIT = 0x4000` 최적화가 있습니다.
- **OS 메모리**: 5.1.1이 제공하는 `Source`는 `Manual`, `Claim`, `GlobalAllocSource`, `AllocatorSource`, `WasmGrow*`입니다. `source/vheaps.rs`(mmap reserve, `mprotect` commit, `MADV_FREE`)는 파일 첫 줄이 `//! UNFINISHED - OPEN AN ISSUE IF YOU WANT OS VIRTUAL MEMORY INTEGRATION`이고, `source/mod.rs`에서도 `// pub mod vheaps;`로 **꺼져 있습니다.** Cargo feature에도 `os`가 없습니다.
- **설치 방식**: README 예제의 `Claim::array(&raw mut INITIAL_HEAP)`가 `unsafe`입니다. OxiBelt의 `deny(unsafe_code)`와 부딪힙니다.
- **벤치마크**: BENCHMARKS.md는 no_std allocator끼리만 비교합니다. jemalloc과 mimalloc은 "Talc의 대안이 아니다"라며 뺐습니다. frusa README에 실린 수치로는 talc가 1 thread 41.85 ns/op, 8 thread 2196 ns/op로 급격히 나빠집니다.
- **판단**: 저자가 직접 "성숙한 hosted 시스템이라면 jemalloc이나 mimalloc을 고려하라"고 씁니다. OxiBelt에는 맞지 않습니다.

### 2. rlsf (yvt/rlsf)
- TLSF 알고리즘이라 O(1)을 보장하는 real-time용입니다. `GlobalTlsf`는 unix에서 `static mut MUTEX: libc::pthread_mutex_t` 전역 lock 하나를 쓰고, `libc::mmap`으로 64 KiB 단위로 늘립니다.
- README에 따르면 "It doesn't support returning memory pages to the system", 즉 RSS가 줄지 않습니다. "No special handling for small allocations"도 명시돼 있습니다.
- 벤치마크는 STM32F401 기준 260-320 cycles(경쟁 allocator는 340-750+)이고, wasm 코드 크기는 1,267 B입니다. 서버 워크로드 수치는 없습니다.
- **판단**: 부적합합니다. 전역 lock에, 메모리를 반환하지 않습니다.

### 3. smalloc (zooko/smalloc, crate 이름 `smmalloc`)
- **이름 주의**: crates.io의 `smalloc` 0.1.2(oxfeeefeee, 2022)는 **다른 crate**입니다. Zooko의 것은 `smmalloc`입니다.
- **설계**:
  - 약 48-bit 가상 주소를 미리 예약하고, 크기 class(2^2부터 2^31 B)마다 slab 64개를 드문드문 배치합니다.
  - 포인터에서 metadata를 산술 계산만으로 찾습니다.
  - 해제된 slot 자체에 다음 slot 번호를 적는 intrusive free list를 씁니다.
  - free-list head를 CAS로 갱신하고, 상위 비트에 ABA 카운터를 둡니다.
  - thread마다 atomic `fetch_add`로 slab 번호를 받아 경합을 줄입니다.
- **의존성**: Linux에서는 `rustix`(mm)만 씁니다. libc도 C 코드도 없습니다.
- **한계**:
  - 할당 1건 최대 2 GiB
  - 큰 slot 개수에 상한이 있음 (>1 GiB는 192개 등)
  - 프로세스당 인스턴스 1개만 가능
  - 한계를 넘으면 null을 반환
  - **madvise/purge를 하지 않아** RSS는 최고치 working set에 머묾
  - **hardening 없음**: 저자가 "Doesn't have any features for hardening"이라고 명시. LIFO 재사용이라 UAF 악용에 불리함
- **설치**: `#[global_allocator] static ALLOC: Smalloc = Smalloc::new();`가 safe `const fn`이라 OxiBelt 쪽에는 unsafe가 필요 없습니다.
- **벤치마크** (저자 측정, bench-allocators, AMD EPYC 9754 128-core Linux, 2026-02-15 생성):
  - simd-json 가중 합 (glibc 대비): jemalloc -19%, snmalloc -22%, **mimalloc -27%**, rpmalloc -25%, **smalloc -25%**
  - micro-bench `mt_aww-64` (64 thread): smalloc 379 ns/i, mimalloc 632, jemalloc 1757, snmalloc 1667, glibc 3019
  - rebar: allocator 간 차이가 작고, mimalloc이나 snmalloc이 대체로 약간 빠름
  - **RSS와 메모리 효율은 측정하지 않았습니다.**
  - mimalloc-bench에 넣자는 제안(issue #248)이 있습니다.
- **판단**: 속도와 lock-free 확장성은 좋은 후보입니다. 다만 장기 실행 proxy에서 RSS 동작과 보안 hardening이 없다는 점이 결정적인 약점입니다. 쓰려면 fork해서 purge를 추가해야 할 수 있습니다.

### 4. frusa (motor-os/frusa)
- Motor OS용 slab allocator입니다. `Frusa4K`/`Frusa2M::new(fallback: &'static dyn GlobalAlloc)`처럼 **back-end allocator가 반드시 필요합니다.** Linux에서는 결국 System(glibc) 같은 다른 allocator가 필요하므로 혼자서는 완결되지 않습니다.
- 자체 atomic RwLock을 씁니다. reclaim은 수동으로 불러야 합니다.
- README 벤치: FRUSA 1/2/4/8 thread = 59/199/465/1339 ns per alloc+dealloc. Rust System은 20/23/23/27 ns입니다.
- **판단**: 부적합합니다.

### 5. buddy_system_allocator (rcore-os)
- buddy system이고, `LockedHeap<ORDER>` = `spin::Mutex<Heap>`입니다. arena는 `unsafe init`으로 넘깁니다. `LockedHeapWithRescue`의 rescue 콜백으로 확장할 수 있습니다.
- 2의 거듭제곱으로 올림하므로 내부 단편화가 큽니다.
- **판단**: 커널/embedded용입니다. 부적합합니다.

### 6. linked_list_allocator (rust-osdev)
- first-fit linked list(O(n))이고, `spinning_top` spinlock을 씁니다. arena는 `unsafe init`으로 넘깁니다.
- RUSTSEC-2022-0063 (HIGH, out-of-bounds write) 이력이 있습니다. 수정 버전은 0.10.2 이상으로 알려져 있지만 advisory 페이지에서 직접 확인하지는 않았습니다 (unverified).
- **판단**: 부적합합니다.

### 7. ralloc (redox-os)
- crates.io 1.0.0이 2016-12에 나왔고, GitHub(GitLab mirror)의 마지막 push는 2020-12입니다.
- `#![feature(allocator, const_fn, nonzero, optin_builtin_traits, type_ascription, ...)]`처럼 이미 제거된 nightly feature에 의존하므로 **현재 컴파일러로는 빌드되지 않습니다.** (소스로 확인했고, 실제 빌드는 시도하지 않았습니다.)
- `brk` 기반이며, global-local(TLS) 구조입니다.
- **판단**: 사용할 수 없습니다. 참고로 Redox는 이후 relibc에서 dlmalloc 계열을 쓰는 것으로 알려져 있습니다 (unverified).

### 8. galloc / good_memory_allocator
- **`galloc` crate (2.0.0)**: Gear 블록체인의 wasm allocator입니다. 소스는 `gear-dlmalloc`을 `#[global_allocator]`로 재수출하는 20줄뿐이고, **GPL-3.0**입니다. 이번 조사 대상이 아닙니다.
- **`good_memory_allocator` 0.1.7** (repo `MaderNoob/galloc`): talc 벤치에 "Galloc"으로 나오는 것이 이 crate입니다.
  - dlmalloc에서 영감을 받은 linked list + smallbin 구조, 할당당 overhead는 `usize` 하나
  - `SpinLockedAllocator` 전역 spinlock, arena는 `unsafe init`
  - 2022-11 이후 업데이트 없음
- **판단**: 부적합합니다.

### 9. rallocator (microsoft/oxidizer): 신규 (2026-08)
- **정체**: "A pure-Rust, high-performance allocator integrated with `allocation_hints`". Microsoft의 Rust 서비스 플랫폼 Oxidizer 안에 있는 crate입니다. edition 2024, MSRV 1.93.1.
- **구조**:
  - Domain → 1 GiB region → 64 KiB slice → 32 KiB slab → block 순서의 계층입니다.
  - **thread마다 implicit general heap**이 있습니다. small 크기(≤16 KiB)의 free는 owner heap cache로 돌아가고, cross-thread free는 owner queue에 쌓입니다.
  - medium(≤1 GiB)은 slice span을 쓰고, 그보다 크거나 alignment가 64 KiB를 넘으면 전용 `mmap`을 씁니다.
  - `with_hint(&heap, || ...)`로 요청 단위 bump heap이나 locality heap을 고를 수 있습니다. proxy의 요청/연결 수명에 맞추기 좋은 기능입니다.
- **OS 연동 (hal/linux.rs)**: `mmap(PROT_NONE)`으로 예약, `mprotect`로 commit, `madvise(MADV_HUGEPAGE)`, `madvise(MADV_DONTNEED)`로 반환합니다. 2 MiB 정렬입니다. libc만 쓰고 C 코드는 없습니다.
- **Telemetry**: 컴파일 타임 설정으로 aggregate counter와 caller tracking을 켤 수 있고, snapshot을 HTML로 볼 수 있습니다.
- **Unsafe**: src/ 기준 `unsafe {` 약 1045개로 가장 많습니다. `rallocator!()` 매크로가 `unsafe Rallocator::new`를 감싸 주지만, 매크로가 펼쳐지는 곳이 사용자 crate라서 OxiBelt의 `deny(unsafe_code)`에 걸릴 수 있습니다 (unverified: 매크로 hygiene나 allow 처리를 확인하지 않았습니다). Cargo.toml에 clippy lint 다수가 켜져 있습니다.
- **벤치마크**: 공개된 mimalloc/jemalloc 비교 수치는 **없습니다**. 성능 통합 PR #764(2026-09-16)는 draft 상태이고, "overall combined speedup을 주장하지 않는다"고 적혀 있으며 리뷰어가 correctness 이슈 3건을 지적했습니다.
- **판단**: 설계상 OxiBelt에 가장 잘 맞는 pure-Rust 후보입니다. per-thread heap, purge, THP, Linux 1급 지원을 갖췄습니다. 하지만 0.1.0이라 API와 성능이 안정되지 않았고, hardening은 문서화되지 않았습니다. 직접 벤치마크해야 합니다.

### 10. rusty_alloc (Remade-With-Rust): 신규 (2026-08)
- **정체**: mimalloc v2.4.5 구조를 Rust로 다시 만든 것입니다.
  - 32 MiB segment, free-list sharding
  - loom으로 검증했다는 4-state cross-thread free 프로토콜
  - thread abandon/adopt
  - `mi_*` API 약 150개
- **crate 구성**: 코어는 `rusty_alloc`, `GlobalAlloc`/`Allocator`는 `rusty_alloc-api`("No unsafe required of callers")입니다.
- **Hardening**:
  - 기본: double-free를 감지하면 abort (upstream mimalloc release 빌드는 조용히 넘어감)
  - opt-in: `secure`(free list link 암호화 + 같은 segment 안으로 bound check, 할당당 약 15 명령 추가), `blockmap`, `debug_checks`
  - 자체 "use-protection-please" 41-gate 중 14/15를 충족했다고 주장 (unverified)
- **RSS**: 기본값으로는 purge를 하지 않습니다. README가 "Long-lived services should set `purge_delay >= 0`"이라고 권장합니다.
- **벤치마크** (저자 측정, callgrind 명령어 수이고 wall-clock이 아님, x86-64 Linux, LD_PRELOAD): vs mimalloc은 lua 0.97, perl 0.99, sqlite 1.00이고, vs jemalloc은 0.84/0.89/0.98입니다. 멀티스레드 wall-clock 확장성과 RSS 수치는 없습니다.
- **성숙도 경고**:
  - 2026-08-06 하루 사이에 0.1.0-alpha.1부터 0.3.2까지 게시됐고, 7주 만에 2.2.1에 도달했습니다.
  - README 문구: "Treat 0.3.2 and earlier as unsound", 즉 abandon/adopt 경로에서 UAF 3건이 있었습니다.
  - GitHub star 3개, 사실상 저자 1인(Mata Network)입니다.
  - Unsafe는 약 322 블록이고 `undocumented_unsafe_blocks = deny`가 걸려 있습니다. OxiBelt의 lint 정책과 방향이 같습니다.
- **판단**: 기능 목록은 secure mimalloc 대체에 가장 가깝습니다. 하지만 프로덕션 edge proxy에 넣기에는 검증 기간과 커뮤니티 검토가 크게 부족합니다. 관찰 대상 또는 PoC 비교군으로 두는 것이 적절합니다.

### 11. 기타
- **ferroc** (Js2xxx): mimalloc에 영감을 받은 lock-free allocator이고 `Mmap` base와 `MADV_DONTNEED`를 씁니다. "only supports the latest nightly"라 stable 1.98 기반인 OxiBelt에서는 제외입니다.
- **rsbmalloc**: binned 구조에 CPU 수×4개의 공유 cache를 두고, bin page를 반환하지 않습니다. 2024 이후 정체입니다.
- **elfmalloc** (allocators-rs, 2017): 사실상 중단됐습니다.
- **dlmalloc-rs**: Rust로 옮긴 dlmalloc이고 전역 lock을 씁니다. wasm std의 기본 allocator입니다.
- **Oxidalloc**: 검색 결과에서는 per-CPU cache와 hardened mode를 내세우는 pure-Rust allocator로 나옵니다. 하지만 2026-09-27 기준 GitHub repo가 404이고 crates.io에도 없습니다. **소스를 확인하지 못해 제외했습니다 (unverified).**
- **zeropool, context-allocator 등**: `GlobalAlloc` 범용 allocator가 아니라 buffer pool 또는 특수 목적용입니다.

---

## OxiBelt 적용 시 고려사항

1. **Unsafe 경계**
   - 어느 후보든 unsafe 자체는 allocator crate 안에 있습니다. OxiBelt workspace의 `deny(unsafe_code)`는 사용자 쪽 설치 코드에만 영향을 줍니다.
   - 설치 코드가 safe인 후보: smalloc, rusty_alloc-api, rlsf `GlobalTlsf`
   - 설치 코드에 unsafe가 필요한 후보: talc, linked_list, buddy, good_memory_allocator(`unsafe init` 또는 `Claim::array`). rallocator는 매크로 안에 unsafe가 있습니다.
   - "allocator 로직은 safe Rust이고 unsafe는 syscall/pointer 경계에만"이라는 목표와 비교하면, 조사한 crate 중 그런 구조가 **명확하게 문서화·강제된 것은 rusty_alloc(주장)뿐**입니다. 나머지는 핵심 로직 전반에 unsafe가 퍼져 있습니다.
   - 자체 구현을 할 경우 smalloc의 설계가 가장 단순해 참고하기 좋습니다: 크기 class마다 VA 예약 + index 기반 free list라서, 대부분을 정수(slot 번호) 연산으로 표현할 수 있습니다.
2. **RSS**
   - 장기 실행 proxy에는 purge(`MADV_DONTNEED`)가 꼭 필요합니다.
   - 기본으로 purge를 하는 것: rallocator
   - 설정해야 purge하는 것: rusty_alloc
   - 반환이 없거나 제한적인 것: smalloc, rlsf, rsbmalloc
3. **Hardening**: secure mimalloc(guard page, 암호화된 free list, 무작위 할당, double-free 감지)과 동등한 수준을 기본으로 제공하는 pure-Rust 후보는 없습니다. 가장 가까운 것은 rusty_alloc의 `secure` feature입니다.
4. **권장 다음 단계**: mimalloc(secure), tikv-jemallocator, smalloc, rallocator, rusty_alloc(`secure`, purge 켬)을 OxiBelt 실제 부하에 걸어 비교합니다. 측정 항목은 wrk/h2load 기준 p99 지연, 처리량, 24시간 RSS 추이입니다.

---

## Sources

- crates.io API (버전, 날짜, 라이선스, 다운로드): https://crates.io/api/v1/crates/{talc,rlsf,smalloc,smmalloc,frusa,buddy_system_allocator,linked_list_allocator,ralloc,galloc,good_memory_allocator,rusty_alloc,rusty_alloc-api,ferroc,rsbmalloc,rallocator,dlmalloc,zeropool,mimalloc,mimalloc-safe,tikv-jemallocator,snmalloc-rs,rpmalloc,tcmalloc-better,scudo}
- GitHub REST API (stars, push 날짜): https://api.github.com/repos/…
- talc: https://github.com/SFBdragon/talc · https://github.com/SFBdragon/talc/blob/master/BENCHMARKS.md · https://docs.rs/talc
- rlsf: https://github.com/yvt/rlsf · https://docs.rs/rlsf
- smalloc: https://github.com/zooko/smalloc · https://github.com/zooko/smalloc/blob/main/bench/README.md · https://github.com/zooko/bench-allocators/blob/main/benchmark-results/AMDEPYC9754128CoreProcessor.linuxgnu/COMBINED-REPORT.md · https://github.com/daanx/mimalloc-bench/issues/248 · https://lobste.rs/s/ubcsl9/smalloc_simple_memory_allocator · https://crates.io/crates/smmalloc
- frusa: https://github.com/moturus/motor-os (frusa README는 crate 소스에서 확인) · https://crates.io/crates/frusa
- buddy_system_allocator: https://github.com/rcore-os/buddy_system_allocator
- linked_list_allocator: https://github.com/rust-osdev/linked-list-allocator · https://rustsec.org/packages/linked_list_allocator.html · https://rustsec.org/advisories/RUSTSEC-2022-0063.html
- ralloc: https://github.com/redox-os/ralloc · https://crates.io/crates/ralloc
- galloc (gear): https://crates.io/crates/galloc · https://github.com/gear-tech/gear
- good_memory_allocator: https://github.com/MaderNoob/galloc · https://crates.io/crates/good_memory_allocator
- rallocator: https://github.com/microsoft/oxidizer/tree/main/crates/rallocator · https://docs.rs/rallocator · https://github.com/microsoft/oxidizer/pull/764
- rusty_alloc: https://github.com/Remade-With-Rust/rusty_alloc · https://crates.io/crates/rusty_alloc · https://crates.io/crates/rusty_alloc-api
- ferroc: https://github.com/Js2xxx/ferroc
- rsbmalloc: https://github.com/AWBroch/rsbmalloc · https://lib.rs/crates/rsbmalloc
- Oxidalloc (404, unverified): https://github.com/Metehan120/Oxidalloc
- zeropool: https://lib.rs/crates/zeropool
- dlmalloc-rs: https://github.com/alexcrichton/dlmalloc-rs
- elfmalloc / allocators-rs: https://github.com/ezrosent/allocators-rs
- C/C++ binding: https://github.com/purpleprotocol/mimalloc_rust · https://github.com/napi-rs/mimalloc-safe · https://github.com/tikv/jemallocator · https://github.com/microsoft/snmalloc · https://github.com/EmbarkStudios/rpmalloc-rs · https://microsoft.github.io/mimalloc/bench.html
- 배경: https://users.rust-lang.org/t/any-dynamic-storage-allocator-s-written-in-rust/61187
