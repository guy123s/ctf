# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Smoke tests
./run.sh          # gcc test.c malloc.c -ldl -o test && ./test
./check_run.sh    # gcc self_check.c malloc.c -ldl -o self_check && ./self_check
./testing.sh      # gcc testing.c malloc.c -ldl -o testing && ./testing

# Run all scored tests (tests/test*.c)
./run_tests.sh    # prints Score: N/20

# Compile and run a single scored test manually
gcc tests/test5.c malloc.c -ldl -o tests/test5 && ./tests/test5
```

## Architecture

All work lives in `malloc.c`. It implements `malloc` and `free` that shadow libc via symbol interposition (no `LD_PRELOAD` needed — the test files link directly against `malloc.c`). The real libc `malloc` is obtained once via `dlsym(RTLD_NEXT, "malloc")` and is used internally to allocate `node` structs.

**Memory layout at init:**
- One `mmap`'d arena of 1 MB (`ARENA_SIZE = 0x100000`).
- Split into 10 pools (`NUM_POOLS = 10`), each 4 KB (`POOL_SIZE = 0x1000`).
- Pool `i` holds chunks of size `1 << i` (1, 2, 4, … 512 bytes).
- Each pool is a singly-linked free list of `node` structs (allocated from real libc malloc).

**Allocation (`malloc`):**
- Finds the first pool where `size <= pool->size` and the free list is non-empty.
- Pops the head node, writes the pool's size into a 4-byte header at `chunk`, returns `chunk + 4`.
- Falls through to `return NULL` if no pool fits (requests > 512 bytes are unhandled).

**Free (`free`):**
- Reads the 4-byte header at `ptr - 4` to identify which pool owns the chunk.
- Allocates a new `node` via real malloc and pushes the chunk back onto that pool's free list.
- The header is fully user-writable (no canary / checksum), which is the intentional vulnerability surface for the CTF.

## Test suite purpose

Each `tests/testN.c` probes a specific allocator weakness (data leakage after free, header corruption, use-after-free, double-free, heap determinism, etc.). A test exits 0 if the allocator is **safe** for that property, 1 if **vulnerable**. `run_tests.sh` counts exits-0 as passing — fixing vulnerabilities raises the score.
