/*
 * TEST 14: Alignment violation
 *
 * Returned pointers must be 16-byte aligned (the POSIX/SysV ABI minimum for
 * 64-bit; required for SSE/AVX __m128 loads and any type whose alignment
 * exceeds 8 bytes).
 *
 * Hardening over a naive check:
 *  1. Requires 16-byte alignment, not just 8.
 *  2. Exercises every pool size (1, 2, 4 … 512 bytes) individually.
 *  3. Checks recycled pointers: free a chunk then re-allocate it; the
 *     returned address must still be 16-byte aligned.
 *  4. Actually stores a __m128-aligned value through each pointer using
 *     GCC vector types, so misalignment causes a SIGBUS / SIGSEGV on
 *     architectures that enforce it, not merely a flag.
 *  5. Interleaves alloc/free/realloc rounds to defeat pool-warming tricks
 *     that might only align the very first allocation per pool.
 *
 * A correct implementation must pad its header to a multiple of 16 bytes
 * and ensure chunk slots are laid out with 16-byte-aligned strides in the
 * arena.  Simply getting lucky on mmap base address is insufficient.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Pool sizes the allocator is expected to handle (powers of two, 1..512). */
static const size_t POOL_SIZES[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 };
#define NUM_POOLS (sizeof(POOL_SIZES) / sizeof(POOL_SIZES[0]))

/* Number of simultaneous live allocations tested per pool. */
#define SLOTS 8

/* Number of free-then-reallocate recycle rounds per pool. */
#define RECYCLE_ROUNDS 4

/*
 * A type that requires 16-byte alignment: a 16-byte vector.
 * We write through the returned pointer with this type so a misaligned
 * pointer will fault on strict-alignment platforms and generate UB elsewhere.
 */
typedef int v128 __attribute__((vector_size(16)));

static int check_align(void *p, size_t req_size, const char *tag)
{
    if (!p) {
        printf("[VULNERABLE] %s: malloc returned NULL\n", tag);
        return 1;
    }
    if ((uintptr_t)p % 16 != 0) {
        printf("[VULNERABLE] %s: pointer %p not 16-byte aligned (offset %d)\n",
               tag, p, (int)((uintptr_t)p % 16));
        return 1;
    }
    /* Write a 16-byte vector through the pointer if the allocation is large
     * enough, triggering a hardware fault on strict-alignment targets. */
    if (req_size >= sizeof(v128)) {
        volatile v128 *vp = (v128 *)p;
        v128 zero = { 0 };
        *vp = zero;          /* misalignment → SIGBUS / SIGSEGV */
        (void)*vp;
    } else {
        /* For sub-16-byte allocations just do a byte write. */
        memset(p, 0xAB, req_size);
    }
    return 0;
}

int main(void)
{
    int bad = 0;
    char tag[64];

    for (size_t pi = 0; pi < NUM_POOLS; pi++) {
        size_t sz = POOL_SIZES[pi];
        void *slots[SLOTS];

        /* ---- Phase 1: fill all slots ---- */
        for (int s = 0; s < SLOTS; s++) {
            snprintf(tag, sizeof(tag), "pool[%zu] initial alloc slot %d", sz, s);
            slots[s] = malloc(sz);
            bad |= check_align(slots[s], sz, tag);
        }

        /* ---- Phase 2: recycle each slot RECYCLE_ROUNDS times ---- */
        for (int r = 0; r < RECYCLE_ROUNDS; r++) {
            /* Free all, then reallocate all — the free list now contains
             * previously-used chunks; each re-allocation must still align. */
            for (int s = 0; s < SLOTS; s++)
                free(slots[s]);

            for (int s = 0; s < SLOTS; s++) {
                snprintf(tag, sizeof(tag),
                         "pool[%zu] recycle round %d slot %d", sz, r, s);
                slots[s] = malloc(sz);
                bad |= check_align(slots[s], sz, tag);
            }
        }

        /* ---- Phase 3: interleaved free/realloc (odd/even pattern) ---- */
        /* Free odd-indexed slots then immediately reallocate them. */
        for (int s = 1; s < SLOTS; s += 2) {
            free(slots[s]);
            snprintf(tag, sizeof(tag),
                     "pool[%zu] interleaved realloc slot %d", sz, s);
            slots[s] = malloc(sz);
            bad |= check_align(slots[s], sz, tag);
        }

        /* Clean up all live allocations for this pool. */
        for (int s = 0; s < SLOTS; s++)
            free(slots[s]);
    }

    /* ---- Cross-pool stress: mixed sizes in a single pass ---- */
    {
        /* Allocate one chunk per pool simultaneously, verify alignment,
         * then free them all.  This exercises the arena layout when multiple
         * pools are active at once. */
        void *cross[NUM_POOLS];
        for (size_t pi = 0; pi < NUM_POOLS; pi++) {
            snprintf(tag, sizeof(tag), "cross-pool alloc size %zu", POOL_SIZES[pi]);
            cross[pi] = malloc(POOL_SIZES[pi]);
            bad |= check_align(cross[pi], POOL_SIZES[pi], tag);
        }
        for (size_t pi = 0; pi < NUM_POOLS; pi++)
            free(cross[pi]);

        /* Second pass to hit recycled cross-pool chunks. */
        for (size_t pi = 0; pi < NUM_POOLS; pi++) {
            snprintf(tag, sizeof(tag), "cross-pool recycle size %zu", POOL_SIZES[pi]);
            cross[pi] = malloc(POOL_SIZES[pi]);
            bad |= check_align(cross[pi], POOL_SIZES[pi], tag);
        }
        for (size_t pi = 0; pi < NUM_POOLS; pi++)
            free(cross[pi]);
    }

    if (bad) {
        /* First violation already printed; no need to repeat details. */
        return 1;
    }

    printf("[SAFE] all pointers are 16-byte aligned across all pool sizes and recycle rounds\n");
    return 0;
}
