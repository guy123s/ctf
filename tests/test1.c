/*
 * TEST 1: Data leakage after free
 *
 * A safe allocator must zero out (or scrub) memory on free or on re-allocation
 * so that a subsequent caller cannot read a previous tenant's data.
 *
 * Hardening strategy:
 *  - Tested across multiple pool size classes (4, 16, 64, 256 bytes) to
 *    prevent a bypass that only zeroes one specific size bin.
 *  - Each size class is exercised for ROUNDS cycles of write→free→realloc
 *    so that we always hit a previously-dirty slot, not a fresh mmap page
 *    (which would appear clean without any zeroing effort).
 *  - The entire allocation is checked (memcmp), not just the first word,
 *    so partial-zero bypasses are caught.
 *  - A fresh "canary" pattern is written each round so a one-time scrub on
 *    the very first free cannot fake safety for later rounds.
 *
 * Exit 0 → SAFE (no leakage detected across all rounds and sizes).
 * Exit 1 → VULNERABLE (at least one stale byte found after realloc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDS 8

/* Size classes that map to distinct pools in the allocator (1<<2=4 ... 1<<8=256). */
static const size_t sizes[] = { 4, 16, 64, 256 };
#define NUM_SIZES ((int)(sizeof(sizes) / sizeof(sizes[0])))

/*
 * Fill buf[0..n-1] with a deterministic non-zero pattern derived from
 * (round, size_index) so every round uses a different secret.
 */
static void fill_pattern(unsigned char *buf, size_t n, int round, int si)
{
    for (size_t k = 0; k < n; k++)
        buf[k] = (unsigned char)(0xA5 ^ (round * 7 + si * 31 + (int)k));
}

int main(void)
{
    /*
     * Phase 1 – warm up each size class so that by the time the real leak
     * check begins, every slot we touch has been written and freed at least
     * once.  This ensures we are always testing reused (potentially dirty)
     * slots, never a pristine mmap page.
     */
    for (int si = 0; si < NUM_SIZES; si++) {
        size_t sz = sizes[si];
        void *p = malloc(sz);
        if (!p) {
            printf("[ERROR] malloc(%zu) returned NULL during warm-up\n", sz);
            return 1;
        }
        fill_pattern((unsigned char *)p, sz, -1, si);
        free(p);
    }

    /*
     * Phase 2 – leak detection across multiple rounds and size classes.
     *
     * Each iteration:
     *   a) malloc(sz)          — must give back a slot from the free list
     *                            (warm-up above guarantees it was used before)
     *   b) fill it with a known pattern
     *   c) free it
     *   d) malloc(sz) again    — same slot, same pool
     *   e) verify every byte is zero (or at least not the previous pattern)
     *
     * We treat any byte that matches the just-written pattern as a leak,
     * because the only way a safe allocator can differ from a vulnerable one
     * here is by zeroing on free or on alloc.
     */
    unsigned char *zero_ref = calloc(1, 256); /* largest size we test */
    if (!zero_ref) {
        printf("[ERROR] calloc failed\n");
        return 1;
    }

    for (int round = 0; round < ROUNDS; round++) {
        for (int si = 0; si < NUM_SIZES; si++) {
            size_t sz = sizes[si];

            /* (a) allocate and write a distinctive secret */
            unsigned char *writer = (unsigned char *)malloc(sz);
            if (!writer) {
                printf("[ERROR] malloc(%zu) returned NULL at round %d\n", sz, round);
                free(zero_ref);
                return 1;
            }
            fill_pattern(writer, sz, round, si);

            /* (b) free – a vulnerable allocator leaves the bytes intact */
            free(writer);

            /* (c) reallocate the same size – should get the same dirty slot */
            unsigned char *reader = (unsigned char *)malloc(sz);
            if (!reader) {
                printf("[ERROR] malloc(%zu) returned NULL at round %d (reader)\n", sz, round);
                free(zero_ref);
                return 1;
            }

            /* (d) check: every byte must be zero (safe) or at least not the
             *     exact pattern we just wrote (would be an unmistakable leak) */
            unsigned char expected[256];
            fill_pattern(expected, sz, round, si);

            if (memcmp(reader, expected, sz) == 0) {
                printf("[VULNERABLE] round %d, size %zu: "
                       "secret pattern still readable after free\n",
                       round, sz);
                free(reader);
                free(zero_ref);
                return 1;
            }

            /*
             * Stricter check: a truly safe allocator zeroes the memory.
             * Flag it if any non-zero byte is found (informational; the
             * primary vuln check above is the hard gate).
             */
            if (memcmp(reader, zero_ref, sz) != 0) {
                printf("[VULNERABLE] round %d, size %zu: "
                       "reallocated buffer is not zeroed (data remnant present)\n",
                       round, sz);
                free(reader);
                free(zero_ref);
                return 1;
            }

            free(reader);
        }
    }

    free(zero_ref);
    printf("[SAFE] no data leakage detected across %d rounds and %d size classes\n",
           ROUNDS, NUM_SIZES);
    return 0;
}
