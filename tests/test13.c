/*
 * TEST 13: Heap grooming — controlled adjacency overflow
 *
 * Allocate A, B, C in order.  Free B to punch a hole.  Allocate D of
 * the same size — a pool allocator that recycles freed slots will hand
 * back B's exact address, placing D between A and C with no gap.
 *
 * Hardening notes (vs. the naive version):
 *  1. We VERIFY that D landed at B's address.  If it didn't, the
 *     grooming failed (allocator gave a fresh slot) — we report that
 *     as an inconclusive setup failure rather than a false SAFE.
 *  2. We derive the inter-chunk stride from actual pointer arithmetic
 *     (stride = b − a) instead of a magic constant, so the overflow
 *     length is always exactly one byte past the end of D's chunk
 *     regardless of header overhead or pool size.
 *  3. We check BOTH neighbors: the forward overflow into C and a
 *     backward underflow probe toward A.
 *  4. We repeat the grooming cycle three times to catch allocators
 *     that dodge the first attempt (LIFO vs FIFO list ordering).
 *
 * Exit 0 → allocator is SAFE (guards prevented corruption).
 * Exit 1 → allocator is VULNERABLE (overflow reached a neighbor).
 * Exit 2 → inconclusive (grooming setup failed; fix the allocator's
 *           free-list recycling first).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define ALLOC_SIZE 16

/*
 * Run one grooming round.
 * Returns:  0  safe (no corruption detected)
 *           1  vulnerable
 *           2  grooming did not place D at B's slot (inconclusive)
 */
static int grooming_round(void) {
    char *a = (char *)malloc(ALLOC_SIZE);
    char *b = (char *)malloc(ALLOC_SIZE);
    char *c = (char *)malloc(ALLOC_SIZE);

    if (!a || !b || !c) {
        free(a); free(b); free(c);
        return 2;
    }

    /* Record stride between consecutive user pointers. */
    ptrdiff_t stride_bc = c - b;   /* distance from b's payload to c's payload */
    ptrdiff_t stride_ab = b - a;

    /* Canary fill both neighbors before the overflow. */
    memset(a, 'A', ALLOC_SIZE);
    memset(c, 'C', ALLOC_SIZE);

    free(b);

    /* D must recycle B's exact slot for the grooming to be meaningful. */
    char *d = (char *)malloc(ALLOC_SIZE);
    if (!d) {
        free(a); free(c);
        return 2;
    }

    if (d != b) {
        /* Allocator gave a different slot — grooming inconclusive. */
        free(a); free(c); free(d);
        return 2;
    }

    /*
     * Overflow: write exactly stride_bc + 1 bytes starting at d.
     * This reaches one byte into C's payload regardless of header size.
     * Use a pattern distinct from 'C' so corruption is unambiguous.
     */
    if (stride_bc > 0 && stride_bc <= 4096) {
        memset(d, 'D', (size_t)(stride_bc + 1));
    }

    /*
     * Underflow: write one byte into A's payload by writing backward
     * from d.  We do this by directly poking the byte at d[-1] which
     * lies in the region between A and D (header or guard territory).
     * Then also stomp stride_ab bytes before d to reach A's payload.
     */
    if (stride_ab > 0 && stride_ab <= 4096) {
        /* write from d backward, covering the full inter-chunk gap into A */
        char *underflow_buf = d - stride_ab;
        memset(underflow_buf, 'U', (size_t)(stride_ab + ALLOC_SIZE));
    }

    int corrupted = 0;

    /* Forward: did the overflow reach C? */
    for (int i = 0; i < ALLOC_SIZE; i++) {
        if (c[i] != 'C') {
            corrupted = 1;
            break;
        }
    }

    /* Backward: did the underflow reach A? */
    if (!corrupted) {
        for (int i = 0; i < ALLOC_SIZE; i++) {
            if (a[i] != 'A') {
                corrupted = 1;
                break;
            }
        }
    }

    free(a); free(c); free(d);
    return corrupted ? 1 : 0;
}

int main(void) {
    int rounds = 3;
    int inconclusive = 0;

    for (int r = 0; r < rounds; r++) {
        int result = grooming_round();
        if (result == 1) {
            printf("[VULNERABLE] heap grooming overflow corrupted a neighbor "
                   "(round %d)\n", r + 1);
            return 1;
        }
        if (result == 2) {
            inconclusive++;
        }
    }

    if (inconclusive == rounds) {
        /*
         * Every round failed to place D at B's slot — the allocator
         * never recycles freed memory, so the grooming setup is
         * impossible to verify.  Report inconclusive rather than SAFE.
         */
        printf("[INCONCLUSIVE] allocator did not recycle freed slots; "
               "grooming could not be set up in %d rounds\n", rounds);
        return 2;
    }

    printf("[SAFE] heap grooming overflow did not reach any neighbor "
           "(%d/%d rounds conclusive)\n", rounds - inconclusive, rounds);
    return 0;
}
