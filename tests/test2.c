/*
 * TEST 2: Heap buffer overflow — hardened multi-scenario version
 *
 * A safe allocator must prevent writes beyond the allocated size from
 * corrupting adjacent allocations.  Hardening strategies include guard
 * pages, canary/red-zone bytes, or placing a gap between consecutive
 * slots.
 *
 * This test checks overflow robustness across several independent
 * scenarios that resist trivial bypasses:
 *
 *   S1  – single-byte overflow (hits the inter-slot header, if any)
 *   S2  – overflow by exactly HEADER_SIZE+1 bytes (reaches next slot's data)
 *   S3  – full double-size overflow (original naive overflow)
 *   S4  – same three distances, repeated for pool sizes 8 and 32
 *   S5  – three consecutive allocations: verify the *left* neighbour is
 *          also unaffected (rules out "always put b before a" tricks)
 *   S6  – interleaved sizes to confirm cross-pool isolation
 *
 * For every scenario the canary pattern is sampled BEFORE the overflow is
 * written, so a correct allocator that zeroes on alloc still passes.
 *
 * Exit 0 → allocator is SAFE for this property.
 * Exit 1 → allocator is VULNERABLE (at least one overflow was detected).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Canary helpers                                                       */
/* ------------------------------------------------------------------ */

#define CANARY_L  0xAA   /* pattern written into the left  neighbour   */
#define CANARY_R  0xBB   /* pattern written into the right neighbour   */
#define CANARY_V  0xCC   /* pattern written into the victim itself      */

/* Fill buf[0..len-1] with byte val. */
static void fill(char *buf, int len, unsigned char val) {
    for (int i = 0; i < len; i++)
        buf[i] = (char)val;
}

/* Return 1 if every byte in buf[0..len-1] equals expected. */
static int check(const char *buf, int len, unsigned char expected) {
    for (int i = 0; i < len; i++)
        if ((unsigned char)buf[i] != expected)
            return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Per-scenario overflow test                                          */
/*                                                                     */
/* Allocates three consecutive buffers of `sz` bytes each:            */
/*   left, victim, right                                               */
/* Fills them with canary bytes, then overflows `victim` by            */
/* `overflow_len` bytes beyond sz (writing 0xDD into the overflow     */
/* region).  Returns 1 if corruption is detected, 0 otherwise.        */
/* ------------------------------------------------------------------ */
static int scenario(const char *label, int sz, int overflow_len) {
    /* Allocate three buffers.  Consecutive mallocs of the same size   */
    /* will come from consecutive slots in the same pool.              */
    char *left   = (char *)malloc(sz);
    char *victim = (char *)malloc(sz);
    char *right  = (char *)malloc(sz);

    if (!left || !victim || !right) {
        fprintf(stderr, "[SKIP] %s: allocation returned NULL (sz=%d)\n",
                label, sz);
        free(left); free(victim); free(right);
        return 0;  /* can't draw a conclusion */
    }

    /* Establish canary patterns. */
    fill(left,   sz, CANARY_L);
    fill(victim, sz, CANARY_V);
    fill(right,  sz, CANARY_R);

    /* Verify baseline (rules out pre-existing corruption). */
    if (!check(left, sz, CANARY_L) || !check(right, sz, CANARY_R)) {
        fprintf(stderr, "[SKIP] %s: canary baseline check failed\n", label);
        free(left); free(victim); free(right);
        return 0;
    }

    /* Write 0xDD into victim[sz .. sz+overflow_len-1]. */
    for (int i = sz; i < sz + overflow_len; i++)
        victim[i] = (char)0xDD;

    /* Detect corruption of either neighbour. */
    int corrupt_right = !check(right, sz, CANARY_R);
    int corrupt_left  = !check(left,  sz, CANARY_L);

    int vulnerable = corrupt_right || corrupt_left;

    if (vulnerable) {
        printf("[VULNERABLE] %s: overflow by %d byte(s) past sz=%d "
               "corrupted %s%s%sneighbour\n",
               label, overflow_len, sz,
               corrupt_left  ? "left "  : "",
               (corrupt_left && corrupt_right) ? "and " : "",
               corrupt_right ? "right " : "");
    }

    free(left);
    free(victim);
    free(right);
    return vulnerable;
}

/* ------------------------------------------------------------------ */
/* Cross-pool isolation scenario                                       */
/*                                                                     */
/* Allocate from two *different* pool sizes in interleaved order.     */
/* If the allocator places them adjacently (no gap), an overflow from */
/* the smaller into the larger (or vice-versa) will be detected.      */
/* ------------------------------------------------------------------ */
static int scenario_cross_pool(void) {
    /* pool for sz=8 and pool for sz=32 are different pools.           */
    char *a8  = (char *)malloc(8);
    char *a32 = (char *)malloc(32);
    char *b8  = (char *)malloc(8);

    if (!a8 || !a32 || !b8) {
        fprintf(stderr, "[SKIP] cross-pool: allocation returned NULL\n");
        free(a8); free(a32); free(b8);
        return 0;
    }

    fill(a8,  8,  CANARY_L);
    fill(a32, 32, CANARY_R);
    fill(b8,  8,  CANARY_L);

    /* Overflow a8 by 32 bytes — enough to reach a32 if they share a  */
    /* contiguous region.                                               */
    for (int i = 8; i < 40; i++)
        a8[i] = (char)0xEE;

    int corrupt_a32 = !check(a32, 32, CANARY_R);
    int corrupt_b8  = !check(b8,  8,  CANARY_L);

    if (corrupt_a32 || corrupt_b8) {
        printf("[VULNERABLE] cross-pool: overflow from sz=8 region "
               "corrupted %s allocation\n",
               corrupt_a32 ? "sz=32" : "sz=8 (b8)");
        free(a8); free(a32); free(b8);
        return 1;
    }

    free(a8); free(a32); free(b8);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    int any_vulnerable = 0;

    /*
     * S1/S2/S3 for pool size 16 (the original pool):
     *   S1: 1-byte overflow  — hits the inter-slot gap / guard canary
     *   S2: HEADER_SIZE+1=5  — clears the header and one data byte
     *   S3: sz+1=17          — well into next slot's data
     */
    any_vulnerable |= scenario("S1-sz16-ov1",  16,  1);
    any_vulnerable |= scenario("S2-sz16-ov5",  16,  5);
    any_vulnerable |= scenario("S3-sz16-ov17", 16, 17);

    /*
     * Same three distances for pool size 8.
     */
    any_vulnerable |= scenario("S4a-sz8-ov1",  8,  1);
    any_vulnerable |= scenario("S4b-sz8-ov5",  8,  5);
    any_vulnerable |= scenario("S4c-sz8-ov9",  8,  9);

    /*
     * Same three distances for pool size 32.
     */
    any_vulnerable |= scenario("S5a-sz32-ov1",  32,  1);
    any_vulnerable |= scenario("S5b-sz32-ov5",  32,  5);
    any_vulnerable |= scenario("S5c-sz32-ov33", 32, 33);

    /*
     * S6: cross-pool isolation.
     */
    any_vulnerable |= scenario_cross_pool();

    if (any_vulnerable) {
        /* Individual scenarios already printed details above. */
        return 1;
    }

    printf("[SAFE] no adjacent allocation was corrupted by any overflow scenario\n");
    return 0;
}
