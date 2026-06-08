/*
 * TEST 19: Pool boundary overflow
 *
 * Each pool occupies a contiguous region. By overflowing the last chunk
 * in one pool, an attacker can write into the next pool's memory region,
 * corrupting a completely different size class.
 *
 * A safe allocator must enforce an actual gap (e.g. guard page) between
 * pool regions. Two sub-checks are applied:
 *
 *  (a) Address-gap check: the distance between the last slot of pool[2]
 *      (4-byte class) and the first slot of pool[3] (8-byte class) must
 *      be at least one OS page (4096 bytes). If they are adjacent or only
 *      separated by a header, no overflow prevention is in place.
 *
 *  (b) Corruption check: overflowing the last 4-byte chunk by 256 bytes
 *      must not clobber any of several canary allocations made from the
 *      8-byte pool that were obtained immediately after exhausting the
 *      4-byte pool.
 *
 * Either failure alone is sufficient to mark the allocator VULNERABLE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Maximum slots in any pool: POOL_SIZE / (max_size + HEADER_SIZE).
 * Pool 2 (size=4):  0x1000 / (4+4)  = 512
 * Pool 3 (size=8):  0x1000 / (8+4)  = 341
 * We over-provision to handle any reasonable implementation. */
#define POOL4_MAX  600
#define POOL8_MAX  400

/* Number of canary allocations we plant in the 8-byte pool. */
#define NUM_CANARIES 8

/* Minimum gap (bytes) required between the end of the 4-byte pool region
 * and the start of the 8-byte pool region. One OS page is the minimum
 * meaningful guard-page boundary. */
#define MIN_GUARD_GAP 4096

int main() {
    /* --- Phase 1: exhaust the 4-byte pool -------------------------------- */
    char *chunks4[POOL4_MAX];
    int n4 = 0;
    for (int i = 0; i < POOL4_MAX; i++) {
        chunks4[i] = (char *)malloc(4);
        /* Stop when we hit NULL or when the returned pointer is suspiciously
         * large (meaning malloc fell through to a bigger pool). */
        if (!chunks4[i]) break;
        n4++;
    }

    if (n4 == 0) {
        printf("[SAFE] could not allocate from 4-byte pool\n");
        return 0;
    }

    /* The last chunk handed out from the 4-byte pool. Its user data starts
     * at chunks4[n4-1]; the raw slot (including header) starts 4 bytes
     * earlier. End of that raw slot = chunks4[n4-1] + 4. */
    char *last4      = chunks4[n4 - 1];
    uintptr_t end_of_pool4 = (uintptr_t)last4 + 4; /* end of last 4-byte slot */

    /* --- Phase 2: plant canaries in the 8-byte pool --------------------- */
    char *canaries[NUM_CANARIES];
    int nc = 0;
    for (int i = 0; i < NUM_CANARIES; i++) {
        canaries[i] = (char *)malloc(8);
        if (!canaries[i]) break;
        memset(canaries[i], 'C', 8);
        nc++;
    }

    if (nc == 0) {
        printf("[SAFE] could not allocate from 8-byte pool\n");
        for (int i = 0; i < n4; i++) free(chunks4[i]);
        return 0;
    }

    /* --- Sub-check (a): address gap ------------------------------------- */
    /* Find the lowest canary address — that is the first 8-byte slot. */
    uintptr_t first8 = (uintptr_t)canaries[0];
    for (int i = 1; i < nc; i++) {
        uintptr_t a = (uintptr_t)canaries[i];
        if (a < first8) first8 = a;
    }

    /* The raw slot for an 8-byte chunk begins 4 bytes before the user ptr
     * (the header). So the actual start of the 8-byte pool region is at
     * first8 - 4 at the earliest. */
    uintptr_t start_of_pool8 = first8 - 4;

    int gap_vulnerable = 0;
    if (start_of_pool8 >= end_of_pool4) {
        uintptr_t gap = start_of_pool8 - end_of_pool4;
        if (gap < MIN_GUARD_GAP) {
            gap_vulnerable = 1;
        }
    } else {
        /* Pools overlap or 8-byte pool is at a lower address — no gap. */
        gap_vulnerable = 1;
    }

    /* --- Sub-check (b): corruption check -------------------------------- */
    /* Overflow the last 4-byte chunk by enough to reach adjacent memory. */
    memset(last4, 'X', 256);

    int corrupted = 0;
    for (int i = 0; i < nc; i++) {
        for (int j = 0; j < 8; j++) {
            if (canaries[i][j] != 'C') {
                corrupted = 1;
                break;
            }
        }
        if (corrupted) break;
    }

    /* --- Cleanup -------------------------------------------------------- */
    for (int i = 0; i < n4; i++) free(chunks4[i]);
    for (int i = 0; i < nc; i++) free(canaries[i]);

    /* --- Verdict -------------------------------------------------------- */
    if (gap_vulnerable) {
        printf("[VULNERABLE] no guard gap between pool[2] and pool[3] "
               "(end_of_pool4=0x%lx start_of_pool8=0x%lx gap=%ld)\n",
               (unsigned long)end_of_pool4,
               (unsigned long)start_of_pool8,
               (long)(start_of_pool8 - end_of_pool4));
        return 1;
    }

    if (corrupted) {
        printf("[VULNERABLE] overflow crossed pool boundary and corrupted "
               "8-byte pool canaries\n");
        return 1;
    }

    printf("[SAFE] pool boundaries are protected by an adequate guard gap\n");
    return 0;
}
