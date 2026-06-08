/*
 * TEST 10: Allocation size confusion — padding byte leakage
 *
 * The allocator rounds a request up to the next pool slot size.  For example,
 * malloc(3) is served from the 4-byte pool, so the returned chunk is 4 bytes
 * wide even though the caller only asked for 3.
 *
 * A safe allocator must zero the entire pool slot (including the
 * (slot_size - requested_size) padding bytes) on every allocation.  Otherwise
 * a later caller who requests the same rounded-up size can read stale data
 * written by the previous tenant through the padding region — a classic
 * size-confusion information leak.
 *
 * Test procedure:
 *   1. malloc(4)  — fill all 4 bytes with 0xFF, then free.
 *   2. malloc(3)  — lands in the same 4-byte slot.
 *   3. Read ptr[3] (the padding byte the caller never asked for).
 *      • 0xFF  → the allocator left the old tenant's data in the padding area.
 *                VULNERABLE.
 *      • 0x00  → the allocator zeroed the full slot on alloc (or on free).
 *                SAFE.
 *
 * We repeat across several (requested, pool) size pairs to prevent a bypass
 * that only scrubs one specific pool:
 *
 *   requested → pool slot
 *       1     →    2
 *       3     →    4
 *       5     →    8
 *      17     →   32
 *
 * Exit 0 → SAFE   (all padding bytes were zeroed).
 * Exit 1 → VULNERABLE (at least one padding byte retained old data).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pairs of (requested_size, pool_slot_size) exercised by the test. */
static const struct {
    size_t req;   /* bytes the caller requests                  */
    size_t slot;  /* bytes the pool slot actually holds         */
} cases[] = {
    { 1, 2  },
    { 3, 4  },
    { 5, 8  },
    { 17, 32 },
};
#define NCASES ((int)(sizeof cases / sizeof cases[0]))

int main(void)
{
    for (int i = 0; i < NCASES; i++) {
        size_t req  = cases[i].req;
        size_t slot = cases[i].slot;

        /*
         * Step 1 – allocate a full slot-sized request and write 0xFF to every
         * byte, including the bytes that will become padding in step 2.
         */
        unsigned char *writer = (unsigned char *)malloc(slot);
        if (!writer) {
            printf("[ERROR] malloc(%zu) returned NULL (step 1, case %d)\n", slot, i);
            return 1;
        }
        memset(writer, 0xFF, slot);
        free(writer);

        /*
         * Step 2 – allocate only req bytes.  The allocator must serve this
         * from the same pool (slot bytes wide), so writer's old chunk is the
         * most likely candidate to be returned.
         */
        unsigned char *reader = (unsigned char *)malloc(req);
        if (!reader) {
            printf("[ERROR] malloc(%zu) returned NULL (step 2, case %d)\n", req, i);
            return 1;
        }

        /*
         * Step 3 – inspect the padding bytes (indices req .. slot-1).
         * If any of them still hold 0xFF, the allocator did not zero the full
         * slot and the caller can read data from the previous tenant.
         */
        for (size_t j = req; j < slot; j++) {
            if (reader[j] == 0xFF) {
                printf("[VULNERABLE] case %d (req=%zu, slot=%zu): "
                       "padding byte [%zu] is 0xFF (stale data from prior tenant)\n",
                       i, req, slot, j);
                free(reader);
                return 1;
            }
        }

        free(reader);
    }

    printf("[SAFE] all padding bytes were zeroed across %d size-confusion cases\n",
           NCASES);
    return 0;
}
