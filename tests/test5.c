/*
 * TEST 5: Metadata corruption → wrong pool free
 *
 * The allocator stores a size header just before the returned pointer.
 * Overwriting it with a DIFFERENT valid pool size causes free() to put
 * the chunk into the wrong pool.  The next malloc() from that pool then
 * returns a chunk that overlaps the original allocation (aliasing) or
 * that lands inside a pool whose slot layout does not match, corrupting
 * unrelated live data.
 *
 * A safe allocator must detect header tampering — e.g. via a checksum,
 * canary, or out-of-band metadata — rather than blindly trusting the
 * user-writable size field.
 *
 * Hardened checks
 * ───────────────
 *  1. Corrupt the header to EVERY other valid pool size (both smaller
 *     and larger), not just one hand-picked value.
 *  2. After each wrong-pool free, drain that wrong pool completely and
 *     check every returned pointer for aliasing with the original chunk.
 *  3. Write a known pattern into a live neighbour before the attack and
 *     verify it is intact afterwards (cross-pool clobber detection).
 *  4. Repeat the entire sequence for several base allocation sizes so
 *     that a trivial "ignore size=1" bypass does not suffice.
 *  5. Return VULNERABLE (exit 1) on the first sign of trouble;
 *     return SAFE (exit 0) only if all probes pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* All valid pool sizes the allocator knows about (1<<0 … 1<<9). */
static const int POOL_SIZES[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
#define NUM_POOLS 10

/*
 * do_corrupt_probe – allocate a chunk of `alloc_size`, corrupt its header
 * to `fake_size`, free it, then drain up to `drain_limit` allocations from
 * the wrong pool and look for aliasing or neighbour clobber.
 *
 * Returns 1 (VULNERABLE) as soon as anything looks wrong, 0 otherwise.
 */
static int do_corrupt_probe(size_t alloc_size, int fake_size, int drain_limit)
{
    /* Allocate the victim and two neighbours to catch clobber. */
    char *before = (char *)malloc(alloc_size);
    char *victim  = (char *)malloc(alloc_size);
    char *after   = (char *)malloc(alloc_size);

    if (!before || !victim || !after) {
        /* Allocator returned NULL — pools exhausted; skip this probe. */
        if (before) free(before);
        if (victim)  free(victim);
        if (after)   free(after);
        return 0;
    }

    /* Stamp neighbours with a recognisable pattern. */
    memset(before, 0xAA, alloc_size);
    memset(after,  0xBB, alloc_size);

    /* Corrupt victim's size header. */
    *(int *)(victim - 4) = fake_size;

    /* Free through the corrupted header — wrong pool if undetected. */
    free(victim);

    /*
     * Drain `drain_limit` allocations of `fake_size` bytes.
     * If the allocator was fooled, one of these may alias `victim`.
     */
    char *drawn[64];
    int n = 0;
    for (int i = 0; i < drain_limit && i < 64; i++) {
        char *p = (char *)malloc(fake_size);
        if (!p) break;
        drawn[n++] = p;

        /* Alias check: does p overlap [victim, victim+alloc_size)? */
        if (p < victim + (int)alloc_size && p + fake_size > victim) {
            printf("[VULNERABLE] alloc_size=%zu fake_size=%d: "
                   "drawn ptr %p aliases victim %p\n",
                   alloc_size, fake_size, (void *)p, (void *)victim);
            /* Clean up best-effort. */
            for (int j = 0; j < n; j++) free(drawn[j]);
            free(before);
            free(after);
            return 1;
        }

        /* Write into the drawn chunk and check neighbours for clobber. */
        memset(p, 0x55, fake_size);
    }

    /* Neighbour integrity check. */
    for (size_t k = 0; k < alloc_size; k++) {
        if ((unsigned char)before[k] != 0xAA) {
            printf("[VULNERABLE] alloc_size=%zu fake_size=%d: "
                   "'before' neighbour corrupted at offset %zu\n",
                   alloc_size, fake_size, k);
            for (int j = 0; j < n; j++) free(drawn[j]);
            free(before);
            free(after);
            return 1;
        }
        if ((unsigned char)after[k] != 0xBB) {
            printf("[VULNERABLE] alloc_size=%zu fake_size=%d: "
                   "'after' neighbour corrupted at offset %zu\n",
                   alloc_size, fake_size, k);
            for (int j = 0; j < n; j++) free(drawn[j]);
            free(before);
            free(after);
            return 1;
        }
    }

    for (int j = 0; j < n; j++) free(drawn[j]);
    free(before);
    free(after);
    return 0;
}

int main(void)
{
    /*
     * For each base allocation size, try corrupting the header to every
     * OTHER valid pool size.  Drain enough chunks from the wrong pool to
     * be confident the victim slot would surface if it were mislaid.
     */
    const size_t base_sizes[] = {1, 4, 16, 64, 128};
    const int num_bases = (int)(sizeof base_sizes / sizeof base_sizes[0]);

    for (int b = 0; b < num_bases; b++) {
        size_t alloc_size = base_sizes[b];

        /* Find this size's canonical pool size (first pool_size >= alloc_size). */
        int canonical = -1;
        for (int pi = 0; pi < NUM_POOLS; pi++) {
            if ((size_t)POOL_SIZES[pi] >= alloc_size) {
                canonical = POOL_SIZES[pi];
                break;
            }
        }
        if (canonical == -1) continue; /* size > 512: allocator returns NULL anyway */

        for (int pi = 0; pi < NUM_POOLS; pi++) {
            int fake = POOL_SIZES[pi];
            if (fake == canonical) continue; /* same pool — not a corruption */

            /*
             * Drain enough slots to surface the misplaced chunk.
             * Each pool holds POOL_SIZE/(slot_size+4) slots ≤ 4096/5 ≈ 819.
             * Draining 32 is sufficient to catch the return with high
             * confidence without exhausting pool memory in the test.
             */
            if (do_corrupt_probe(alloc_size, fake, 32))
                return 1;
        }
    }

    printf("[SAFE] header corruption was detected or prevented across all probes\n");
    return 0;
}
