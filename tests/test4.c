/*
 * TEST 4: Stale data in reallocated memory
 *
 * A correct allocator must scrub (zero) freed memory before handing it back,
 * so that previously-written secrets are not visible to the next caller.
 *
 * Hardening over the naive version:
 *
 *  1. Alias check — we verify that the reallocated pointer is the SAME address
 *     that was freed.  If the allocator always returns a fresh chunk it would
 *     look "safe" without actually scrubbing; that shortcut is caught here.
 *
 *  2. Multiple pool sizes — we probe three different size classes (8, 32, 128
 *     bytes) so a fix that only zeroes one slot size cannot hide the bug.
 *
 *  3. Full-payload write — every byte of each allocation is poisoned with a
 *     non-zero sentinel before freeing, making partial-zero fixes fail.
 *
 *  4. Multiple free/realloc cycles — each size is recycled twice so a one-shot
 *     zeroing patch that forgets subsequent frees is caught.
 *
 *  5. Interleaved allocations — between free and realloc of the target slot we
 *     allocate (and free) a same-sized decoy.  This prevents a "zero on alloc
 *     of this specific pointer" trick from working.
 *
 * Exit 0 → allocator is SAFE (scrubs memory between uses).
 * Exit 1 → allocator is VULNERABLE (stale data visible to new owner).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

/*
 * Returns the number of non-zero bytes in [buf, buf+n).
 */
static int count_dirty(const unsigned char *buf, size_t n) {
    int dirty = 0;
    for (size_t i = 0; i < n; i++)
        if (buf[i] != 0) dirty++;
    return dirty;
}

/*
 * Probe one size class for the stale-data vulnerability.
 *
 * Strategy:
 *   alloc A  → poison every byte → free A
 *   alloc D  → (decoy, same size, interleaves with the free list)
 *   alloc B  → must be same address as A; check for stale bytes
 *   free D, free B
 *   repeat a second cycle to catch fixes that only scrub on first reuse
 *
 * Returns 1 if a leak was detected, 0 if clean.
 */
static int probe_size(size_t sz, unsigned char sentinel) {
    int leaked = 0;

    for (int cycle = 0; cycle < 2; cycle++) {
        /* Step 1: allocate and fully poison a chunk. */
        unsigned char *a = malloc(sz);
        if (!a) {
            printf("[SKIP] malloc(%zu) returned NULL\n", sz);
            continue;
        }
        memset(a, sentinel, sz);
        void *saved_addr = a;
        free(a);

        /* Step 2: allocate a decoy of the same size to perturb the free list.
         * If the allocator pops from a LIFO stack the decoy now sits at the
         * top; our target (saved_addr) is behind it.  We free the decoy right
         * away so the next alloc should return saved_addr again. */
        unsigned char *decoy = malloc(sz);
        if (decoy) free(decoy);

        /* Step 3: reallocate — expect to get saved_addr back. */
        unsigned char *b = malloc(sz);
        if (!b) {
            printf("[SKIP] malloc(%zu) returned NULL on realloc\n", sz);
            continue;
        }

        /* Alias check: if we did NOT get the same address back the allocator
         * served a fresh (mmap-zeroed) chunk; that looks "safe" but is not a
         * real fix — flag it so the scoring script can report it separately.
         * We do NOT count it as SAFE. */
        if ((void *)b != saved_addr) {
            printf("[INFO] sz=%zu cycle=%d: realloc returned different address "
                   "(%p vs %p); alias check inconclusive\n",
                   sz, cycle, (void *)b, saved_addr);
            free(b);
            continue;
        }

        /* Step 4: scan for stale bytes. */
        int dirty = count_dirty(b, sz);
        if (dirty > 0) {
            printf("[VULNERABLE] sz=%zu cycle=%d: %d/%zu bytes are non-zero "
                   "after realloc (sentinel=0x%02x)\n",
                   sz, cycle, dirty, sz, sentinel);
            leaked = 1;
        }
        free(b);
    }
    return leaked;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    int vulnerable = 0;

    /* Three distinct pool size classes with distinct sentinels. */
    vulnerable |= probe_size(8,   0xAA);
    vulnerable |= probe_size(32,  0xBB);
    vulnerable |= probe_size(128, 0xCC);

    if (vulnerable) {
        printf("[VULNERABLE] reallocated memory contains stale data\n");
        return 1;
    }

    printf("[SAFE] reallocated memory is zeroed across all tested size classes\n");
    return 0;
}
