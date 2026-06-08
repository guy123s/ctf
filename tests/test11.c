/*
 * TEST 11: Header metadata exposure (hardened)
 *
 * The allocator stores pool metadata in the 4 bytes immediately before
 * the returned pointer.  A safe allocator must not let users learn
 * allocator internals through ANY of these four channels:
 *
 *   (A) Direct read  — ptr[-4] contains a recognisable power-of-2 pool size.
 *   (B) Delta inference — consecutive same-class allocations are separated by
 *       exactly (pool_size + HEADER_SIZE), leaking both the size class and
 *       the header width without ever touching header bytes.
 *   (C) Slot-count inference — exhausting a pool and counting how many slots
 *       it held lets the attacker compute pool_size = POOL_SIZE / count -
 *       HEADER_SIZE, leaking the internal pool geometry.
 *   (D) Stale header persistence — allocating, writing a sentinel to the
 *       header region, freeing, and re-allocating the same slot should NOT
 *       return the sentinel value unchanged; a safe allocator scrubs or
 *       re-keys per-allocation metadata.
 *
 * The test reports [VULNERABLE] (exits 1) if ANY channel leaks information.
 * It reports [SAFE] (exits 0) only when every channel is closed.
 *
 * NOTE: The test does NOT know what the safe obfuscation scheme looks like.
 * It only checks observable behaviour from the user's perspective.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int is_power_of_two_in_range(int v)
{
    /* covers all pool sizes 1..512 */
    for (int s = 1; s <= 512; s <<= 1)
        if (v == s) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* (A) Direct header read                                              */
/* ------------------------------------------------------------------ */
static int check_direct_read(void)
{
    char *a = (char *)malloc(10);
    if (!a) return 0; /* can't check */

    int header = *(int *)(a - 4);
    int exposed = is_power_of_two_in_range(header);

    free(a);

    if (exposed) {
        printf("[VULNERABLE] (A) ptr[-4] == %d — raw pool size is readable\n",
               header);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* (B) Address-delta inference                                         */
/*                                                                     */
/* Allocate many same-class buffers and collect their addresses.       */
/* If every consecutive pair is separated by a constant stride that    */
/* equals (some_power_of_two + some_small_header), the attacker can   */
/* read off both the pool size and the header width.                   */
/*                                                                     */
/* "Small header" means <= 32 bytes, which covers any reasonable       */
/* fixed-size tag.  A randomised or pointer-disguising allocator would */
/* not have a constant stride at all.                                  */
/* ------------------------------------------------------------------ */
#define DELTA_SAMPLES 8

static int check_delta_inference(void)
{
    char *ptrs[DELTA_SAMPLES];
    for (int i = 0; i < DELTA_SAMPLES; i++) {
        ptrs[i] = (char *)malloc(10);
        if (!ptrs[i]) {
            /* clean up and skip */
            for (int j = 0; j < i; j++) free(ptrs[j]);
            return 0;
        }
    }

    /* compute absolute deltas between consecutive pointers */
    intptr_t first_delta = 0;
    int constant_stride = 1;
    for (int i = 1; i < DELTA_SAMPLES; i++) {
        intptr_t d = (intptr_t)ptrs[i] - (intptr_t)ptrs[i - 1];
        if (d < 0) d = -d;
        if (i == 1) {
            first_delta = d;
        } else if (d != first_delta) {
            constant_stride = 0;
            break;
        }
    }

    for (int i = 0; i < DELTA_SAMPLES; i++) free(ptrs[i]);

    if (!constant_stride || first_delta == 0) return 0;

    /* check whether the stride is (power-of-two + plausible header) */
    for (int s = 1; s <= 512; s <<= 1) {
        for (int h = 1; h <= 32; h++) {
            if (first_delta == (intptr_t)(s + h)) {
                printf("[VULNERABLE] (B) consecutive same-class allocs have "
                       "constant stride %td = %d + %d — pool geometry leaked "
                       "via address arithmetic\n",
                       first_delta, s, h);
                return 1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* (C) Slot-count inference                                            */
/*                                                                     */
/* Drain the pool for a small size class until malloc returns NULL,    */
/* count how many slots existed, and verify whether                    */
/*   slots * (size + header) == some_known_pool_byte_size              */
/* is consistent with any (pool_bytes, header_bytes) pair the         */
/* attacker might guess.  If yes, the attacker now knows both the      */
/* pool byte size and the internal header width.                       */
/*                                                                     */
/* We check against pool byte sizes 1 KB – 64 KB (reasonable range)   */
/* and header sizes 1 – 32 bytes.                                      */
/* ------------------------------------------------------------------ */
#define SLOT_DRAIN_MAX 4096

static int check_slot_count(void)
{
    char **slots = (char **)malloc(sizeof(char *) * SLOT_DRAIN_MAX);
    if (!slots) return 0;

    /* use size 1 — smallest class, most slots, fastest drain */
    int count = 0;
    while (count < SLOT_DRAIN_MAX) {
        char *p = (char *)malloc(1);
        if (!p) break;
        slots[count++] = p;
    }

    /* return everything */
    for (int i = 0; i < count; i++) free(slots[i]);
    free(slots);

    if (count == 0) return 0;

    /* does (count * (1 + h)) match any plausible pool_bytes? */
    for (int h = 1; h <= 32; h++) {
        intptr_t pool_implied = (intptr_t)count * (1 + h);
        /* Check 1 KB to 64 KB in power-of-two steps */
        for (intptr_t pb = 1024; pb <= 65536; pb <<= 1) {
            if (pool_implied == pb) {
                printf("[VULNERABLE] (C) drained %d slots of size 1; "
                       "count * (1 + %d) = %td matches a plausible pool size "
                       "— internal geometry inferred by exhaustion\n",
                       count, h, pool_implied);
                return 1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* (D) Stale header persistence                                        */
/*                                                                     */
/* Allocate a buffer, stamp the 4 bytes before it with a sentinel,    */
/* free it, re-allocate the same slot, and read those 4 bytes again.  */
/* If the sentinel survives, the allocator never refreshes the header  */
/* between allocations — a stale metadata oracle.                      */
/*                                                                     */
/* To ensure we get the same slot back we drain all but one slot of    */
/* that size class first, then free and immediately re-alloc.         */
/* ------------------------------------------------------------------ */
#define SENTINEL 0xDEADBEEF

static int check_stale_header(void)
{
    /* Warm up: drain almost all size-2 slots so we control exactly one. */
    char *drain[SLOT_DRAIN_MAX];
    int n = 0;
    while (n < SLOT_DRAIN_MAX) {
        char *p = (char *)malloc(2);
        if (!p) break;
        drain[n++] = p;
    }
    if (n == 0) return 0;

    /* Keep all but the last slot drained; free only the last one. */
    char *victim = drain[n - 1];
    n--;

    /* Stamp a sentinel into victim's header before freeing. */
    *(unsigned int *)(victim - 4) = SENTINEL;
    free(victim);

    /* Re-allocate from the same (now only-free) slot. */
    char *recycled = (char *)malloc(2);

    int stale = 0;
    if (recycled) {
        unsigned int hdr_after = *(unsigned int *)(recycled - 4);
        if (hdr_after == SENTINEL) {
            printf("[VULNERABLE] (D) header sentinel 0x%08X survived free+realloc "
                   "— metadata is never refreshed between allocations\n",
                   SENTINEL);
            stale = 1;
        }
        free(recycled);
    }

    for (int i = 0; i < n; i++) free(drain[i]);
    return stale;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    int vuln = 0;

    vuln |= check_direct_read();
    vuln |= check_delta_inference();
    vuln |= check_slot_count();
    vuln |= check_stale_header();

    if (!vuln) {
        printf("[SAFE] no metadata channel leaked allocator internals\n");
        return 0;
    }
    return 1;
}
