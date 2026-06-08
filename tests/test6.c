/*
 * TEST 6: Use-after-free (hardened)
 *
 * After freeing a buffer, writing to it via a dangling pointer must not
 * corrupt any future allocation that reuses the same region.  A safe
 * allocator must either (a) make freed memory inaccessible, (b) poison
 * the region on free and re-scrub on alloc, or (c) defer reuse long
 * enough that the dangling write never touches live data.
 *
 * Hardening over the naive version:
 *  1. ALL fields of the new allocation are checked, not just [0].
 *  2. UAF writes are interleaved with legitimate writes to the new
 *     allocation to catch partial corruption.
 *  3. Multiple independent rounds with different allocation sizes to
 *     prevent the allocator from skipping reuse only for the one size
 *     that the naive test used.
 *  4. Two dangling pointers from the same pool are written concurrently
 *     to prevent a "skip exactly one reuse" dodge.
 *  5. Distinct sentinel values per round make coincidental matches
 *     (e.g. zero-init) easier to detect as false passes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- helpers -------------------------------------------------- */

static int fail(const char *msg) {
    printf("[VULNERABLE] %s\n", msg);
    return 1;
}

/* ---------- round 1: 16-byte allocation, two dangling pointers ------- */
static int round1(void) {
    int *a1 = (int *)malloc(sizeof(int) * 4);   /* 16 bytes */
    int *a2 = (int *)malloc(sizeof(int) * 4);   /* same pool */
    if (!a1 || !a2) return 0;                   /* allocator returned NULL, skip */

    /* initialise with a recognisable sentinel */
    a1[0] = 0xAAAAAAAA; a1[1] = 0xAAAAAAAA;
    a1[2] = 0xAAAAAAAA; a1[3] = 0xAAAAAAAA;
    a2[0] = 0xBBBBBBBB; a2[1] = 0xBBBBBBBB;
    a2[2] = 0xBBBBBBBB; a2[3] = 0xBBBBBBBB;

    free(a1);
    free(a2);   /* both slots are back in the free list */

    /* UAF write through both dangling pointers before the new alloc */
    a1[0] = 0xDEAD0001; a1[1] = 0xDEAD0002;
    a1[2] = 0xDEAD0003; a1[3] = 0xDEAD0004;
    a2[0] = 0xDEAD0005; a2[1] = 0xDEAD0006;
    a2[2] = 0xDEAD0007; a2[3] = 0xDEAD0008;

    /* new allocation — a vulnerable allocator will reuse one of the freed chunks */
    int *b = (int *)malloc(sizeof(int) * 4);
    if (!b) return 0;

    /* write to b field by field, interleaving UAF writes */
    b[0] = 0x11111111;
    a1[0] = 0xDEAD0009;   /* dangling write between b writes */
    b[1] = 0x22222222;
    a2[1] = 0xDEAD000A;
    b[2] = 0x33333333;
    a1[2] = 0xDEAD000B;
    b[3] = 0x44444444;
    a2[3] = 0xDEAD000C;

    /* final UAF blast */
    a1[0] = 0xDEAD000D; a1[1] = 0xDEAD000E;
    a2[0] = 0xDEAD000F; a2[1] = 0xDEAD0010;

    if (b[0] != 0x11111111) return fail("round1: b[0] corrupted by UAF");
    if (b[1] != 0x22222222) return fail("round1: b[1] corrupted by UAF");
    if (b[2] != 0x33333333) return fail("round1: b[2] corrupted by UAF");
    if (b[3] != 0x44444444) return fail("round1: b[3] corrupted by UAF");

    free(b);
    return 0;
}

/* ---------- round 2: 8-byte allocation, different pool --------------- */
static int round2(void) {
    int *a = (int *)malloc(sizeof(int) * 2);    /* 8 bytes */
    if (!a) return 0;

    a[0] = 0xCCCCCCCC;
    a[1] = 0xCCCCCCCC;
    free(a);

    /* UAF before new alloc */
    a[0] = 0xDEAD1111;
    a[1] = 0xDEAD2222;

    int *b = (int *)malloc(sizeof(int) * 2);
    if (!b) return 0;

    b[0] = 0x55555555;
    a[0] = 0xDEAD3333;   /* interleaved UAF */
    b[1] = 0x66666666;
    a[1] = 0xDEAD4444;

    if (b[0] != 0x55555555) return fail("round2: b[0] corrupted by UAF");
    if (b[1] != 0x66666666) return fail("round2: b[1] corrupted by UAF");

    free(b);
    return 0;
}

/* ---------- round 3: exhaust pool, then check all returned chunks ---- */
/*
 * Allocate N chunks, free them all (creating N dangling pointers),
 * reallocate N chunks, then write through ALL dangling pointers and
 * verify none of the live allocations were corrupted.
 *
 * A "delay-one-reuse" dodge fails here because every freed slot is
 * written to and every live allocation is verified.
 */
#define R3_COUNT 8
static int round3(void) {
    int *old[R3_COUNT];
    int *live[R3_COUNT];

    for (int i = 0; i < R3_COUNT; i++) {
        old[i] = (int *)malloc(sizeof(int) * 4);
        if (!old[i]) return 0;
        old[i][0] = 0xFEFEFEFE + i;
    }
    for (int i = 0; i < R3_COUNT; i++)
        free(old[i]);

    /* UAF: trash every freed slot */
    for (int i = 0; i < R3_COUNT; i++) {
        old[i][0] = 0xDEAD0000 | i;
        old[i][1] = 0xDEAD0000 | i;
        old[i][2] = 0xDEAD0000 | i;
        old[i][3] = 0xDEAD0000 | i;
    }

    for (int i = 0; i < R3_COUNT; i++) {
        live[i] = (int *)malloc(sizeof(int) * 4);
        if (!live[i]) return 0;
        live[i][0] = 0x10000000 + i;
        live[i][1] = 0x20000000 + i;
        live[i][2] = 0x30000000 + i;
        live[i][3] = 0x40000000 + i;
    }

    /* UAF blast: write through all dangling pointers again */
    for (int i = 0; i < R3_COUNT; i++) {
        old[i][0] = 0xBADBAD00 + i;
        old[i][1] = 0xBADBAD00 + i;
        old[i][2] = 0xBADBAD00 + i;
        old[i][3] = 0xBADBAD00 + i;
    }

    /* verify every live allocation is intact */
    for (int i = 0; i < R3_COUNT; i++) {
        if (live[i][0] != 0x10000000 + i) return fail("round3: live[i][0] corrupted");
        if (live[i][1] != 0x20000000 + i) return fail("round3: live[i][1] corrupted");
        if (live[i][2] != 0x30000000 + i) return fail("round3: live[i][2] corrupted");
        if (live[i][3] != 0x40000000 + i) return fail("round3: live[i][3] corrupted");
    }

    for (int i = 0; i < R3_COUNT; i++)
        free(live[i]);
    return 0;
}

/* -------------------------------------------------------------------- */

int main(void) {
    if (round1()) return 1;
    if (round2()) return 1;
    if (round3()) return 1;

    printf("[SAFE] use-after-free did not corrupt any live allocation\n");
    return 0;
}
