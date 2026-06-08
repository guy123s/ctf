/*
 * TEST 17: Bit-flip in size header
 *
 * Flip bits in the 4-byte size header before the pointer and verify the
 * allocator detects the corruption.  Three distinct attack scenarios are
 * exercised:
 *
 *  (a) Flip a bit so the stored size becomes a *different valid pool size*
 *      (e.g. 16 → 32).  A naive allocator routes the chunk into the wrong
 *      pool; the next malloc(16) then returns the same address again,
 *      producing a double-hand-out alias.
 *
 *  (b) Flip a bit so the stored size becomes an *invalid* value (not any
 *      pool size).  A safe allocator must detect this and signal the error;
 *      a naive one silently drops the chunk (leak) and the freed address is
 *      never reused — detectable by exhausting the pool.
 *
 *  (c) Flip bits in the high bytes of the header (bytes 1–3).  These bytes
 *      are zero for every valid pool size (all sizes fit in one byte), so
 *      any non-zero value here is unambiguously corrupt.  A safe allocator
 *      must still detect this.
 *
 * Exit 0 = SAFE (corruption was detected in every scenario).
 * Exit 1 = VULNERABLE (at least one scenario was accepted silently).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

static jmp_buf jump;
static volatile int caught_signal = 0;

static void handler(int sig) {
    (void)sig;
    caught_signal = 1;
    longjmp(jump, 1);
}

static void install_handlers(void) {
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);
    signal(SIGBUS,  handler);
}

/* ------------------------------------------------------------------ */
/* Scenario (a): bit-flip that maps header to a DIFFERENT valid size.  */
/*                                                                     */
/* malloc(16) stores header value 16 (0x10).  XOR with 0x20 gives 48, */
/* which is not a pool size — but XOR with 0x10 gives 0 (invalid) and */
/* XOR with 0x20 on the low nibble of 16=0x10 gives 0x30=48 (invalid).*/
/* The reliable cross-pool flip: 16 XOR 0x10 = 0 is invalid; use      */
/* 16 (0x10) XOR 0x20 = 0x30 = 48 (invalid).                         */
/* Better: malloc(16)=0x10, flip bit4 → 0x00 invalid; flip bit5 →     */
/* 0x30=48 invalid; flip bit 1 of byte0 → 0x12=18 invalid.            */
/*                                                                     */
/* For a truly cross-pool flip: malloc(32)=0x20, flip bit4 → 0x30=48  */
/* (invalid).  But malloc(16)=0x10, flip bit5 of byte0: 0x10^0x20=0x30*/
/* =48 (invalid).  Flip bit4 of byte0: 0x10^0x10=0x00 (invalid).      */
/*                                                                     */
/* Reliable cross-pool alias: malloc(16)=0x10, write 32 (0x20) into   */
/* header.  free() routes chunk into pool[5] (size=32).  Next          */
/* malloc(32) returns that same address → alias with the still-live    */
/* malloc(16) buffer.                                                  */
/* ------------------------------------------------------------------ */
static int scenario_a(void) {
    caught_signal = 0;
    install_handlers();

    if (setjmp(jump) != 0) {
        /* crash = allocator detected the corruption */
        return 1; /* SAFE */
    }

    char *a = (char *)malloc(16);
    if (!a) return 1; /* can't test */

    /* Overwrite header: change stored size from 16 to 32 (next pool). */
    *(unsigned int *)(a - 4) = 32;

    /* free() will push 'a' onto pool[5] (size=32) instead of pool[4] */
    free(a);

    /*
     * Now malloc(32) should return 'a' if the flip was accepted — an
     * alias: the caller still holds 'a' (notionally) and now gets it
     * again from a different pool.
     *
     * Additionally, malloc(16) must NOT return 'a' (the pool[4] slot
     * was never returned, so pool[4] lost a slot permanently).
     * We exhaust pool[4] to see if it is one short.
     */
    int pool4_slots = 4096 / (16 + 4); /* POOL_SIZE / (size + HEADER_SIZE) */

    char *alias = (char *)malloc(32);

    /* Drain all legitimate pool[4] slots */
    char *drain[pool4_slots];
    int got = 0;
    for (int i = 0; i < pool4_slots; i++) {
        drain[i] = (char *)malloc(16);
        if (drain[i]) got++;
    }

    int vulnerable = 0;

    /* alias == a → the corrupted free was accepted, aliasing occurred */
    if (alias == a) {
        printf("[VULNERABLE] scenario(a): cross-pool alias: malloc(32) "
               "returned the same address as live malloc(16) buffer\n");
        vulnerable = 1;
    }

    /* If pool[4] is short by exactly one slot, the chunk was silently
     * stolen into pool[5] without detection.                          */
    if (got < pool4_slots) {
        printf("[VULNERABLE] scenario(a): pool[4] lost a slot after "
               "cross-pool header flip (got %d/%d)\n", got, pool4_slots);
        vulnerable = 1;
    }

    /* cleanup — best-effort, pool state may be corrupt */
    if (alias) free(alias);
    for (int i = 0; i < got; i++) if (drain[i]) free(drain[i]);

    return vulnerable ? 0 : 1; /* 0 = vulnerable, 1 = safe */
}

/* ------------------------------------------------------------------ */
/* Scenario (b): bit-flip to an INVALID size (no matching pool).       */
/*                                                                     */
/* free() must detect the bad header and crash/abort.  If it silently  */
/* drops the chunk the freed slot is lost, detectable by exhausting    */
/* the pool and finding it one slot short.                             */
/* ------------------------------------------------------------------ */
static int scenario_b(void) {
    caught_signal = 0;
    install_handlers();

    if (setjmp(jump) != 0) {
        return 1; /* crash = SAFE */
    }

    char *a = (char *)malloc(64);
    if (!a) return 1;

    /* 64 XOR 0x08 = 72, which is not a power-of-two pool size */
    unsigned char *hdr = (unsigned char *)(a - 4);
    hdr[0] ^= 0x08;

    free(a);

    /*
     * If free() silently dropped the chunk, pool[6] (size=64) is now
     * one slot short.  Exhaust it and check.
     */
    int pool6_slots = 4096 / (64 + 4);
    char *drain[pool6_slots];
    int got = 0;
    for (int i = 0; i < pool6_slots; i++) {
        drain[i] = (char *)malloc(64);
        if (drain[i]) got++;
    }

    /* An extra malloc(64) must return NULL (pool exhausted) if the
     * chunk was silently dropped; if it returns non-NULL then the slot
     * was reused which is impossible if the header was corrupt —
     * meaning the allocator somehow healed itself (unexpected, treat
     * as safe for this sub-check).                                    */
    int vulnerable = 0;
    if (got < pool6_slots) {
        printf("[VULNERABLE] scenario(b): pool[6] lost a slot after "
               "invalid bit-flip on free (got %d/%d)\n", got, pool6_slots);
        vulnerable = 1;
    }

    for (int i = 0; i < got; i++) if (drain[i]) free(drain[i]);
    return vulnerable ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* Scenario (c): flip a bit in the HIGH bytes (bytes 1–3) of header.  */
/*                                                                     */
/* All valid pool sizes (1–512) fit in byte 0; bytes 1–3 are always 0.*/
/* Flipping any bit there gives a size > 255, which matches no pool.  */
/* A safe allocator detects this.  A naive one silently drops chunk.   */
/* ------------------------------------------------------------------ */
static int scenario_c(void) {
    /*
     * Test each of the three high bytes independently.  Any one that
     * passes without a crash is a vulnerability.
     */
    unsigned int flip_positions[] = { 1, 2, 3 }; /* byte indices */
    int all_safe = 1;

    for (int fi = 0; fi < 3; fi++) {
        int byte_idx = flip_positions[fi];

        caught_signal = 0;
        install_handlers();

        if (setjmp(jump) != 0) {
            /* crash on this byte = safe, try next */
            continue;
        }

        char *a = (char *)malloc(128);
        if (!a) continue;

        unsigned char *hdr = (unsigned char *)(a - 4);
        hdr[byte_idx] ^= 0x01; /* flip lowest bit of that byte */

        free(a);

        /* If we reach here free() accepted the corrupt header silently.
         * Verify the slot was lost from pool[7] (size=128).           */
        int pool7_slots = 4096 / (128 + 4);
        char *drain[pool7_slots];
        int got = 0;
        for (int i = 0; i < pool7_slots; i++) {
            drain[i] = (char *)malloc(128);
            if (drain[i]) got++;
        }

        if (got < pool7_slots) {
            printf("[VULNERABLE] scenario(c): pool[7] lost a slot after "
                   "flip in header byte %d (got %d/%d)\n",
                   byte_idx, got, pool7_slots);
            all_safe = 0;
        }

        for (int i = 0; i < got; i++) if (drain[i]) free(drain[i]);

        /* Re-install handlers for next iteration */
        install_handlers();
    }

    return all_safe ? 1 : 0;
}

/* ------------------------------------------------------------------ */

int main(void) {
    int sa = scenario_a();
    int sb = scenario_b();
    int sc = scenario_c();

    if (sa && sb && sc) {
        printf("[SAFE] bit-flip header corruption detected in all scenarios\n");
        return 0;
    }

    /* At least one scenario was not detected */
    if (!sa) printf("[VULNERABLE] scenario(a): cross-pool alias via header flip\n");
    if (!sb) printf("[VULNERABLE] scenario(b): invalid-size flip silently dropped\n");
    if (!sc) printf("[VULNERABLE] scenario(c): high-byte flip silently dropped\n");
    return 1;
}
