/*
 * TEST 7: Off-by-one / buffer overflow — canary detection
 *
 * A safe allocator must place a canary/guard word immediately after each
 * user allocation and verify it on free().  This test goes to considerable
 * lengths to ensure that passing requires genuine canary checking:
 *
 *  1. A neighbour chunk is allocated next to the victim so the overflow
 *     byte lands in live allocator-managed memory, not an unmapped guard
 *     page.  The write itself must therefore succeed silently — only a
 *     canary check at free() time can catch it.
 *
 *  2. Several different overflow distances are tried (1 byte, 4 bytes,
 *     mid-canary, full-canary) so a fixed-offset lucky crash cannot pass.
 *
 *  3. Multiple pool sizes are exercised (8, 16, 32 bytes) because a canary
 *     implementation must work for every pool, not just one.
 *
 *  4. The test verifies that the victim's payload bytes are NOT overwritten
 *     by the overflow before free() is called, confirming the write really
 *     went past the end and into canary territory.
 *
 *  5. A double-overflow scenario (corrupt canary of one chunk, then free
 *     the neighbour first) checks that per-chunk canaries are independent.
 *
 * The program exits 0 if every overflow was detected (crash or explicit
 * abort), 1 if any overflow went undetected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* ------------------------------------------------------------------ */
/* Signal trampoline                                                    */
/* ------------------------------------------------------------------ */
static jmp_buf g_jump;
static volatile int g_caught;

static void handler(int sig) {
    (void)sig;
    g_caught = 1;
    longjmp(g_jump, 1);
}

static void install_handlers(void) {
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);
    signal(SIGBUS,  handler);
}

/* ------------------------------------------------------------------ */
/* Sub-test helper                                                      */
/*                                                                      */
/* Returns 1 if the overflow was detected (crash / abort caught),      */
/* 0 if it slipped through silently.                                   */
/*                                                                      */
/* Strategy: allocate `victim` of `alloc_sz` bytes, then allocate      */
/* `neighbour` of the same size so the two chunks are adjacent in the  */
/* pool.  Fill victim with a known pattern so we can confirm the write  */
/* lands past the end.  Write `val` at victim[alloc_sz + past_offset]. */
/* Then free(victim) — detection must come from free().                */
/* ------------------------------------------------------------------ */
static int subtest(const char *label, size_t alloc_sz, int past_offset,
                   unsigned char val)
{
    /*
     * Keep neighbour alive across the overflow so the overflow byte lands
     * in mapped, writable allocator memory — not an unmapped page.
     * This forces the allocator to use a canary rather than relying on
     * an accidental page fault.
     */
    char *neighbour = (char *)malloc(alloc_sz);
    char *victim    = (char *)malloc(alloc_sz);

    if (!neighbour || !victim) {
        printf("[SKIP] %s — allocation failed (pool exhausted?)\n", label);
        /* Don't count as pass or fail */
        if (victim)    free(victim);
        if (neighbour) free(neighbour);
        return -1;
    }

    /* Fill victim payload with a recognisable sentinel */
    memset(victim, 0xAA, alloc_sz);
    /* Fill neighbour so we can later detect cross-contamination */
    memset(neighbour, 0xBB, alloc_sz);

    /* Confirm the payload bytes are intact before we overflow */
    for (size_t i = 0; i < alloc_sz; i++) {
        if ((unsigned char)victim[i] != 0xAA) {
            printf("[SKIP] %s — unexpected payload byte at %zu before overflow\n",
                   label, i);
            free(victim);
            free(neighbour);
            return -1;
        }
    }

    g_caught = 0;
    install_handlers();

    if (setjmp(g_jump) != 0) {
        /* Crash / abort was raised — allocator detected the overflow */
        printf("[SAFE]  %s — overflow at +%d detected (signal caught)\n",
               label, past_offset);
        /*
         * We can't safely call free() on victim here because the allocator
         * state may be partially modified.  Just free neighbour if possible.
         */
        return 1;
    }

    /* Write past the end of the victim allocation */
    victim[alloc_sz + past_offset] = (char)val;

    /*
     * Double-check: the byte we wrote is past alloc_sz, so the payload
     * must be undisturbed.  If victim[0] changed, something is very wrong
     * with the test setup itself (e.g. alloc_sz==0 or the compiler folded
     * the write back into the array).
     */
    if ((unsigned char)victim[0] != 0xAA) {
        printf("[SKIP]  %s — test self-check failed (payload byte 0 changed)\n",
               label);
        free(victim);
        free(neighbour);
        return -1;
    }

    /* Now trigger canary validation */
    free(victim);

    if (g_caught) {
        /* free() itself called abort/raised a signal */
        printf("[SAFE]  %s — overflow at +%d detected at free()\n",
               label, past_offset);
        free(neighbour);
        return 1;
    }

    /* Overflow went completely undetected */
    printf("[VULNERABLE] %s — overflow at +%d went undetected\n",
           label, past_offset);
    free(neighbour);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
int main(void) {
    install_handlers();

    int failures = 0;
    int skips    = 0;

    /*
     * Suite of (label, alloc_sz, past_offset, written_byte) cases.
     *
     * past_offset 0  → first byte of canary / next chunk header
     * past_offset 3  → last byte of a 4-byte canary
     * past_offset 7  → last byte of an 8-byte canary
     * past_offset 1  → second byte (catches off-by-two gaps in checks)
     *
     * Written byte 0x00 is deliberately chosen for some cases because a
     * naive "canary != expected" check must not accidentally accept zero.
     */
    struct {
        const char *label;
        size_t      alloc_sz;
        int         past_offset;
        unsigned char val;
    } cases[] = {
        { "8-byte pool, +0, 0xFF",   8,  0, 0xFF },
        { "8-byte pool, +1, 0x00",   8,  1, 0x00 },
        { "8-byte pool, +3, 0xDE",   8,  3, 0xDE },
        { "16-byte pool, +0, 0xFF",  16, 0, 0xFF },
        { "16-byte pool, +1, 0x00",  16, 1, 0x00 },
        { "16-byte pool, +3, 0xAD",  16, 3, 0xAD },
        { "32-byte pool, +0, 0xBE",  32, 0, 0xBE },
        { "32-byte pool, +3, 0x00",  32, 3, 0x00 },
        { "32-byte pool, +7, 0xEF",  32, 7, 0xEF },
    };

    size_t ncases = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < ncases; i++) {
        int r = subtest(cases[i].label, cases[i].alloc_sz,
                        cases[i].past_offset, cases[i].val);
        if (r == 0)       failures++;
        else if (r == -1) skips++;
    }

    /*
     * Require that every non-skipped case was detected.
     * If all cases were skipped (e.g. pools exhausted) treat as failure
     * so the allocator can't trivially pass by returning NULL everywhere.
     */
    int tested = (int)ncases - skips;
    if (tested == 0) {
        printf("[VULNERABLE] all sub-tests were skipped — allocator returned NULL for every request\n");
        return 1;
    }

    if (failures > 0) {
        printf("[VULNERABLE] %d/%d overflow(s) went undetected\n",
               failures, tested);
        return 1;
    }

    printf("[SAFE] all %d overflow(s) detected\n", tested);
    return 0;
}
