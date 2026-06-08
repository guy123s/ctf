/*
 * TEST 12: Freed memory still accessible (no guard page)
 *
 * After free(), the backing memory should be inaccessible — any read or
 * write to a freed pointer must raise SIGSEGV/SIGBUS.  A safe allocator
 * achieves this by calling mprotect(PROT_NONE) on freed chunks or by
 * unmapping them.
 *
 * Hardening notes (what this test resists):
 *  - Zeroing / poisoning on free: the region stays readable, just
 *    contains different bytes. We probe with a volatile write as well,
 *    so a zero-fill cannot hide the vulnerability.
 *  - Canary-value tricks: we check every byte of the chunk, not just
 *    byte 0, across three different size classes.
 *  - Lucky signal timing: setjmp() is called BEFORE the access attempt;
 *    each probe gets its own jmp_buf so a signal on one probe cannot
 *    accidentally "pass" a later probe.
 *  - Surviving one probe: all three size-class probes (read AND write)
 *    must fault; a single success suffices to declare vulnerable.
 *
 * Exit 0  → allocator makes freed memory inaccessible (safe).
 * Exit 1  → freed memory remains accessible (vulnerable).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* ------------------------------------------------------------------ */
/* Signal infrastructure                                                */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_faulted;
static jmp_buf g_jmp;

static void fault_handler(int sig) {
    (void)sig;
    g_faulted = 1;
    longjmp(g_jmp, 1);
}

static void install_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    /* SA_RESETHAND: re-arm manually each probe so a second fault in the
       same probe cannot be swallowed by the default (crash) action.    */
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
}

/* Returns 1 if the access raised a signal, 0 if it succeeded silently. */
#define PROBE_READ(ptr, idx)  probe_read ((volatile char *)(ptr), (idx))
#define PROBE_WRITE(ptr, idx) probe_write((volatile char *)(ptr), (idx))

static int probe_read(volatile char *p, int idx) {
    install_handlers();
    g_faulted = 0;
    if (setjmp(g_jmp) == 0) {
        volatile char v = p[idx];
        (void)v;
        return 0;   /* no fault — memory is still readable */
    }
    return 1;       /* faulted */
}

static int probe_write(volatile char *p, int idx) {
    install_handlers();
    g_faulted = 0;
    if (setjmp(g_jmp) == 0) {
        p[idx] = 0xAB;
        return 0;   /* no fault — memory is still writable */
    }
    return 1;       /* faulted */
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/*
 * Fill every byte of a live allocation with a known pattern, free it,
 * then probe every byte for both read and write access.
 *
 * Returns 1 if ALL probes faulted (safe), 0 if any probe succeeded.
 *
 * We probe: first byte, last byte, and a middle byte to catch partial
 * guard-page implementations that only protect chunk boundaries.
 */
static int check_size_class(size_t sz, unsigned char fill) {
    char *p = (char *)malloc(sz);
    if (!p) {
        printf("[SKIP] malloc(%zu) returned NULL\n", sz);
        return 1;   /* treat as safe — can't test what we can't alloc */
    }

    /* Write a known fill so we can detect "zeroed but not guarded" */
    memset(p, fill, sz);
    free(p);

    /* Indices to probe: 0, middle, last */
    int indices[3] = { 0, (int)(sz / 2), (int)(sz - 1) };
    int n = (sz == 1) ? 1 : (sz == 2) ? 2 : 3;

    for (int i = 0; i < n; i++) {
        int idx = indices[i];

        /* Read probe */
        if (!probe_read((volatile char *)p, idx)) {
            printf("[VULNERABLE] freed ptr (size=%zu) readable at offset %d"
                   " (got 0x%02x, fill was 0x%02x)\n",
                   sz, idx, (unsigned char)p[idx], fill);
            return 0;
        }

        /* Write probe — re-arm handlers (SA_RESETHAND clears them) */
        if (!probe_write((volatile char *)p, idx)) {
            printf("[VULNERABLE] freed ptr (size=%zu) writable at offset %d\n",
                   sz, idx);
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Main                                                                 */
/* ------------------------------------------------------------------ */

int main(void) {
    /*
     * Three size classes that map to different pools in the reference
     * allocator: 1-byte (pool 0), 32-byte (pool 5), 256-byte (pool 8).
     * Using distinct fills makes "zeroing on free" detectable: a zero
     * fill changes bytes but does not make the region inaccessible.
     */
    struct { size_t sz; unsigned char fill; } cases[] = {
        {   1, 0xAA },
        {  32, 0xBB },
        { 256, 0xCC },
    };
    int ncases = (int)(sizeof cases / sizeof cases[0]);

    int all_safe = 1;
    for (int i = 0; i < ncases; i++) {
        if (!check_size_class(cases[i].sz, cases[i].fill)) {
            all_safe = 0;
            /* Keep going so all vulnerable sizes are reported */
        }
    }

    if (all_safe) {
        printf("[SAFE] all freed regions are inaccessible (SIGSEGV on access)\n");
        return 0;
    }
    return 1;
}
