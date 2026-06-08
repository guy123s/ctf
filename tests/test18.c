/*
 * TEST 18: Fake chunk forgery — hardened
 *
 * The allocator trusts the 4-byte header before the pointer to select the
 * pool on free().  An attacker can write a valid-looking header at an
 * arbitrary location and free an interior (or completely alien) pointer,
 * injecting a fake chunk into a free list.  On the next allocation from
 * that pool the allocator may hand out a pointer that aliases an existing
 * live allocation.
 *
 * Hardening over the naive version:
 *
 *  (a) Multiple forgery sites and sizes — one probe is not enough to pass.
 *  (b) The forged free happens on pointers that were NEVER returned by
 *      malloc, so an arena-range check alone is insufficient to catch it.
 *  (c) After each forged free we drain the target pool (up to its capacity)
 *      and look for any returned pointer that aliases a live buffer.  The
 *      test therefore catches lazy/stale entries as well as immediate ones.
 *  (d) Cross-allocation forgery: we forge a 32-byte header inside a 64-byte
 *      buffer and check that subsequent malloc(32) never aliases the source.
 *  (e) We verify that the allocator is still functional after the attacks
 *      (no silent corruption of the free list that just happens to not
 *      return an overlapping pointer this run).
 *  (f) The SIGSEGV/SIGABRT handler is kept only as a last-resort safety net;
 *      a crash during the forged free is NOT treated as "safe" on its own —
 *      the test must prove the allocator rejects the forgery without crashing
 *      normal subsequent allocations.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* ------------------------------------------------------------------ */
/* Signal safety net                                                    */
/* ------------------------------------------------------------------ */
static jmp_buf jump;
static int in_probe = 0;   /* set while doing something dangerous */

static void handler(int sig) {
    (void)sig;
    if (in_probe) longjmp(jump, 1);
    /* crash outside a probe — allocator is broken in a non-recoverable way */
    _exit(1);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/* Returns 1 if [ptr, ptr+len) overlaps with any live buffer in the   */
/* array bufs[0..n), each of which is buf_size bytes wide.             */
static int overlaps_any(void *ptr, size_t len,
                        void **bufs, int n, size_t buf_size) {
    char *p = (char *)ptr;
    for (int i = 0; i < n; i++) {
        if (!bufs[i]) continue;
        char *b = (char *)bufs[i];
        /* overlap iff the intervals intersect */
        if (p < b + (long)buf_size && p + (long)len > b)
            return 1;
    }
    return 0;
}

/* Drain up to max_drain allocations of the given size, check each     */
/* for aliasing against the live set.  Returns 1 if aliasing found.    */
static int drain_and_check(size_t alloc_size, void **live, int nlive,
                            size_t live_sz, void **drain_out, int *drained) {
    /* Pool capacity: POOL_SIZE / (size + HEADER_SIZE).
     * For size=16: 4096/20 = 204.  For size=32: 4096/36 = 113.
     * Over-allocate to 512 to be safe — NULL terminates the loop. */
    int cap = 512;
    *drained = 0;
    for (int i = 0; i < cap; i++) {
        void *p = malloc(alloc_size);
        if (!p) break;
        drain_out[*drained] = p;
        (*drained)++;
        if (overlaps_any(p, alloc_size, live, nlive, live_sz))
            return 1;   /* aliasing found */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
int main(void) {
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);

    int vulnerable = 0;

    /* ============================================================
     * Attack 1: forge a 16-byte header at multiple interior offsets
     *           inside a 64-byte allocation, then drain malloc(16).
     * ============================================================ */
    {
        /* Keep several live 64-byte buffers so aliasing is detectable. */
        enum { NLIVE = 4 };
        void *live[NLIVE];
        for (int i = 0; i < NLIVE; i++) {
            live[i] = malloc(64);
            if (!live[i]) { printf("[SKIP] allocation failed\n"); return 0; }
            memset(live[i], 'L', 64);
        }

        /* Try forging at five different interior offsets. */
        int offsets[] = { 4, 12, 20, 28, 36 };
        for (int oi = 0; oi < (int)(sizeof(offsets)/sizeof(offsets[0])); oi++) {
            int off = offsets[oi];
            char *base = (char *)live[oi % NLIVE];

            /* Plant a fake 16-byte header at base+off; free base+off+4. */
            *(int *)(base + off) = 16;

            in_probe = 1;
            int jumped = setjmp(jump);
            if (!jumped) {
                free(base + off + 4);   /* forged free */
            }
            in_probe = 0;
            /* Whether it crashed or not, drain the 16-byte pool. */

            void *drained[512];
            int nd = 0;
            if (drain_and_check(16, live, NLIVE, 64, drained, &nd)) {
                vulnerable = 1;
                for (int j = 0; j < nd; j++) if (drained[j]) free(drained[j]);
                goto attack1_done;
            }
            for (int j = 0; j < nd; j++) if (drained[j]) free(drained[j]);
        }
attack1_done:
        for (int i = 0; i < NLIVE; i++) if (live[i]) free(live[i]);
    }

    if (vulnerable) {
        printf("[VULNERABLE] fake interior chunk forged into free list\n");
        return 1;
    }

    /* ============================================================
     * Attack 2: cross-size forgery.
     *           Forge a 32-byte header inside a 64-byte buffer and
     *           check that malloc(32) never aliases the live buffer.
     * ============================================================ */
    {
        enum { NLIVE = 4 };
        void *live[NLIVE];
        for (int i = 0; i < NLIVE; i++) {
            live[i] = malloc(64);
            if (!live[i]) { printf("[SKIP] allocation failed\n"); return 0; }
            memset(live[i], 'C', 64);
        }

        int offsets[] = { 8, 16, 24 };
        for (int oi = 0; oi < (int)(sizeof(offsets)/sizeof(offsets[0])); oi++) {
            int off = offsets[oi];
            char *base = (char *)live[oi % NLIVE];

            *(int *)(base + off) = 32;

            in_probe = 1;
            int jumped = setjmp(jump);
            if (!jumped) {
                free(base + off + 4);
            }
            in_probe = 0;

            void *drained[512];
            int nd = 0;
            if (drain_and_check(32, live, NLIVE, 64, drained, &nd)) {
                vulnerable = 1;
                for (int j = 0; j < nd; j++) if (drained[j]) free(drained[j]);
                goto attack2_done;
            }
            for (int j = 0; j < nd; j++) if (drained[j]) free(drained[j]);
        }
attack2_done:
        for (int i = 0; i < NLIVE; i++) if (live[i]) free(live[i]);
    }

    if (vulnerable) {
        printf("[VULNERABLE] cross-size fake chunk forged into free list\n");
        return 1;
    }

    /* ============================================================
     * Attack 3: alien pointer — forge a header just before a stack
     *           buffer and free the stack address.  The pointer is
     *           completely outside the arena, so an arena-range check
     *           would catch it; but the forged entry must not corrupt
     *           a subsequent malloc(8).
     * ============================================================ */
    {
        /* stack buffer with a forged 8-byte header just before data */
        char stack_buf[64];
        memset(stack_buf, 'S', sizeof(stack_buf));
        *(int *)(stack_buf + 0) = 8;   /* fake header at stack_buf[0..3] */
        /* "user pointer" would be stack_buf + 4 */

        in_probe = 1;
        int jumped = setjmp(jump);
        if (!jumped) {
            free(stack_buf + 4);   /* free a stack address */
        }
        in_probe = 0;

        /* drain malloc(8) and make sure none alias the stack buffer */
        void *live_stack[1] = { stack_buf };
        void *drained[512];
        int nd = 0;
        if (drain_and_check(8, live_stack, 1, sizeof(stack_buf), drained, &nd)) {
            vulnerable = 1;
        }
        for (int j = 0; j < nd; j++) if (drained[j]) free(drained[j]);
    }

    if (vulnerable) {
        printf("[VULNERABLE] alien (stack) fake chunk accepted into free list\n");
        return 1;
    }

    /* ============================================================
     * Sanity: allocator must still be functional after all attacks.
     * ============================================================ */
    {
        void *a = malloc(16);
        void *b = malloc(16);
        void *c = malloc(32);
        if (!a || !b || !c || a == b) {
            printf("[VULNERABLE] allocator corrupted after forgery attacks\n");
            if (a) free(a);
            if (b) free(b);
            if (c) free(c);
            return 1;
        }
        free(a); free(b); free(c);
    }

    printf("[SAFE] fake chunk forgery was rejected in all scenarios\n");
    return 0;
}
