/*
 * TEST 3: Double-free detection
 *
 * A safe allocator must not hand out the same chunk to two live callers as a
 * result of a double-free.  "Safe" outcomes are:
 *   (a) The allocator detects the double-free and calls abort() / raises a
 *       signal — the child process dies via a signal, which we accept as
 *       "detected".
 *   (b) The allocator silently ignores the second free (idempotent) so the
 *       chunk is never put back on the free-list twice, and subsequent
 *       allocations are all distinct.
 *
 * "Vulnerable" outcome: the same chunk address is returned by two separate
 * malloc() calls that are both live at the same time (classic double-free
 * aliasing), or writes through one pointer corrupt another.
 *
 * Hardening over the naive version:
 *   1. We fork() for each trial so a crashing allocator is caught cleanly via
 *      waitpid() — it does not kill the test process and does not produce a
 *      spurious pass.
 *   2. We test four different pool sizes (1, 8, 64, 256 bytes) to prevent a
 *      size-specific special-case bypass.
 *   3. After the double-free we drain the pool with N allocations (not just 2)
 *      and check every pair for aliasing — a single-entry free-list duplicate
 *      would be caught even if the first two happen to differ.
 *   4. We fill each live allocation with a unique sentinel and re-read all of
 *      them afterwards to detect cross-contamination caused by aliasing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Number of follow-up allocations to make after the double-free. */
#define DRAIN_COUNT 6

/*
 * Run a single double-free trial for the given allocation size.
 * Returns 0 if the allocator behaved safely, 1 if it is vulnerable.
 *
 * We fork() so that an abort()/crash inside the allocator does not kill the
 * test harness; instead we inspect the child's exit status.
 */
static int trial(size_t sz)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1; /* treat fork failure as a problem */
    }

    if (pid == 0) {
        /* ---- child ---- */
        void *ptrs[DRAIN_COUNT];
        int i, j;

        void *a = malloc(sz);
        if (!a) _exit(2);
        memset(a, 0xAA, sz);

        free(a);
        free(a); /* double-free */

        /*
         * Drain: allocate DRAIN_COUNT chunks of the same size and collect
         * their addresses.  A broken allocator will return 'a' twice.
         */
        for (i = 0; i < DRAIN_COUNT; i++) {
            ptrs[i] = malloc(sz);
            if (!ptrs[i]) {
                /* Pool exhausted — that is fine, just stop early. */
                for (j = 0; j < i; j++) free(ptrs[j]);
                _exit(0);
            }
        }

        /* Check every pair for aliasing. */
        for (i = 0; i < DRAIN_COUNT; i++) {
            for (j = i + 1; j < DRAIN_COUNT; j++) {
                if (ptrs[i] == ptrs[j]) {
                    /* Same address returned for two live allocations. */
                    _exit(1);
                }
            }
        }

        /*
         * Sentinel fill: write a unique byte pattern into every live chunk,
         * then verify that none of the other live chunks were corrupted.
         * Corruption would mean two pointers alias the same memory.
         */
        for (i = 0; i < DRAIN_COUNT; i++)
            memset(ptrs[i], (unsigned char)(0x10 + i), sz);

        for (i = 0; i < DRAIN_COUNT; i++) {
            unsigned char expected = (unsigned char)(0x10 + i);
            unsigned char *p = (unsigned char *)ptrs[i];
            for (j = 0; j < (int)sz; j++) {
                if (p[j] != expected) {
                    /* Cross-contamination detected — aliased pointer. */
                    _exit(1);
                }
            }
        }

        for (i = 0; i < DRAIN_COUNT; i++) free(ptrs[i]);
        _exit(0);
    }

    /* ---- parent ---- */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) return 0;  /* safe */
        if (code == 1) return 1;  /* vulnerable — aliasing detected */
        /* code == 2: malloc returned NULL (pool too small for drain) — safe */
        return 0;
    }

    if (WIFSIGNALED(status)) {
        /*
         * The allocator raised a signal (SIGABRT from assert/abort, SIGSEGV
         * from an intentional trap, etc.).  Treat this as "detected and
         * aborted" — a valid safe-allocator defence.
         */
        return 0;
    }

    /* Unexpected wait result — treat as vulnerable. */
    return 1;
}

int main(void)
{
    /*
     * Four pool sizes chosen to span distinct pool buckets:
     *   sz=1   → pool 0  (1-byte slots)
     *   sz=8   → pool 3  (8-byte slots)
     *   sz=64  → pool 6  (64-byte slots)
     *   sz=200 → pool 8  (256-byte slots)
     */
    static const size_t sizes[] = { 1, 8, 64, 200 };
    static const int    nsizes  = (int)(sizeof sizes / sizeof sizes[0]);
    int vulnerable = 0;

    for (int i = 0; i < nsizes; i++) {
        int r = trial(sizes[i]);
        if (r) {
            printf("[VULNERABLE] double-free aliasing at size %zu\n", sizes[i]);
            vulnerable = 1;
        }
    }

    if (!vulnerable) {
        printf("[SAFE] double-free handled correctly for all tested sizes\n");
        return 0;
    }
    return 1;
}
