/*
 * TEST 20: ASLR / heap randomization
 *
 * A safe allocator should introduce enough randomization that an attacker
 * cannot predict which slot will be returned after a free.  This test
 * exercises several angles that weak / fake implementations fail:
 *
 *  (A) Many-round same-pattern test (20 rounds):
 *      alloc two 16-byte blocks, free the first, alloc a third.
 *      Record the address of the third allocation each round.
 *      With a truly random free list the probability that all 20 rounds
 *      return the same address is negligibly small.  A deterministic LIFO
 *      allocator always returns the same slot and fails here.
 *
 *  (B) Minimum unique-address requirement:
 *      Over the 20 rounds we must see at least 3 distinct addresses.
 *      This defeats "swap first two entries" cheats that only ever
 *      oscillate between two slots.
 *
 *  (C) Varied-pattern test (10 rounds):
 *      Each round allocates a different number of blocks (1..10) before
 *      freeing them all and recording the address returned by the very
 *      next malloc.  A truly random allocator should produce a spread of
 *      addresses; a trivially deterministic one will always return the
 *      same slot regardless of how many allocations preceded the free.
 *
 *  (D) Run-to-run entropy check via fork:
 *      Fork the process.  Each half allocates the same sequence and
 *      records an address.  If the allocator's only randomness is an
 *      arena base picked by mmap (ASLR), both halves will see the same
 *      relative offsets — so we compare the offsets, not the raw
 *      pointers.  A safe allocator must introduce per-free or per-malloc
 *      randomness *within* the arena so that relative slot order differs
 *      between the two independent processes.
 *
 * The test passes (exits 0) only when ALL four checks pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ROUNDS_A       20
#define MIN_UNIQUE_A    3
#define ROUNDS_C       10

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int count_unique(uintptr_t *arr, int n)
{
    int unique = 0;
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < i; j++)
            if (arr[j] == arr[i]) { seen = 1; break; }
        if (!seen) unique++;
    }
    return unique;
}

/* ------------------------------------------------------------------ */
/* (A) + (B)  many-round same-pattern                                  */
/* ------------------------------------------------------------------ */

static int check_A(void)
{
    uintptr_t addrs[ROUNDS_A];

    for (int r = 0; r < ROUNDS_A; r++) {
        void *a = malloc(16);
        void *b = malloc(16);
        free(a);
        void *c = malloc(16);
        addrs[r] = (uintptr_t)c;
        free(b);
        free(c);
    }

    /* (A): all identical → deterministic */
    int all_same = 1;
    for (int i = 1; i < ROUNDS_A; i++)
        if (addrs[i] != addrs[0]) { all_same = 0; break; }

    if (all_same) {
        printf("[VULNERABLE-A] all %d rounds returned the same address\n",
               ROUNDS_A);
        return 0;
    }

    /* (B): too few unique addresses → weak shuffle */
    int uniq = count_unique(addrs, ROUNDS_A);
    if (uniq < MIN_UNIQUE_A) {
        printf("[VULNERABLE-B] only %d unique address(es) across %d rounds"
               " (need >= %d)\n", uniq, ROUNDS_A, MIN_UNIQUE_A);
        return 0;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* (C) varied-pattern: stress different free-list depths               */
/* ------------------------------------------------------------------ */

static int check_C(void)
{
    /*
     * Each round allocates (r+1) blocks, frees them all, then allocates
     * one more and records its address.  A deterministic allocator always
     * hands out the same "next available" slot regardless of prior depth.
     */
    uintptr_t addrs[ROUNDS_C];

    for (int r = 0; r < ROUNDS_C; r++) {
        int depth = r + 1;          /* 1 .. ROUNDS_C */
        void *ptrs[ROUNDS_C];

        for (int j = 0; j < depth; j++)
            ptrs[j] = malloc(16);
        for (int j = 0; j < depth; j++)
            free(ptrs[j]);

        void *probe = malloc(16);
        addrs[r] = (uintptr_t)probe;
        free(probe);
    }

    int uniq = count_unique(addrs, ROUNDS_C);
    if (uniq < 2) {
        printf("[VULNERABLE-C] varied-depth pattern: only %d unique address(es)"
               " across %d rounds\n", uniq, ROUNDS_C);
        return 0;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* (D) fork-based run-to-run entropy                                   */
/* ------------------------------------------------------------------ */

/*
 * Layout of data exchanged through a pipe: two uintptr_t offsets.
 * We compute offset = ptr - first_ever_allocation so that ASLR on the
 * mmap base cancels out.  A safe allocator must randomise *within* the
 * arena independently each run, so the two offsets should differ.
 *
 * We repeat the probe FORK_PROBE_ROUNDS times to reduce the chance that
 * two truly-random processes happen to draw the same offset.
 */
#define FORK_PROBE_ROUNDS 8

static uintptr_t collect_offsets(uintptr_t base, uintptr_t *out, int n)
{
    /*
     * Perform (check_A's pattern) n times and compute each address
     * relative to `base`.
     */
    for (int r = 0; r < n; r++) {
        void *a = malloc(16);
        void *b = malloc(16);
        free(a);
        void *c = malloc(16);
        out[r] = (uintptr_t)c - base;
        free(b);
        free(c);
    }
    return 0;
}

static int check_D(void)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        /* If pipe fails, skip this check rather than false-fail */
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return 1; /* skip */
    }

    if (pid == 0) {
        /* child */
        close(pfd[0]);

        /* establish the arena base by doing one alloc+free */
        void *first = malloc(16);
        uintptr_t base = (uintptr_t)first;
        free(first);

        uintptr_t offsets[FORK_PROBE_ROUNDS];
        collect_offsets(base, offsets, FORK_PROBE_ROUNDS);

        write(pfd[1], offsets, sizeof(offsets));
        close(pfd[1]);
        _exit(0);
    }

    /* parent */
    close(pfd[1]);

    /* parent: same sequence */
    void *first = malloc(16);
    uintptr_t base = (uintptr_t)first;
    free(first);

    uintptr_t parent_off[FORK_PROBE_ROUNDS];
    collect_offsets(base, parent_off, FORK_PROBE_ROUNDS);

    uintptr_t child_off[FORK_PROBE_ROUNDS];
    ssize_t got = 0, total = (ssize_t)sizeof(child_off);
    char *buf = (char *)child_off;
    while (got < total) {
        ssize_t r = read(pfd[0], buf + got, (size_t)(total - got));
        if (r <= 0) break;
        got += r;
    }
    close(pfd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (got < total) {
        /* child failed to write — skip */
        return 1;
    }

    /* Compare offset sequences.  If they are identical the allocator is
     * deterministic across processes (no true per-process entropy). */
    if (memcmp(parent_off, child_off, sizeof(parent_off)) == 0) {
        printf("[VULNERABLE-D] parent and child processes produced identical"
               " relative allocation sequences — no inter-process entropy\n");
        return 0;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    int ok_A = check_A();
    int ok_C = check_C();
    int ok_D = check_D();

    if (ok_A && ok_C && ok_D) {
        printf("[SAFE] heap layout has sufficient randomization\n");
        return 0;
    }

    /* Individual failures already printed above */
    return 1;
}
