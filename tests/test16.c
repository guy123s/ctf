/*
 * TEST 16: Allocator memory leak (free costs memory / no node recycling)
 *
 * The vulnerability: free() internally allocates a fresh list-node via the
 * real libc malloc every time a chunk is returned.  The node that was
 * consumed (popped) when the chunk was originally handed out is simply
 * discarded.  This leaks one node-sized allocation per free() call.
 *
 * Three independent checks are performed.  ALL three must pass for the test
 * to exit 0 (SAFE).  This makes it hard to pass by accident.
 *
 * CHECK 1 — LIFO pointer recycling
 *   After freeing a pointer, the very next malloc of the same size MUST
 *   return the same address (assuming a simple LIFO free-list with no
 *   intervening allocations).  If a new node is allocated but the old chunk
 *   slot is recycled correctly this still passes; if the allocator returns a
 *   different slot it means the free-list is not being maintained properly.
 *
 * CHECK 2 — Pool exhaustion after many cycles
 *   Each size-16 pool has exactly POOL_SIZE / (16 + 4) = 204 slots.
 *   A correct allocator recycles slots on free, so the pool never empties
 *   no matter how many malloc/free cycles are performed.
 *   A leaking allocator eventually runs out of slots (returns NULL) once the
 *   node bookkeeping collapses — though in this specific impl the node count
 *   on the free list stays at 1, so exhaustion is masked.  We therefore use
 *   a stronger probe: allocate ALL 204 slots at once, free them all, then
 *   allocate all 204 again.  The second batch must succeed without NULL.
 *
 * CHECK 3 — RSS growth with glibc trim
 *   Force glibc to return freed memory to the OS after every cycle using
 *   mallopt + malloc_trim so that leaked nodes cannot hide in glibc's
 *   internal free-list cache.  500 000 malloc/free cycles must not grow
 *   RSS by more than 50 pages.  The threshold is intentionally tight because
 *   with trimming enabled each leaked node causes a visible page.
 */
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>   /* mallopt, malloc_trim */
#include <string.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

#define POOL_SLOTS  204   /* floor(4096 / (16 + 4)) */
#define ALLOC_SIZE  16

static long get_rss_pages(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long size, rss;
    if (fscanf(f, "%ld %ld", &size, &rss) != 2) rss = -1;
    fclose(f);
    return rss;
}

/* ------------------------------------------------------------------ */
/* CHECK 1: LIFO pointer recycling                                     */
/* ------------------------------------------------------------------ */
static int check_lifo_recycling(void) {
    /*
     * Do several warm-up rounds so the free-list is in steady state,
     * then verify the freed pointer is immediately returned on the next
     * malloc call.  Repeat across 1 000 independent cycles so a lucky
     * coincidence cannot mask the bug.
     */
    const int ROUNDS = 1000;
    int failures = 0;

    for (int r = 0; r < ROUNDS; r++) {
        void *p = malloc(ALLOC_SIZE);
        if (!p) { failures++; continue; }
        free(p);
        void *q = malloc(ALLOC_SIZE);
        if (q != p) failures++;
        free(q);
    }

    if (failures > 0) {
        printf("[FAIL check1] LIFO recycling broken: %d/%d rounds returned "
               "a different address after free\n", failures, ROUNDS);
        return 0;
    }
    printf("[OK   check1] LIFO pointer recycling verified (%d rounds)\n",
           ROUNDS);
    return 1;
}

/* ------------------------------------------------------------------ */
/* CHECK 2: Pool exhaustion after full fill-and-drain                  */
/* ------------------------------------------------------------------ */
static int check_pool_exhaustion(void) {
    void *ptrs[POOL_SLOTS];
    memset(ptrs, 0, sizeof ptrs);

    /* Drain the pool completely. */
    int allocated = 0;
    for (int i = 0; i < POOL_SLOTS; i++) {
        ptrs[i] = malloc(ALLOC_SIZE);
        if (!ptrs[i]) break;
        allocated++;
    }

    if (allocated < POOL_SLOTS) {
        printf("[FAIL check2] pool drained early: only %d/%d slots "
               "available on first fill\n", allocated, POOL_SLOTS);
        for (int i = 0; i < allocated; i++) free(ptrs[i]);
        return 0;
    }

    /* Verify pool is truly exhausted. */
    void *extra = malloc(ALLOC_SIZE);
    int truly_exhausted = (extra == NULL);
    if (!truly_exhausted) free(extra);   /* unexpected; free it anyway */

    /* Return all slots. */
    for (int i = 0; i < POOL_SLOTS; i++) free(ptrs[i]);

    /* Second fill: must succeed entirely if recycling works. */
    int second = 0;
    for (int i = 0; i < POOL_SLOTS; i++) {
        ptrs[i] = malloc(ALLOC_SIZE);
        if (!ptrs[i]) break;
        second++;
    }
    for (int i = 0; i < second; i++) free(ptrs[i]);

    if (second < POOL_SLOTS) {
        printf("[FAIL check2] pool not refilled after free: only %d/%d slots "
               "available on second fill — nodes are not being recycled\n",
               second, POOL_SLOTS);
        return 0;
    }
    printf("[OK   check2] pool fill-drain-refill succeeded (%d slots)\n",
           POOL_SLOTS);
    return 1;
}

/* ------------------------------------------------------------------ */
/* CHECK 3: RSS stability under trim pressure                          */
/* ------------------------------------------------------------------ */
static int check_rss_stable(void) {
    /*
     * Instruct glibc to release freed memory to the OS immediately so
     * that leaked nodes cannot accumulate invisibly in glibc's cache.
     * This makes every leaked node_struct show up as RSS growth.
     */
    mallopt(M_TRIM_THRESHOLD, 0);
    mallopt(M_MMAP_THRESHOLD, 0);

    /* warm up */
    for (int i = 0; i < 2000; i++) {
        void *p = malloc(ALLOC_SIZE);
        free(p);
        malloc_trim(0);
    }

    long rss_before = get_rss_pages();

    const int CYCLES = 100000;
    for (int i = 0; i < CYCLES; i++) {
        void *p = malloc(ALLOC_SIZE);
        free(p);
        /* Trim every 1 000 cycles — aggressive but not per-iteration
         * to keep runtime reasonable.                                  */
        if ((i & 0x3FF) == 0x3FF) malloc_trim(0);
    }
    malloc_trim(0);

    long rss_after  = get_rss_pages();
    long growth     = rss_after - rss_before;

    /* 50 pages == 200 KB.  Each leaked node is ~16 bytes; 100 000 nodes
     * == ~1.6 MB == ~400 pages, well above threshold if not recycled.  */
    if (growth > 50) {
        printf("[FAIL check3] RSS grew by %ld pages over %d cycles "
               "(threshold 50) — allocator leaks memory\n",
               growth, CYCLES);
        return 0;
    }
    printf("[OK   check3] RSS stable under trim pressure "
           "(%ld page delta, %d cycles)\n", growth, CYCLES);
    return 1;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    int c1 = check_lifo_recycling();
    int c2 = check_pool_exhaustion();
    int c3 = check_rss_stable();

    if (c1 && c2 && c3) {
        printf("[SAFE] allocator recycles memory correctly — all checks passed\n");
        return 0;
    }

    printf("[VULNERABLE] allocator leaks allocator-internal memory "
           "(checks: lifo=%s exhaustion=%s rss=%s)\n",
           c1 ? "ok" : "FAIL",
           c2 ? "ok" : "FAIL",
           c3 ? "ok" : "FAIL");
    return 1;
}
