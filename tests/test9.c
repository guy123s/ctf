/*
 * TEST 9: Free of invalid pointer (stack / BSS / code-segment injection)
 *
 * A safe allocator must validate that a pointer passed to free() actually
 * belongs to the managed arena before accepting it onto a free list.
 * The allocator's only defence is the 4-byte size header preceding each
 * chunk; because that header is user-writable, an attacker can craft a
 * fake header on the stack (or anywhere) and trick free() into injecting
 * an arbitrary address into a pool's free list.  The next malloc() from
 * that pool then returns the attacker-controlled address.
 *
 * Hardening rationale
 * -------------------
 * The original test had several bypass paths:
 *
 *   1. Only one pool size (4) was tested; a patched allocator could
 *      special-case it.
 *   2. The vulnerable check only asked "is the returned pointer near the
 *      stack?" — if the injected chunk happened to sit behind legitimate
 *      pool entries the test would report SAFE even though the bad free
 *      was accepted.
 *   3. The arena base was never established, so a fallback to libc malloc
 *      could silently pass the check.
 *   4. Only one post-injection malloc was issued; draining the pool is
 *      required to guarantee the injected pointer surfaces.
 *
 * This version fixes all four issues:
 *
 *   • Establishes the arena base and size by examining the first real
 *     allocation, then confirms every subsequent allocation stays within
 *     [arena_base, arena_base + ARENA_SIZE).
 *   • Tests four different pool sizes (4, 8, 16, 32) with independent
 *     fake-header structs placed in different memory regions (stack,
 *     static storage, and a separate stack frame).
 *   • After each poisoned free(), drains the pool completely (up to the
 *     maximum number of slots the pool can hold) so the injected pointer
 *     must surface if it was accepted.
 *   • Considers the allocator VULNERABLE if *any* returned pointer falls
 *     outside the known arena range.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Must match malloc.c constants */
#define ARENA_SIZE   0x100000   /* 1 MB  */
#define POOL_SIZE    0x1000     /* 4 KB  */
#define HEADER_SIZE  4
/* Maximum slots in the smallest pool we test (size=4):
 * POOL_SIZE / (pool_size + HEADER_SIZE) = 4096 / 8 = 512 */
#define MAX_SLOTS    512

/* ------------------------------------------------------------------ */
/* Global fake-header struct so we can test injection from .bss too   */
/* ------------------------------------------------------------------ */
static struct { int hdr; int target; } g_fake;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Determine the arena base by allocating a probe, reading the 4-byte
 * size header immediately before it, and computing the pool start.
 * The first allocation from pool i lands at:
 *   arena_buf + i * POOL_SIZE + HEADER_SIZE
 * We don't need the exact pool index — we just record the raw pointer
 * and accept any allocation within ARENA_SIZE bytes of it.
 *
 * Returns the lowest address we observed so we can build a [lo, hi) range.
 */
static uintptr_t g_arena_lo = 0;
static uintptr_t g_arena_hi = 0;

static void establish_arena_bounds(void) {
    /* Allocate one chunk from each of the four pool sizes we will test,
     * then free them.  Record the min/max addresses to bracket the arena. */
    int sizes[] = {4, 8, 16, 32};
    for (int i = 0; i < 4; i++) {
        void *p = malloc(sizes[i]);
        if (!p) continue;
        uintptr_t addr = (uintptr_t)p;
        if (g_arena_lo == 0 || addr < g_arena_lo) g_arena_lo = addr;
        if (addr > g_arena_hi)                     g_arena_hi = addr;
        free(p);
    }
    /* Extend the range by the full arena size in both directions to be safe */
    if (g_arena_lo > ARENA_SIZE)
        g_arena_lo -= ARENA_SIZE;
    else
        g_arena_lo = 0;
    g_arena_hi += ARENA_SIZE;
}

static int in_arena(void *p) {
    uintptr_t addr = (uintptr_t)p;
    return addr >= g_arena_lo && addr < g_arena_hi;
}

/* ------------------------------------------------------------------ */
/* One injection trial for a given pool size                           */
/* pool_size must be a power of two in [1, 512]                       */
/* fake_hdr / fake_target are the two adjacent ints to forge          */
/* Returns 1 if injection succeeded (VULNERABLE), 0 if safe.          */
/* ------------------------------------------------------------------ */
static int try_inject(int pool_size, int *fake_hdr_p, int *fake_target_p,
                      const char *region_name) {
    /* Set up the fake header just before the target word */
    *fake_hdr_p    = pool_size;
    *fake_target_p = 0;

    /* Poison the free list */
    free(fake_target_p);

    /*
     * Drain the pool: allocate up to MAX_SLOTS chunks.  If any of them
     * falls outside the arena, the injected pointer surfaced.
     */
    void *ptrs[MAX_SLOTS];
    int n = 0;
    int vulnerable = 0;

    for (int i = 0; i < MAX_SLOTS; i++) {
        void *p = malloc(pool_size);
        if (!p) break;
        ptrs[n++] = p;
        if (!in_arena(p)) {
            printf("[VULNERABLE] free(%s addr) injected out-of-arena pointer "
                   "(pool_size=%d, ptr=%p)\n",
                   region_name, pool_size, p);
            vulnerable = 1;
            /* keep draining a bit to empty the pool cleanly */
        }
    }

    /* Return all legitimate chunks so later tests have a full pool */
    for (int i = 0; i < n; i++) {
        if (in_arena(ptrs[i]))
            free(ptrs[i]);
    }

    return vulnerable;
}

/* ------------------------------------------------------------------ */
/* Separate stack frame so the fake struct is at a different address   */
/* ------------------------------------------------------------------ */
static int stack_frame_inject(int pool_size) {
    struct { int hdr; int target; } local;
    return try_inject(pool_size, &local.hdr, &local.target, "stack(frame)");
}

/* ------------------------------------------------------------------ */
int main(void) {
    /* Warm up the allocator */
    void *w = malloc(1);
    free(w);

    /* Learn the arena address range */
    establish_arena_bounds();

    int vulnerable = 0;

    /* --- Trial 1: stack (main frame), pool size 4 --- */
    {
        struct { int hdr; int target; } s1;
        vulnerable |= try_inject(4, &s1.hdr, &s1.target, "stack(main)");
    }

    /* --- Trial 2: stack (separate frame), pool size 8 --- */
    vulnerable |= stack_frame_inject(8);

    /* --- Trial 3: static (.bss), pool size 16 --- */
    vulnerable |= try_inject(16, &g_fake.hdr, &g_fake.target, "bss");

    /* --- Trial 4: stack (main frame), pool size 32 --- */
    {
        struct { int hdr; int target; } s4;
        vulnerable |= try_inject(32, &s4.hdr, &s4.target, "stack(main-32)");
    }

    /*
     * Final cross-check: every allocation from a fresh malloc() call must
     * stay within the arena.  If the allocator fell back to libc malloc for
     * any size, it's a different kind of vulnerability (out-of-arena return)
     * that the drain loop above already catches, but we do one explicit
     * verification here as well.
     */
    int sizes[] = {4, 8, 16, 32};
    for (int i = 0; i < 4; i++) {
        void *p = malloc(sizes[i]);
        if (p && !in_arena(p)) {
            printf("[VULNERABLE] normal malloc(%d) returned out-of-arena "
                   "pointer %p — possible libc fallback after pool exhaustion\n",
                   sizes[i], p);
            vulnerable = 1;
        }
        if (p) free(p);
    }

    if (vulnerable) {
        return 1;
    }

    printf("[SAFE] all invalid pointers were rejected; no out-of-arena "
           "allocation observed\n");
    return 0;
}
