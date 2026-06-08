/*
 * TEST 8: Memory scrubbing after free
 *
 * A safe allocator must scrub freed memory so secrets cannot be recovered
 * by any of the following attack surfaces:
 *
 *   (a) Direct re-read of the freed pointer (use-after-free read).
 *   (b) Scanning memory around a fresh allocation that lands in the same slot.
 *   (c) Partial scrub evasion: secret split into non-contiguous fragments.
 *   (d) Multi-size evasion: secrets placed in different pool size classes.
 *   (e) Multi-round evasion: repeated alloc/free/alloc cycles.
 *   (f) Post-free write visibility: data written via a dangling pointer
 *       must not survive into the next allocation of the same slot.
 *
 * The test exits 0 (SAFE) only if ALL checks pass.
 * It exits 1 (VULNERABLE) at the first failure, printing which check failed.
 *
 * Design constraints:
 *   - We never free a pointer we haven't allocated (no fake headers).
 *   - All sizes fit within the allocator's pool range (1–512 bytes).
 *   - We pin the slot with a live "anchor" allocation so the recycled
 *     slot is always adjacent to a known address, defeating scan-evasion
 *     tricks that rely on probe landing far from the secret.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Scan [base - radius, base + radius) for a 'len'-byte needle.
 * Returns the offset at which it was found, or INT32_MIN if not found.
 */
static int scan_for(const char *base, int radius,
                    const char *needle, int len)
{
    for (int off = -radius; off < radius - len + 1; off++) {
        if (memcmp(base + off, needle, len) == 0)
            return off;
    }
    return (int)0x80000000;
}

/* Check whether 'needle' appears anywhere in [ptr, ptr+range). */
static int region_contains(const char *ptr, size_t range,
                            const char *needle, size_t len)
{
    if (range < len) return 0;
    for (size_t i = 0; i <= range - len; i++) {
        if (memcmp(ptr + i, needle, len) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Check (a+b): direct dangling-pointer read + scan around next alloc */
/* ------------------------------------------------------------------ */
static int check_direct_and_scan(void)
{
    const char SECRET[] = "TOPSECRET_A1B2C3";   /* 16 bytes, no NUL needed */
    const int  SZ       = 32;

    /*
     * Anchor: allocate a block of the same size first so the freed slot
     * and the next allocation are guaranteed to be in the same pool region,
     * making it impossible to pass by returning a distant slot.
     */
    char *anchor = (char *)malloc(SZ);
    if (!anchor) { printf("[SKIP] malloc returned NULL\n"); return 0; }
    memset(anchor, 0xAA, SZ);

    char *secret = (char *)malloc(SZ);
    if (!secret) { free(anchor); printf("[SKIP] malloc returned NULL\n"); return 0; }
    memcpy(secret, SECRET, 16);
    char *saved = secret;   /* dangling pointer after free */
    free(secret);

    /* (a) Direct read through dangling pointer */
    if (memcmp(saved, SECRET, 16) == 0) {
        printf("[VULNERABLE] check_direct_and_scan(a): "
               "secret survives free via dangling pointer\n");
        free(anchor);
        return 1;
    }

    /* (b) Scan around a fresh allocation that should reuse the same slot */
    char *probe = (char *)malloc(SZ);
    if (!probe) { free(anchor); printf("[SKIP] malloc returned NULL\n"); return 0; }

    if (scan_for(probe, 4096, SECRET, 16) != (int)0x80000000) {
        printf("[VULNERABLE] check_direct_and_scan(b): "
               "secret found in memory scan around new allocation\n");
        free(probe);
        free(anchor);
        return 1;
    }

    free(probe);
    free(anchor);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Check (c): partial / fragmented secret detection                   */
/* ------------------------------------------------------------------ */
static int check_partial_scrub(void)
{
    /*
     * Write a secret that is split into two halves. If an allocator only
     * zeroes the first 8 bytes (or the last 8 bytes), one half survives.
     */
    const char HALF_A[] = "FRAGMENT_ALPHA__";  /* bytes 0-15  */
    const char HALF_B[] = "FRAGMENT_BETA___";  /* bytes 16-31 */
    const int  SZ       = 32;

    char *anchor = (char *)malloc(SZ);
    if (!anchor) return 0;

    char *secret = (char *)malloc(SZ);
    if (!secret) { free(anchor); return 0; }
    memcpy(secret,      HALF_A, 16);
    memcpy(secret + 16, HALF_B, 16);
    free(secret);

    char *probe = (char *)malloc(SZ);
    if (!probe) { free(anchor); return 0; }

    /* Check each half independently */
    if (scan_for(probe, 4096, HALF_A, 16) != (int)0x80000000) {
        printf("[VULNERABLE] check_partial_scrub: "
               "first 16 bytes of secret survived free\n");
        free(probe); free(anchor);
        return 1;
    }
    if (scan_for(probe, 4096, HALF_B, 16) != (int)0x80000000) {
        printf("[VULNERABLE] check_partial_scrub: "
               "last 16 bytes of secret survived free\n");
        free(probe); free(anchor);
        return 1;
    }

    free(probe);
    free(anchor);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Check (d): multi-size: secrets in different pool size classes       */
/* ------------------------------------------------------------------ */
static int check_multi_size(void)
{
    /* pool sizes: 4, 8, 16, 32, 64, 128 */
    static const struct { int sz; const char *tag; } cases[] = {
        {  4, "S4__" },
        {  8, "SEC8SZ08" },
        { 16, "SECRETSIXTEEN!!!" },
        { 32, "SECRET_IN_32BYTE_SLOT_ABCDEFGHIJ" },
        { 64, "SECRET_IN_64BYTE_SLOT_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD" },
    };
    static const int NCASES = 5;

    for (int c = 0; c < NCASES; c++) {
        int sz         = cases[c].sz;
        const char *tag = cases[c].tag;
        int taglen     = (int)strlen(tag);

        char *anchor = (char *)malloc(sz);
        if (!anchor) continue;

        char *secret = (char *)malloc(sz);
        if (!secret) { free(anchor); continue; }
        /* fill entire slot with the tag pattern (repeating if shorter than sz) */
        for (int i = 0; i < sz; i++)
            secret[i] = tag[i % taglen];
        free(secret);

        char *probe = (char *)malloc(sz);
        if (!probe) { free(anchor); continue; }

        /* check for the tag pattern (use min(taglen, sz) bytes) */
        int check_len = taglen < sz ? taglen : sz;
        char pattern[64];
        for (int i = 0; i < check_len; i++)
            pattern[i] = tag[i % taglen];

        if (scan_for(probe, 4096, pattern, check_len) != (int)0x80000000) {
            printf("[VULNERABLE] check_multi_size: "
                   "secret survived in pool-size-%d slot\n", sz);
            free(probe); free(anchor);
            return 1;
        }

        free(probe);
        free(anchor);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Check (e): multi-round — repeated alloc/free/alloc                 */
/* ------------------------------------------------------------------ */
static int check_multi_round(void)
{
    const int  SZ    = 32;
    const int  NRND  = 8;

    for (int round = 0; round < NRND; round++) {
        char pattern[SZ];
        /* Each round uses a distinct pattern so a "remember first write"
           trick cannot pass. */
        memset(pattern, 0xA0 + round, SZ);
        memcpy(pattern, "RND_SECRET_ROUND", 16);
        pattern[16] = (char)round;   /* make each round's pattern unique */

        char *anchor = (char *)malloc(SZ);
        if (!anchor) continue;

        char *secret = (char *)malloc(SZ);
        if (!secret) { free(anchor); continue; }
        memcpy(secret, pattern, SZ);
        free(secret);

        char *probe = (char *)malloc(SZ);
        if (!probe) { free(anchor); continue; }

        if (region_contains(probe - 4096, 8192, pattern, 16) ||
            region_contains(probe,        SZ,   pattern, SZ)) {
            printf("[VULNERABLE] check_multi_round: "
                   "secret survived round %d\n", round);
            free(probe); free(anchor);
            return 1;
        }

        free(probe);
        free(anchor);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Check (f): post-free write must not be visible to next allocation  */
/* ------------------------------------------------------------------ */
static int check_postfree_write(void)
{
    /*
     * Write a secret, free the block, then write a DIFFERENT value through
     * the dangling pointer. If the allocator does NOT scrub on malloc
     * (only on free), the new allocation returns a slot that was written
     * by the attacker between free and malloc — that value is readable by
     * the next holder. A truly safe allocator scrubs on malloc (or on both),
     * so the attacker's post-free write is wiped before the slot is returned.
     *
     * Specifically: write CANARY_A, free, write CANARY_B via dangling ptr,
     * malloc again — the new block must not contain CANARY_B.
     *
     * Note: we test both because:
     *   - scrub-on-free  removes CANARY_A but CANARY_B leaks to next holder.
     *   - scrub-on-malloc removes CANARY_B before returning to next holder.
     *   - both scrubs: neither leaks.
     */
    const char CANARY_B[] = "POSTFREE_INJECT!";
    const int  SZ         = 32;

    char *anchor = (char *)malloc(SZ);
    if (!anchor) return 0;

    char *p = (char *)malloc(SZ);
    if (!p) { free(anchor); return 0; }
    memset(p, 0x11, SZ);
    free(p);   /* p is now dangling */

    /* attacker writes through dangling pointer */
    memcpy(p, CANARY_B, 16);

    char *probe = (char *)malloc(SZ);
    if (!probe) { free(anchor); return 0; }

    if (memcmp(probe, CANARY_B, 16) == 0) {
        printf("[VULNERABLE] check_postfree_write: "
               "post-free write visible to next malloc caller\n");
        free(probe); free(anchor);
        return 1;
    }
    /* Also scan wider region */
    if (scan_for(probe, 4096, CANARY_B, 16) != (int)0x80000000) {
        printf("[VULNERABLE] check_postfree_write: "
               "post-free canary found in scan around new allocation\n");
        free(probe); free(anchor);
        return 1;
    }

    free(probe);
    free(anchor);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    if (check_direct_and_scan())  return 1;
    if (check_partial_scrub())    return 1;
    if (check_multi_size())       return 1;
    if (check_multi_round())      return 1;
    if (check_postfree_write())   return 1;

    printf("[SAFE] all memory-scrubbing checks passed\n");
    return 0;
}
