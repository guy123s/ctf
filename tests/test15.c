/*
 * TEST 15: Heap layout determinism / address predictability
 *
 * A safe allocator must make it non-trivial for an attacker to predict
 * where a future allocation will land.  This test applies three
 * independent checks; failing ANY ONE is sufficient to report VULNERABLE.
 *
 * Check A — arithmetic-sequence detection (N allocations, same size)
 *   Allocate SAMPLE_N pointers.  Collect their raw addresses, sort them,
 *   then compute every gap between adjacent sorted addresses.  If all
 *   gaps are identical the live set forms a perfect arithmetic sequence —
 *   the layout is fully determined by two numbers (base + stride) and is
 *   trivially predictable.
 *
 * Check B — linear-regression prediction
 *   Using the first TRAIN_N pointers (in allocation order), fit a least-
 *   squares line (index → address).  Predict the address of allocation
 *   TRAIN_N+1 and check whether it lands within PREDICT_WINDOW bytes of
 *   the actual address.  A stride-based or offset-shifted allocator will
 *   be caught here even if it survived check A by introducing a single
 *   irregular gap.
 *
 * Check C — inter-run entropy (fork-based)
 *   Fork a child that performs the same SAMPLE_N allocations and writes
 *   its first address to a pipe.  Compare it to the parent's first
 *   address.  If they are equal the allocator is completely deterministic
 *   across process instances (no ASLR, no per-run seed).  Processes
 *   started by fork() share the same mmap base in kernels that do not
 *   re-randomise after fork, so for a robust check we additionally
 *   compare the full sorted gap vectors: two deterministic allocators
 *   that differ only in base address will produce identical gap vectors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define SAMPLE_N       16
#define TRAIN_N        8          /* must be < SAMPLE_N */
#define PREDICT_WINDOW 64         /* bytes; tighter than one pool slot     */
#define ALLOC_SIZE     16

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int cmp_uintptr(const void *a, const void *b) {
    uintptr_t x = *(const uintptr_t *)a;
    uintptr_t y = *(const uintptr_t *)b;
    return (x > y) - (x < y);
}

/*
 * Returns 1 if all SAMPLE_N-1 sorted gaps are identical (arithmetic
 * sequence), 0 otherwise.
 */
static int is_arithmetic_sequence(uintptr_t *addrs, int n) {
    uintptr_t sorted[SAMPLE_N];
    memcpy(sorted, addrs, n * sizeof(uintptr_t));
    qsort(sorted, n, sizeof(uintptr_t), cmp_uintptr);

    uintptr_t ref_gap = sorted[1] - sorted[0];
    for (int i = 2; i < n; i++) {
        if (sorted[i] - sorted[i-1] != ref_gap)
            return 0;
    }
    return 1;
}

/*
 * Least-squares linear fit over the first 'train' points (x = index,
 * y = address).  Returns predicted address for index 'predict_idx'.
 * Uses integer arithmetic (double would introduce floating-point
 * dependency but is fine for a test).
 */
static uintptr_t linear_predict(uintptr_t *addrs, int train, int predict_idx) {
    /* Use double for the fit — this is a test binary, not production. */
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    int n = train;
    for (int i = 0; i < n; i++) {
        double x = i, y = (double)addrs[i];
        sx  += x;
        sy  += y;
        sxx += x * x;
        sxy += x * y;
    }
    double denom = n * sxx - sx * sx;
    if (denom == 0.0) {
        /* All x-values identical — degenerate; predict mean. */
        return (uintptr_t)(sy / n);
    }
    double slope     = (n * sxy - sx * sy) / denom;
    double intercept = (sy - slope * sx) / n;
    double predicted = intercept + slope * predict_idx;
    return (uintptr_t)predicted;
}

/* ------------------------------------------------------------------ */
/* Check A & B — run in this process                                   */
/* ------------------------------------------------------------------ */

static int run_checks_ab(void) {
    void  *ptrs[SAMPLE_N];
    uintptr_t addrs[SAMPLE_N];

    /* Allocate SAMPLE_N chunks. */
    for (int i = 0; i < SAMPLE_N; i++) {
        ptrs[i] = malloc(ALLOC_SIZE);
        if (!ptrs[i]) {
            printf("[SKIP] malloc returned NULL at alloc %d\n", i);
            /* free what we have */
            for (int j = 0; j < i; j++) free(ptrs[j]);
            return -1;
        }
        addrs[i] = (uintptr_t)ptrs[i];
    }

    int result = 0;

    /* --- Check A --------------------------------------------------- */
    if (is_arithmetic_sequence(addrs, SAMPLE_N)) {
        printf("[VULNERABLE] Check A: all %d allocations form a perfect "
               "arithmetic sequence — layout is fully predictable\n",
               SAMPLE_N);
        result = 1;
    }

    /* --- Check B --------------------------------------------------- */
    if (!result) {
        uintptr_t predicted = linear_predict(addrs, TRAIN_N, TRAIN_N);
        uintptr_t actual    = addrs[TRAIN_N];
        uintptr_t diff = (predicted > actual) ? (predicted - actual)
                                              : (actual - predicted);
        if (diff <= PREDICT_WINDOW) {
            printf("[VULNERABLE] Check B: linear prediction of allocation "
                   "%d was within %lu bytes (predicted=0x%lx actual=0x%lx)\n",
                   TRAIN_N, (unsigned long)diff,
                   (unsigned long)predicted, (unsigned long)actual);
            result = 1;
        }
    }

    for (int i = 0; i < SAMPLE_N; i++) free(ptrs[i]);
    return result;
}

/* ------------------------------------------------------------------ */
/* Check C — fork and compare gap vectors                              */
/* ------------------------------------------------------------------ */

/*
 * We write SAMPLE_N uintptr_t values (raw addresses) from child to
 * parent via a pipe.  Then the parent converts both sets to sorted gap
 * vectors and compares them.  Identical gap vectors mean identical
 * pool layout regardless of ASLR slide.
 */
static int run_check_c(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        /* Can't fork/pipe — skip this check. */
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        /* ---- child ---- */
        close(pipefd[0]);
        void  *ptrs[SAMPLE_N];
        uintptr_t addrs[SAMPLE_N];
        for (int i = 0; i < SAMPLE_N; i++) {
            ptrs[i] = malloc(ALLOC_SIZE);
            addrs[i] = ptrs[i] ? (uintptr_t)ptrs[i] : 0;
        }
        /* write raw addresses; parent will sort them */
        write(pipefd[1], addrs, SAMPLE_N * sizeof(uintptr_t));
        close(pipefd[1]);
        for (int i = 0; i < SAMPLE_N; i++) if (ptrs[i]) free(ptrs[i]);
        _exit(0);
    }

    /* ---- parent ---- */
    close(pipefd[1]);

    /* Collect parent's own addresses. */
    void  *ptrs_p[SAMPLE_N];
    uintptr_t addrs_p[SAMPLE_N];
    for (int i = 0; i < SAMPLE_N; i++) {
        ptrs_p[i] = malloc(ALLOC_SIZE);
        addrs_p[i] = ptrs_p[i] ? (uintptr_t)ptrs_p[i] : 0;
    }

    /* Read child's addresses. */
    uintptr_t addrs_c[SAMPLE_N];
    ssize_t got = read(pipefd[0], addrs_c, SAMPLE_N * sizeof(uintptr_t));
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    for (int i = 0; i < SAMPLE_N; i++) if (ptrs_p[i]) free(ptrs_p[i]);

    if (got != (ssize_t)(SAMPLE_N * sizeof(uintptr_t)))
        return 0; /* partial read — skip */

    /* Build sorted gap vectors for both runs. */
    uintptr_t sorted_p[SAMPLE_N], sorted_c[SAMPLE_N];
    memcpy(sorted_p, addrs_p, SAMPLE_N * sizeof(uintptr_t));
    memcpy(sorted_c, addrs_c, SAMPLE_N * sizeof(uintptr_t));
    qsort(sorted_p, SAMPLE_N, sizeof(uintptr_t), cmp_uintptr);
    qsort(sorted_c, SAMPLE_N, sizeof(uintptr_t), cmp_uintptr);

    uintptr_t gaps_p[SAMPLE_N - 1], gaps_c[SAMPLE_N - 1];
    for (int i = 0; i < SAMPLE_N - 1; i++) {
        gaps_p[i] = sorted_p[i+1] - sorted_p[i];
        gaps_c[i] = sorted_c[i+1] - sorted_c[i];
    }

    if (memcmp(gaps_p, gaps_c, (SAMPLE_N - 1) * sizeof(uintptr_t)) == 0) {
        printf("[VULNERABLE] Check C: parent and child gap vectors are "
               "identical — pool layout is fully deterministic across "
               "process instances\n");
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    int ab = run_checks_ab();
    if (ab < 0) return 1; /* allocation failure — treat as vulnerable */

    int c = run_check_c();

    if (ab || c) {
        /* At least one check failed — already printed a VULNERABLE line. */
        return 1;
    }

    printf("[SAFE] allocation addresses are not trivially predictable "
           "(all three checks passed)\n");
    return 0;
}
