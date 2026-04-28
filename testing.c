#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int passed = 0;
int failed = 0;

void check(int ok, const char *name) {
    if (ok) {
        printf("[PASS] %s\n", name);
        passed++;
    } else {
        printf("[FAIL] %s\n", name);
        failed++;
    }
}

// Test 1: basic malloc returns non-NULL
void test_malloc_returns_non_null() {
    void *p = malloc(32);
    check(p != NULL, "malloc returns non-NULL");
    free(p);
}

// Test 2: write and read back data
void test_write_read() {
    int *arr = (int *)malloc(sizeof(int) * 4);
    arr[0] = 42;
    arr[1] = 99;
    arr[2] = -1;
    arr[3] = 0;
    check(arr[0] == 42 && arr[1] == 99 && arr[2] == -1 && arr[3] == 0,
          "write and read back data");
    free(arr);
}

// Test 3: multiple allocations don't overlap
void test_no_overlap() {
    char *a = (char *)malloc(16);
    char *b = (char *)malloc(16);
    memset(a, 'A', 16);
    memset(b, 'B', 16);
    int ok = 1;
    for (int i = 0; i < 16; i++) {
        if (a[i] != 'A' || b[i] != 'B') {
            ok = 0;
            break;
        }
    }
    check(ok, "multiple allocations don't overlap");
    free(a);
    free(b);
}

// Test 4: free and reuse — after freeing, a new malloc can succeed
void test_free_and_reuse() {
    void *a = malloc(64);
    free(a);
    void *b = malloc(64);
    check(b != NULL, "free and reuse");
    free(b);
}

// Test 5: free(NULL) doesn't crash
void test_free_null() {
    free(NULL);
    check(1, "free(NULL) doesn't crash");
}

// Test 6: malloc and free in a loop many times
void test_malloc_free_loop() {
    int ok = 1;
    for (int i = 0; i < 100000; i++) {
        void *p = malloc(32);
        if (p == NULL) {
            ok = 0;
            break;
        }
        free(p);
    }
    check(ok, "malloc/free loop 100k times");
}

int main() {
    test_malloc_returns_non_null();
    test_write_read();
    test_no_overlap();
    test_free_and_reuse();
    test_free_null();
    test_malloc_free_loop();

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
