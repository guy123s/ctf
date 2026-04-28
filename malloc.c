#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#define NUM_POOLS    10
#define POOL_SIZE    0x1000
#define ARENA_SIZE   0x100000
#define HEADER_SIZE  4

typedef void *(*malloc_fn)(size_t);

static malloc_fn real_malloc;

static malloc_fn get_real_malloc() {
    if (!real_malloc) {
        real_malloc = (malloc_fn)dlsym(RTLD_NEXT, "malloc");
        if (!real_malloc) {
            const char err[] = "malloc hook init failed\n";
            write(STDERR_FILENO, err, sizeof err - 1);
            _exit(1);
        }
    }
    return real_malloc;
}

typedef struct node {
    struct node *next;
    void *cur;
} node;

typedef struct pool {
    node *free_list;
    size_t size;
} pool;

typedef struct arena {
    char *buf;
    int index;
    pool pools[NUM_POOLS];
} arena;

static arena global_arena;

static node *create_pool_list(size_t node_size) {
    malloc_fn rmalloc = get_real_malloc();
    void *beg = global_arena.buf + global_arena.index;
    int count = POOL_SIZE / (node_size + HEADER_SIZE);

    node *head = rmalloc(sizeof(node));
    node *cur = head;
    head->cur = beg;
    head->next = NULL;

    for (int i = 1; i < count; i++) {
        node *n = rmalloc(sizeof(node));
        n->cur = beg + i * (node_size + HEADER_SIZE);
        n->next = NULL;
        cur->next = n;
        cur = n;
    }
    return head;
}

static void init_malloc() {
    global_arena.index = 0;
    global_arena.buf = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    for (int i = 0; i < NUM_POOLS; i++) {
        global_arena.pools[i].size = 1 << i;
        global_arena.pools[i].free_list = create_pool_list(1 << i);
        global_arena.index += POOL_SIZE;
    }
}

void *malloc(size_t size) {
    if (!global_arena.buf)
        init_malloc();

    for (int i = 0; i < NUM_POOLS; i++) {
        pool *p = &global_arena.pools[i];
        if (size <= p->size && p->free_list) {
            node *cur = p->free_list;
            p->free_list = cur->next;
            *(int *)cur->cur = p->size;
            return cur->cur + HEADER_SIZE;
        }
    }
    return NULL;
}

void free(void *ptr) {
    if (!ptr) return;

    void *chunk = ptr - HEADER_SIZE;
    size_t size = *(int *)chunk;

    for (int i = 0; i < NUM_POOLS; i++) {
        if (size == global_arena.pools[i].size) {
            node *n = get_real_malloc()(sizeof(node));
            n->cur = chunk;
            n->next = global_arena.pools[i].free_list;
            global_arena.pools[i].free_list = n;
            return;
        }
    }
}
