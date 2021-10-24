#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void* simple_malloc(size_t size) {
    void* p = sbrk(0);
    void* request = sbrk(size);
    if (request == (void*)-1) {
        return NULL;
    } else {
        return p;
    }
}

typedef struct block_meta {
    size_t size;
    struct block_meta* next;
    int free_flag;
} block_t;

#define BLOCK_SIZE sizeof(block_t)

void* global_heap_base = NULL;

block_t* find_free_block(block_t** last, size_t size) {
    block_t* current = global_heap_base;
    while (current != NULL && !(current->free_flag && current->size >= size)) {
        *last = current;
        current = current->next;
    }
    return current;
}

block_t* request_heap_space(block_t* last, size_t size) {
    block_t* block;
    block = sbrk(0);
    void* request = sbrk(size + BLOCK_SIZE);
    if (request == (void*)-1) {
        return NULL;
    }
    if (last != NULL) {
        last->next = block;
    }
    block->size = size;
    block->next = NULL;
    block->free_flag = 0;
    return block;
}

void* malloc(size_t size) {
    block_t* block;
    if (size <= 0) {
        return NULL;
    }
    if (!global_heap_base) {
        // first call
        block = request_heap_space(NULL, size);
        if (!block) {
            return NULL;
        }
        global_heap_base = block;
    } else {
        block_t* last = global_heap_base;
        block = find_free_block(&last, size);
        if (!block) {
            block = request_heap_space(last, size);
            if (!block) {
                return NULL;
            }
        } else {
            block->free_flag = 0;
        }
    }

    return (block + 1);
}

block_t* get_block_ptr(void* ptr) {
    return (block_t*)ptr - 1;
}

void free(void* ptr) {
    if (!ptr) {
        return;
    }
    block_t* block_ptr = get_block_ptr(ptr);
    block_ptr->free_flag = 1;
}

void* realloc(void* ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    block_t* block_ptr = get_block_ptr(ptr);
    if (block_ptr->size >= size) {
        return ptr;
    }
    void* new_ptr;
    new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }
    memcpy(new_ptr, ptr, block_ptr->size);
    free(ptr);
    return new_ptr;
}

void* calloc(size_t nelem, size_t elem_size) {
    size_t size = nelem * elem_size;
    void* ptr = malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

int main() {
    printf("malloc\n");

    void* p1 = malloc(10);
    printf("pointer 1 = %zu\n", p1);

    void* p2 = malloc(100);
    printf("pointer 2 = %zu\n", p2);

    void* p3 = malloc(200);
    printf("pointer 3 = %zu\n", p3);

    void* p4 = malloc(200);
    printf("pointer 4 = %zu\n", p4);

    free(p2);

    void* p5 = malloc(20);
    printf("pointer 5 = %zu\n", p5);

    free(p4);

    p5 = realloc(p5, 20);
    printf("reallocated pointer 5 = %zu\n", p5);
}
