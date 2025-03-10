#ifndef MALLOC_AND_FREE_H
#define MALLOC_AND_FREE_H

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <dlfcn.h>

typedef struct malloced {
    void* addr;
    size_t size;
    struct malloced* prev;
    struct malloced* next;
} malloced;

typedef struct freed {
    void* addr;
    struct freed* prev;
    struct freed* next;
} freed;

extern malloced* malloced_addrs;
extern freed* freed_addrs;
extern FILE* dev_null;

extern void* (*original_malloc)(size_t size);
extern void (*original_free)(void* ptr);
extern void* (*original_realloc)(void* ptr, size_t size);
extern void* (*original_calloc)(size_t nmemb, size_t size);
static int (*original_pthread_create)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) = NULL;

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
void cleanup();
void malloced_insert(void* addr, size_t size);
void print_malloced();
int malloced_contains(void* ptr);
void delete_malloced_addr(void* ptr);
void delete_freed_addr(void* ptr);
void* malloc(size_t size);
void freed_insert(void* addr);
void print_freed();
int freed_contains(void* ptr);
void check_malloced_list();
void check_freed_list();
void free(void* ptr);

#endif // MALLOC_AND_FREE_H