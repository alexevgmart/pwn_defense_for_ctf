#include "malloc_and_free.h"
#include "formats.h"

malloced* malloced_addrs = NULL;
freed* freed_addrs = NULL;
FILE* dev_null = NULL;

void* (*original_malloc)(size_t size) = NULL;
void (*original_free)(void* ptr) = NULL;
void* (*original_realloc)(void* ptr, size_t size) = NULL;
void* (*original_calloc)(size_t nmemb, size_t size) = NULL;

pthread_mutex_t malloc_mutex = PTHREAD_MUTEX_INITIALIZER;

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    if (!original_pthread_create) {
        original_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
        if (!original_pthread_create) {
            fprintf(stderr, "Error: Unable to find original pthread_create\n");
            exit(1);
        }
    }

    // printf("Thread created: start_routine = %p, arg = %p\n", start_routine, arg);

    return original_pthread_create(thread, attr, start_routine, arg);
}

void cleanup() {
    while (malloced_addrs) {
        malloced* next = malloced_addrs->next;
        original_free(malloced_addrs);
        malloced_addrs = next;
    }

    while (freed_addrs) {
        freed* next = freed_addrs->next;
        original_free(freed_addrs);
        freed_addrs = next;
    }
}

void malloced_insert(void* addr, size_t size) {
    malloced* new_node = original_malloc(sizeof(malloced));
    if (!new_node) {
        perror("Error: Failed to allocate memory for malloced node");
        return;
    }

    new_node->addr = addr;
    new_node->size = size;
    new_node->next = malloced_addrs;
    new_node->prev = NULL;

    if (malloced_addrs) {
        malloced_addrs->prev = new_node;
    }

    malloced_addrs = new_node;
}

void print_malloced() {
    puts("============malloc============");
    malloced* tmp = malloced_addrs;
    while (tmp) {
        printf("%p: %zu bytes\n", tmp->addr, tmp->size);
        tmp = tmp->next;
    }
    puts("==============================");
}

int malloced_contains(void* ptr) {
    malloced* tmp = malloced_addrs;
    while (tmp) {
        if (tmp->addr == ptr) {
            return tmp->size;
        }
        tmp = tmp->next;
    }
    return 0;
}

void delete_malloced_addr(void* ptr) {
    malloced* tmp = malloced_addrs;
    while (tmp) {
        if (tmp->addr == ptr) {
            if (tmp->prev) {
                tmp->prev->next = tmp->next;
            } else {
                // Если удаляемый элемент — голова списка
                malloced_addrs = tmp->next;
            }

            if (tmp->next) {
                tmp->next->prev = tmp->prev;
            }

            original_free(tmp);
            return;
        }
        tmp = tmp->next;
    }
}

void delete_freed_addr(void* ptr) {
    freed* tmp = freed_addrs;
    while (tmp) {
        if (tmp->addr == ptr) {
            if (tmp->prev) {
                tmp->prev->next = tmp->next;
            } else {
                // Если удаляемый элемент — голова списка
                freed_addrs = tmp->next;
            }

            if (tmp->next) {
                tmp->next->prev = tmp->prev;
            }

            return;
        }
        tmp = tmp->next;
    }
}

void* malloc(size_t size) {
    // pthread_mutex_lock(&malloc_mutex);

    // Игнорируем вызовы malloc с размером 4096 байт, если список пуст, он служебный
    // if (size == 4096 && malloced_addrs == NULL) {
    //     return original_malloc(size);
    // }

    void* addr = original_malloc(size);
    if (!addr) {
        // pthread_mutex_unlock(&malloc_mutex);
        perror("Error: Failed to allocate memory");
        return NULL;
    }

    malloced_insert(addr, size);
    delete_freed_addr(addr);
    // pthread_mutex_unlock(&malloc_mutex);
    return addr;
}

void freed_insert(void* addr) {
    freed* new_node = original_malloc(sizeof(freed));
    if (!new_node) {
        perror("Error: Failed to allocate memory for freed node");
        return;
    }

    new_node->addr = addr;
    new_node->next = freed_addrs;
    new_node->prev = NULL;

    if (freed_addrs) {
        freed_addrs->prev = new_node;
    }

    freed_addrs = new_node;
}

void print_freed() {
    puts("=============free=============");
    freed* tmp = freed_addrs;
    while (tmp != NULL) {
        printf("%p\n", tmp->addr);
        tmp = tmp->next;
    }
    puts("==============================");
}

int freed_contains(void* ptr) {
    freed* tmp = freed_addrs;
    while (tmp) {
        if (tmp->addr == ptr) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

void check_malloced_list() {
    malloced* tmp = malloced_addrs;
    while (tmp) {
        if (tmp->prev && tmp->prev->next != tmp) {
            puts("Corrupted malloced list: prev->next mismatch");
            exit(1);
        }
        if (tmp->next && tmp->next->prev != tmp) {
            puts("Corrupted malloced list: next->prev mismatch");
            exit(1);
        }
        tmp = tmp->next;
    }
}

void check_freed_list() {
    freed* tmp = freed_addrs;
    while (tmp) {
        if (tmp->prev && tmp->prev->next != tmp) {
            puts("Corrupted freed list: prev->next mismatch");
            exit(1);
        }
        if (tmp->next && tmp->next->prev != tmp) {
            puts("Corrupted freed list: next->prev mismatch");
            exit(1);
        }
        tmp = tmp->next;
    }
}

void free(void* ptr) {
    // pthread_mutex_lock(&malloc_mutex);

    // if (original_pthread_create) // убрать состояние гонки если есть другие потоки
        // fprintf(dev_null, "free addr: %p\n", ptr); // опыт показал, что этот вывод случайно синхронизирует потоки, скрывая проблемы с гонками данных
    
    if (!ptr) {
        // pthread_mutex_unlock(&malloc_mutex);
        return;
    }

    if (freed_contains(ptr)) {
        puts("Double free detected");
        exit(1);
    }

    freed_insert(ptr);
    delete_malloced_addr(ptr);
    original_free(ptr);  

    check_malloced_list();
    check_freed_list();
    // pthread_mutex_unlock(&malloc_mutex);
}

void* realloc(void* ptr, size_t size) {
    void* addr = original_realloc(ptr, size);

    if (addr) {
        delete_malloced_addr(ptr);
        malloced_insert(addr, size);
    }

    delete_freed_addr(addr);
    return addr;
}

void* calloc(size_t nmemb, size_t size) {
    void* addr = original_calloc(nmemb, size);

    if (addr) {
        malloced_insert(addr, nmemb * size);
    }

    delete_freed_addr(addr);
    return addr;
}