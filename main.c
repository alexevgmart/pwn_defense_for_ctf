#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>

#include "malloc_and_free.h"
#include "formats.h"
#include "strings.h"

int (*original_system)(const char *command);

__attribute__((constructor)) void library_load() {
    original_system = dlsym(RTLD_NEXT, "system");
    if (!original_system) {
        perror("Error: Unable to find original system");
        exit(1);
    }

    original_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!original_malloc) {
        perror("Error: Unable to find original malloc");
        exit(1);
    }

    original_free = dlsym(RTLD_NEXT, "free");
    if (!original_free) {
        perror("Error: Unable to find original free");
        exit(1);
    }

    original_realloc = dlsym(RTLD_NEXT, "realloc");
    if (!original_realloc) {
        perror("Error: Unable to find original realloc");
        exit(1);
    }

    original_calloc = dlsym(RTLD_NEXT, "calloc");
    if (!original_calloc) {
        perror("Error: Unable to find original calloc");
        exit(1);
    }

    dev_null = fopen("/dev/null", "w");
}

__attribute__((destructor)) void library_unload() {
    cleanup();

    if (dev_null)
        fclose(dev_null);
}

int system(const char* command) {
    if (!is_in_rodata(command)) {
        puts("No no no");
        errno = EPERM;
        perror("system");
        return -1;
    }

    return original_system(command);
}