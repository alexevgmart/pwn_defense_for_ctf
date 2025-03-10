#include "malloc_and_free.h"
#include "formats.h"

int is_in_rodata(const void *addr) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char line[256];
    uintptr_t start, end;
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Ищем секции с правами "r--p" (read-only, private)
        if (strstr(line, "r--p") != NULL) {
            // Парсим диапазон адресов
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                // Проверяем, попадает ли адрес в диапазон
                if ((uintptr_t)addr >= start && (uintptr_t)addr < end) {
                    fclose(fp);
                    return 1;
                }
            }
        }
    }

    fclose(fp);
    return 0;
}

int printf(const char *format, ...) {
    int result;
    va_list args;
    va_start(args, format);

    if (!is_in_rodata(format) || strstr(format, "%n")) {
        result = puts(format);
    } else {
        result = vprintf(format, args);
    }

    va_end(args);
    return result;
}