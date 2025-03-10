#include "strings.h"

char* (*original_strcpy)(char *restrict dst, const char *restrict src) = NULL;

char *strcpy(char *restrict dst, const char *restrict src) {
    size_t size = malloced_contains(dst);
    char* result;

    if (size) {
        result = strncpy(dst, src, size + 1);
        dst[size] = 0;
    }
    else {
        // о боже, спаси от переполнения буфера
        // пускай в следующей переменной на стеке будут данные

        int len = 0;
        while (!*(dst + len))
            len++;

        len = strlen(src) > len ? len : strlen(src);

        result = strncpy(dst, src, len + 1);
        dst[len] = 0;
    }

    return result;
}