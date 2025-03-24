#include "strings.h"

char *strcpy(char *restrict dst, const char *restrict src) {
    size_t size = malloced_contains(dst);

    if (size) {
        memcpy(dst, src, size + 1);
        dst[size] = 0;
    }
    else {
        // о боже, спаси от переполнения буфера
        // пускай в следующей переменной на стеке будут данные

        int len = 0;
        while (!*(dst + len))
            len++;

        if (!len) { // у этой переменной есть данные на стеке
            for (int i = 0; i < strlen(src); i++) {
                if ((src[i] < 0x20 && (src[i] < 0x07 || src[i] > 0x0d)) || src[i] > 0x7e) {
                    goto exit;
                }
                len++;
            }
        }

        len = strlen(src) > len ? len : strlen(src); // может работать неправильно, если в переменной остался мусор

exit:
        memcpy(dst, src, len + 1);
        dst[len] = 0;
    }

    return dst;
}