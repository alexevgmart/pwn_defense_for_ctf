#ifndef STRINGS_H
#define STRINGS_H

#include <string.h>

#include "formats.h"
#include "malloc_and_free.h"

extern char* (*original_strcpy)(char *restrict dst, const char *restrict src);

char *strcpy(char *restrict dst, const char *restrict src);

#endif // STRINGS_H