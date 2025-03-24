#ifndef FORMATS_H
#define FORMATS_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

int is_in_rodata(const void *addr);
int printf(const char *format, ...);

#endif // FORMATS_H