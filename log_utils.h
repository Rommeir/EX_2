#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static inline void print_log(const char* who, const char* type, const char* format, ...) {
    printf("%ld [%s] [%s] ", time(NULL), who, type);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

#endif 
