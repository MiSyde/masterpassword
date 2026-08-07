#include "errorhandling.h"

#include <stdarg.h>
#include <stdlib.h>

void error_handler_exit(const int exitcode, const char* msg, const int count, ...) {
    va_list args;
    va_start(args, count);

    for (int i = 0; i < count; ++i) {
        free(va_arg(args, unsigned char*));
    }
    perror(msg);
    exit(exitcode);
}

unsigned char* error_handler_null(const char* msg, const int count, ...) {
    va_list args;
    va_start(args, count);

    for (int i = 0; i < count; ++i) {
        free(va_arg(args, unsigned char*));
    }
    perror(msg);
    return NULL;
}
