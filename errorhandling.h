#ifndef MASTERPASSWORD_ERRORHANDLING_H
#define MASTERPASSWORD_ERRORHANDLING_H

void error_handler_exit(int exitcode, const char* msg, int count, ...);

unsigned char* error_handler_null(const char* msg, int count, ...);

#endif