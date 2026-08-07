#ifndef MASTERPASSWORD_HMAC_H
#define MASTERPASSWORD_HMAC_H
#include <stddef.h>

unsigned char* hmac(const unsigned char* key, size_t keyLen, unsigned char* (*hash)(const unsigned char*, size_t),
                     const unsigned char* message, size_t messageLen, int blockSize, size_t hashLen);

unsigned char* computeBlockSizedKey(const unsigned char* key, size_t keyLen, unsigned char* (*hash)(const unsigned char*, size_t), size_t hashLen, int blockSize);

#endif