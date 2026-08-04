#include "hmac.h"
#include "scrypt.h"

#include <stdlib.h>
#include <string.h>

unsigned char* hmac(const unsigned char* key, const size_t keyLen, unsigned char* (*hash)(const unsigned char*, size_t),
                     const unsigned char* message, const size_t messageLen, int const blockSize, const size_t hashLen) {

    unsigned char* blockSizedKey = computeBlockSizedKey(key, keyLen, hash, hashLen, blockSize);
    if (blockSizedKey == NULL) goto block_null_err;

    unsigned char* outerKeyPad = malloc(blockSize);
    if (outerKeyPad == NULL) goto okey_null_err;

    unsigned char* innerKeyPad = malloc(blockSize);
    if (innerKeyPad == NULL) goto ikey_null_err;

    xor_constant(outerKeyPad, blockSizedKey, 0x5c, blockSize);
    xor_constant(innerKeyPad, blockSizedKey, 0x36, blockSize);

    unsigned char* innerInput = concat(innerKeyPad, blockSize, message, strlen((char*) message));
    unsigned char* innerHash = hash(innerInput, blockSize + messageLen);

    unsigned char* outerInput = concat(outerKeyPad, blockSize, innerHash, hashLen);
    unsigned char* result = hash(outerInput, blockSize + hashLen);

    free(blockSizedKey);
    free(outerKeyPad);
    free(innerKeyPad);
    free(innerInput);
    free(innerHash);
    free(outerInput);

    return result;

    block_null_err:
        perror("Couldn't allocate memory for blockSizedKey in computeBlockSizedKey.");
        return NULL;
    okey_null_err:
        perror("Couldn't allocate memory for oKeyPad in HMAC.");
        free(blockSizedKey);
        return NULL;
    ikey_null_err:
        perror("Couldn't allocate memory for innerKeyPad in HMAC.");
        free(outerKeyPad);
        free(blockSizedKey);
        return NULL;
}

unsigned char* computeBlockSizedKey(const unsigned char* key, size_t keyLen, unsigned char* (*hash)(const unsigned char*, size_t), size_t const hashLen, int const blockSize) {
    unsigned char* result;
    if (keyLen > blockSize) {
        result = hash(key, keyLen);
        keyLen = hashLen;
    }
    else {
        result = malloc(blockSize);
        if (result == NULL)
            return NULL;
        memcpy(result, key, keyLen);
    }

    if (keyLen < blockSize) {
        memset(result + keyLen, 0, blockSize - keyLen);
    }

    return result;
}