#include "scrypt.h"
#include "Math.h"
#include "pbkdf2.h"
#include "chacha.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned char* scrypt(unsigned char* passPhrase, unsigned char* salt, int const costFactor, int const blockSizeFactor,
                      int parallelizationFactor, int const desiredKeyLen, int const hashLen, int const mixFuncLen) {

    double const logOfCostFactor = log2(costFactor);

    if (logOfCostFactor == 0 || modf(logOfCostFactor, (double*)2) != 0) goto cost_fact_err;
    if (parallelizationFactor > pow(2, 32) - 1) goto paralell_err;

    parallelizationFactor *= hashLen/mixFuncLen;
    int const blockSize = 128 * blockSizeFactor;

    unsigned char* initialData = pbkdf2(passPhrase, salt, 1, blockSize*parallelizationFactor);
    if (initialData == NULL) goto init_null_err;

    for (int i = 0; i < parallelizationFactor; ++i) {
        ROMix(initialData + i, blockSize, costFactor);
    }

    free(initialData);
    return pbkdf2(passPhrase, initialData, 1, desiredKeyLen);

    cost_fact_err:
        perror("Cost factor is not a power of 2.");
        exit(2);

    paralell_err:
        perror("Parallelization factor is bigger than the 32th power of 2 - 1.");
        exit(32);

    init_null_err:
        perror("Couldn't allocate memory for initial data.");
        exit(-1);
}

void ROMix(unsigned char* block, int const blockSize, int const iterations) {
    unsigned char* X = malloc(iterations * blockSize);
    if (X == NULL) goto x_null_err;

    unsigned char* V = malloc(blockSize);
    if (V == NULL) goto v_null_err;

    unsigned char* Y = malloc((blockSize/128)*2-1);
    if (Y == NULL) goto y_null_err;


    memcpy(X, block, blockSize);

    for (int i = 0; i < iterations; ++i) {
        memcpy(V + i * blockSize, X, blockSize);
        memcpy(X, BlockMix(X, Y, blockSize), blockSize);
    }

    for (int i = 0; i < iterations; ++i) {
        uint64_t const j = Integrify(X, blockSize) % iterations;
        xor_block(X, X, V + j * blockSize, blockSize);
        unsigned char* temp = BlockMix(X, Y, blockSize);
        memcpy(X, temp , blockSize);
        free(temp);
    }

    memcpy(block, X, blockSize);

    free(V);
    free(X);
    free(Y);

    x_null_err:
        free(block);
        perror("Couldn't allocate memory for X in ROMix.");
        exit(-1);

    v_null_err:
        free(block);
        free(X);
        perror("Couldn't allocate memory for V in ROMix.");
        exit(-1);

    y_null_err:
        free(block);
        free(X);
        free(V);
        perror("Couldn't allocate memory for Y in ROMix.");
        exit(-1);
}

unsigned char* BlockMix(const unsigned char* block, unsigned char* Y, int const blockSize) {
    int const r = blockSize / 128;
    int const chunkCount = 2 * r;
    int const chunkSize = 64;

    unsigned char* X = malloc(chunkSize);
    if (X == NULL) {
        perror("Couldn't allocate memory for X in BlockMix.");
        exit(-1);
    }
    memcpy(X, block + (chunkCount - 1) * chunkSize, chunkSize);

    for (int i = 0; i < chunkCount; ++i) {
        xor_block(X,X, block + i * chunkSize, chunkSize);
        chacha_block_bytes(X,X);
        memcpy(Y + i * chunkSize, X, chunkSize);
    }

    unsigned char* result = malloc(blockSize);
    int pos = 0;
    for (int i = 0; i < chunkCount; i += 2) {
        memcpy(result + pos, Y + i * chunkSize, chunkSize);
        pos += chunkSize;
    }
    for (int i = 1; i < chunkCount; i += 2) {
        memcpy(result + pos, Y + i * chunkSize, chunkSize);
        pos += chunkSize;
    }
    return result;
}

uint64_t Integrify(const unsigned char* x, int const blockSize) {
    const unsigned char* last64 = x + blockSize - 64;

    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= ((uint64_t)last64 + i) << (8 * i);
    }

    return result;
}

unsigned char* concat(const unsigned char* a, const size_t aLen, const unsigned char* b, const size_t bLen) {
    unsigned char* result = malloc(aLen + bLen);
    if (result == NULL) {
        perror("Couldn't allocate memory for concat result.");
        exit(-1);
    }
    memcpy(result, a, aLen);
    memcpy(result + aLen, b, bLen);
    return result;
}