#ifndef MASTERPASSWORD_SCRYPT_H
#define MASTERPASSWORD_SCRYPT_H
#include <stdint.h>

/**
 * A costly key derivation function - preventing brute forcing.
 * @param passPhrase String of characters to be hashed.
 * @param salt String of random characters that modifies the hash to protect against Rainbow table attacks.
 * @param costFactor CPU/memory cost parameter – Must be a power of 2.
 * @param blockSizeFactor Blocksize parameter, which fine-tunes sequential memory read size and performance.
 * @param parallelizationFactor Parallelization parameter.
 * @param desiredKeyLen Desired key length in bytes.
 * @param hashLen The length in octets of the hash function.
 * @param mixFuncLen The length in octets of the output of the mixing function.
 * @return The derived key, an array of bytes, DesiredKeyLen long
 */
unsigned char* scrypt(unsigned char* passPhrase, unsigned char* salt, int costFactor, int blockSizeFactor,
                      int parallelizationFactor, int desiredKeyLen, int hashLen, int mixFuncLen);

void ROMix(unsigned char* block, int blockSize, int iterations);

unsigned char* BlockMix(const unsigned char* block, unsigned char* Y, int blockSize);

uint64_t Integrify(const unsigned char* x, int blockSize);

inline void xor_block(unsigned char* result, const unsigned char* block, const unsigned char* other_block, int const blockSize) {
    for (int i = 0; i < blockSize; ++i) {
        result[i] = block[i] ^ other_block[i];
    }
}

inline void xor_constant(unsigned char* dst, const unsigned char* src, unsigned char constant, int len) {
    for (int i = 0; i < len; ++i) {
        dst[i] = src[i] ^ constant;
    }
}

unsigned char* concat(const unsigned char* a, size_t aLen, const unsigned char* b, size_t bLen);

#endif