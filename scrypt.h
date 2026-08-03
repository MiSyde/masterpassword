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
 * @param mixFuncLen The length in octets of the output of the mixing function.
 * @return The derived key, an array of bytes, DesiredKeyLen long
 */
unsigned char* scrypt(unsigned char* passPhrase, unsigned char* salt, int costFactor, int blockSizeFactor,
                      int parallelizationFactor, int desiredKeyLen, int mixFuncLen);

void ROMix(unsigned char* block, int blockSize, int iterations);

unsigned char* BlockMix(unsigned char* block, unsigned char* Y, int blockSize);

uint64_t Integrify(const unsigned char* x, int blockSize);

inline void xor(unsigned char* block, const unsigned char* other, int const blockSize) {
    for (int i = 0; i < blockSize; ++i) {
        block[i] ^= other[i];
    }
}

#endif