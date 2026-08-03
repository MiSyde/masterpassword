#ifndef MASTERPASSWORD_SALSA20_H
#define MASTERPASSWORD_SALSA20_H
#include <stdint.h>
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (         \
a += b, d ^= a, d = ROTL(d, 16), \
c += d, b ^= c, b = ROTL(b, 12), \
a += b, d ^= a, d = ROTL(d,  8), \
c += d, b ^= c, b = ROTL(b,  7))
#define ROUNDS 8

void chacha_block(uint32_t  out[16], uint32_t const in[16]);

void bytes_to_words(const unsigned char* in, uint32_t out[16]);

void words_to_bytes(const uint32_t in[16], unsigned char* out);

void chacha_block_bytes(unsigned char* out, const unsigned char* in);

#endif