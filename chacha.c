#include "chacha.h"

void chacha_block(uint32_t  out[65], uint32_t const in[16])
{
    int i;
    unsigned char x[16];

    for (i = 0; i < 16; ++i)
        x[i] = in[i];

    for (i = 0; i < ROUNDS; i += 2) {

        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);

        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}

void bytes_to_words(const unsigned char* in, uint32_t out[16]) {
    for (int i = 0; i < 16; ++i) {
        out[i] = (uint32_t)in[4*i]
                | ((uint32_t)in[4*i+1] << 8)
                | ((uint32_t)in[4*i+2] << 16)
                | ((uint32_t)in[4*i+3] << 24);
    }
}

void words_to_bytes(const uint32_t in[16], unsigned char* out) {
    for (int i = 0; i < 16; ++i) {
        out[4*i]   = in[i] & 0xff;
        out[4*i+1] = (in[i] >> 8) & 0xff;
        out[4*i+2] = (in[i] >> 16) & 0xff;
        out[4*i+3] = (in[i] >> 24) & 0xff;
    }
}

void chacha_block_bytes(unsigned char* out, const unsigned char* in) {
    uint32_t win[16], wout[16];
    bytes_to_words(in, win);
    chacha_block(wout, win);
    words_to_bytes(wout, out);
}