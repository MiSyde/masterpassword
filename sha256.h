#ifndef MASTERPASSWORD_SHA256_H
#define MASTERPASSWORD_SHA256_H
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#include <stdint.h>

extern uint32_t h0;
extern uint32_t h1;
extern uint32_t h2;
extern uint32_t h3;
extern uint32_t h4;
extern uint32_t h5;
extern uint32_t h6;
extern uint32_t h7;
extern const unsigned int constants[64];
#endif