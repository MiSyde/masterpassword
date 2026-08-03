#ifndef MASTERPASSWORD_PBKDF2_H
#define MASTERPASSWORD_PBKDF2_H

unsigned char* pbkdf2(unsigned char* passphrase, unsigned char* salt, int iterationCount, int desiredKeyLen);

#endif