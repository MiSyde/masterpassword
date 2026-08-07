cmake_minimum_required(VERSION 4.1)
project(MasterPassword C)

set(CMAKE_C_STANDARD 11)

add_executable(MasterPassword main.c
        scrypt.c
        scrypt.h
        pbkdf2.c
        pbkdf2.h
        chacha.c
        chacha.h
        hmac.c
        hmac.h
        sha256.c
        sha256.h
        errorhandling.c
        errorhandling.h)
