#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "rsaref.h"
#include "rsa.h"
#include "blowfish.h"
#include "sha256.h"
#include "sha512.h"
#include "hmac256.h"
#include "rnd.h"
#include "my_crc32.h"

#define MAX_PASSWORD_LEN    128
#define MAX_RSA_BLOCK_LEN    512
#define SESSION_KEY_LEN        SHA512_DIGEST_LEN
#define EFS_KEY_LEN         SHA512_DIGEST_LEN
#define RNDSALT_LEN         8

#define BLOWFISH_ENCRYPT(bf, key, buf, bufsz) { \
    blowfish_init(&(bf), (key), BLOWFISH_KEY_LEN, &(key)[BLOWFISH_KEY_LEN]); \
    blowfish_encrypt(&(bf), (buf), (buf), (bufsz)); \
    blowfish_final(&(bf)); \
}

#define BLOWFISH_DECRYPT(bf, key, buf, bufsz) { \
    blowfish_init(&(bf), (key), BLOWFISH_KEY_LEN, &(key)[BLOWFISH_KEY_LEN]); \
    blowfish_decrypt(&(bf), (buf), (buf), (bufsz)); \
    blowfish_final(&(bf)); \
}

#define SHA256_GET_HASH(sha256, buf, bufsz, res) { \
    sha256_init(&(sha256)); \
    sha256_update(&(sha256), (buf), (bufsz)); \
    sha256_final(&(sha256), (res)); \
}

typedef R_RSA_PROTO_KEY RSA_PROTO_KEY;
typedef R_RSA_PUBLIC_KEY RSA_PUBLIC_KEY;
typedef R_RSA_PRIVATE_KEY RSA_PRIVATE_KEY;
typedef R_RANDOM_STRUCT RSA_RANDOM_STRUCT;

typedef struct {
    CW_UINT32 len;
    CW_UINT8 data[MAX_RSA_BLOCK_LEN];
} CW_RSA_ENCRYPTED_DATA;

#endif