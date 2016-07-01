#ifndef _SHA256_H_
#define _SHA256_H_

#define SHA256_DIGEST_LEN 32

typedef struct {
    CW_UINT32 state[8];
    CW_UINT32 count[2];
    CW_UINT8 buf[128];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);

void sha256_update(SHA256_CTX *ctx, const void *buffer, CW_UINT32 len);

void sha256_burn(SHA256_CTX *ctx);

void sha256_final(SHA256_CTX *ctx, void *result);

#endif