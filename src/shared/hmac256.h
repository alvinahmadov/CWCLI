#ifndef _HMAC256_H_
#define _HMAC256_H_
#define HMAC256_DIGEST_LEN    SHA256_DIGEST_LEN
#define HMAC256_MAX_KEY_LEN    SHA512_DIGEST_LEN

typedef struct {
    SHA256_CTX sha256;
    CW_UINT8 k_ipad[HMAC256_MAX_KEY_LEN];
    CW_UINT8 k_opad[HMAC256_MAX_KEY_LEN];
} HMAC256_CTX;

void hmac256_init(HMAC256_CTX *ctx, const void *key, const CW_UINT8 keylen);

void hmac256_update_first(HMAC256_CTX *ctx, const void *buffer, CW_UINT32 len);

void hmac256_update_next(HMAC256_CTX *ctx, const void *buffer, CW_UINT32 len);

void hmac256_final(HMAC256_CTX *ctx, void *result);

void hmac256_burn(HMAC256_CTX *ctx);

#endif
