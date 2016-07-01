#include "general.h"
#include "errors.h"
#include "sha256.h"
#include "sha512.h"

#include "hmac256.h"

void hmac256_init(HMAC256_CTX *ctx, const void *key, const CW_UINT8 keylen) {
  register CW_UINT8 i;

  mlock(ctx, sizeof(HMAC256_CTX));

  memcpy(&ctx->k_ipad[(CW_UINT8) sizeof(ctx->k_ipad) - keylen], key, keylen);
  memcpy(&ctx->k_opad[(CW_UINT8) sizeof(ctx->k_opad) - keylen], key, keylen);

  for (i = 0; i < (CW_UINT8) sizeof(ctx->k_ipad) - keylen; i++)
    ctx->k_ipad[i] = ctx->k_opad[i] = 0x00;

  for (i = 0; i < (CW_UINT8) sizeof(ctx->k_ipad); i++) {
    ctx->k_ipad[i] ^= 0x36;
    ctx->k_opad[i] ^= 0x5A;
  }
}

void hmac256_update_first(HMAC256_CTX *ctx, const void *buffer, CW_UINT32 len) {
  sha256_init(&ctx->sha256);
  sha256_update(&ctx->sha256, ctx->k_ipad, sizeof(ctx->k_ipad));
  sha256_update(&ctx->sha256, buffer, len);
}

void __inline hmac256_update_next(HMAC256_CTX *ctx, const void *buffer, CW_UINT32 len) {
  sha256_update(&ctx->sha256, buffer, len);
}

void hmac256_final(HMAC256_CTX *ctx, void *result) {
  CW_UINT8 hash[SHA256_DIGEST_LEN];

  sha256_final(&ctx->sha256, hash);

  sha256_init(&ctx->sha256);
  sha256_update(&ctx->sha256, ctx->k_opad, sizeof(ctx->k_opad));
  sha256_update(&ctx->sha256, hash, sizeof(hash));
  sha256_final(&ctx->sha256, result);
}

void __inline hmac256_burn(HMAC256_CTX *ctx) {
  memset(ctx, 0, sizeof(HMAC256_CTX));
  munlock(ctx, sizeof(HMAC256_CTX));
}
