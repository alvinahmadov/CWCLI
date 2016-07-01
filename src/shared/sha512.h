#ifndef _SHA512_H_
#define _SHA512_H_

#define SHA512_DIGEST_LEN 64

typedef struct {
	CW_UINT64 state[8];
	CW_UINT32 count[4];
	CW_UINT8 buf[128];
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const void *buffer, CW_UINT32 len);
void sha512_burn(SHA512_CTX *ctx);
void sha512_final(SHA512_CTX *ctx, void *result);

#endif
