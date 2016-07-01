#ifndef _BLOWFISH_H_
#define _BLOWFISH_H_

#define BLOWFISH_KEY_LEN    56
#define BLOWFISH_IV_LEN        8

#define P_SIZE                (16 + 2)
#define S_SIZE                (256 * 4)
#define IV_SIZE                2

typedef struct {
    CW_UINT32 P[P_SIZE];
    CW_UINT32 S[S_SIZE];
    CW_UINT32 IV[IV_SIZE];
    struct {
        CW_UINT32 P[P_SIZE];
        CW_UINT32 S[S_SIZE];
        CW_UINT32 IV[IV_SIZE];
    } _init;
} BLOWFISH_CTX;

void blowfish_init(BLOWFISH_CTX *ctx,
                   const void *key,
                   const CW_UINT8 keylen,
                   const void *iv);

void blowfish_reset(BLOWFISH_CTX *ctx);

void blowfish_encrypt(BLOWFISH_CTX *ctx,
                      const void *in_buf,
                      void *out_buf,
                      CW_UINT32 buflen);

void blowfish_decrypt(BLOWFISH_CTX *ctx,
                      const void *in_buf,
                      void *out_buf,
                      CW_UINT32 buflen);

void blowfish_final(BLOWFISH_CTX *ctx);

#endif
