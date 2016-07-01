#ifndef _RND_H_
#define _RND_H_

#define UPDATE_POOL_TIMEOUT 60 /* sec */


typedef struct {
    CW_UINT8 seed[SHA512_DIGEST_LEN];
    BLOWFISH_CTX bf;
    pthread_t upool_thrd;
    pthread_mutex_t r_mtx;
} RND_CTX;


CWERROR rnd_init(void);

void rnd_getbytes(void *buffer, const CW_UINT32 needed);

CWERROR rnd_getchars(char *buffer, const CW_UINT32 needed);

void rnd_final(void);

#endif
