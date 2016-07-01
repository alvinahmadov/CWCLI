#ifndef _PACKETS_H_
#define _PACKETS_H_

typedef CW_UINT8 CW_PACKET_TYPE;

#include "align1.h"

typedef struct {
    struct {
        CW_PACKET_TYPE type;
        CW_UINT32 len;
    } tl;
    CW_UINT8 hmac[HMAC256_DIGEST_LEN];
} CW_PACKET_HEADER;

#include "align_def.h"

typedef struct {
    pthread_mutex_t send_mtx;
    pthread_mutex_t recv_mtx;
    SOCKET sock;
    CW_UINT64 in_bytes;
    CW_UINT64 out_bytes;
    CW_UINT64 left;
    BLOWFISH_CTX bf_send;
    BLOWFISH_CTX bf_recv;
    HMAC256_CTX hmac256;
} CW_PACKETS_CTX;


#define PACKET_INIT(_ctx) { \
    MUTEX_INIT((_ctx).send_mtx); \
    MUTEX_INIT((_ctx).recv_mtx); \
    pthread_mutex_init(&((_ctx).send_mtx), NULL); \
    pthread_mutex_init(&((_ctx).recv_mtx), NULL); \
    (_ctx).sock = INVALID_SOCKET; \
    (_ctx).in_bytes = (_ctx).out_bytes = (_ctx).left = 0; \
}

#define PACKET_CONNECTED(_ctx)  ((_ctx).sock != INVALID_SOCKET)

#define PACKET_BIND(_ctx, _sock) (_ctx).sock = (_sock)

#define PACKET_FINAL(_ctx) { \
    if ((_ctx).sock != INVALID_SOCKET) { \
        shutdown((_ctx).sock, SD_BOTH); \
        closesocket((_ctx).sock); \
    } \
    blowfish_final(&((_ctx).bf_send)); \
    blowfish_final(&((_ctx).bf_recv)); \
    hmac256_burn(&((_ctx).hmac256)); \
    pthread_mutex_destroy(&((_ctx).send_mtx)); \
    pthread_mutex_destroy(&((_ctx).recv_mtx)); \
}

void packets_startup(const long timeout);

void packet_get_stat(CW_PACKETS_CTX *ctx, CW_UINT64 *in_bytes, CW_UINT64 *out_bytes);

void packet_set_crypto(CW_PACKETS_CTX *ctx, const void *key, const void *siv, const void *riv);

/* raw packets */

CWERROR packet_send_raw(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type);

CWERROR packet_recv_raw(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type);

/* crypted packets */

CWERROR packet_send_crypted(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type);

CWERROR packet_recv_crypted(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type);

/* mixed packets */

CWERROR packet_send_mixed(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type);

CWERROR packet_recv_mixed(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type);

#endif
