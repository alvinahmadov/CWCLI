#include "general.h"
#include "errors.h"
#include "crypto.h"
#include "usock.h"

#include "packets.h"

static long recv_timeout;

void packets_startup(const long timeout) {
  recv_timeout = timeout;
}

void packet_get_stat(CW_PACKETS_CTX *ctx, CW_UINT64 *in_bytes, CW_UINT64 *out_bytes) {
  pthread_mutex_lock(&ctx->send_mtx);
  pthread_mutex_lock(&ctx->recv_mtx);

  *in_bytes = ctx->in_bytes;
  *out_bytes = ctx->out_bytes;

  pthread_mutex_unlock(&ctx->send_mtx);
  pthread_mutex_unlock(&ctx->recv_mtx);
}

void packet_set_crypto(CW_PACKETS_CTX *ctx, const void *key, const void *siv, const void *riv) {
  hmac256_init(&ctx->hmac256, key, SESSION_KEY_LEN);
  blowfish_init(&ctx->bf_send, key, BLOWFISH_KEY_LEN, siv);
  blowfish_init(&ctx->bf_recv, key, BLOWFISH_KEY_LEN, riv);
}

CWERROR packet_send_raw(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type) {

  CW_PACKET_HEADER pckt_head;
  int sz = sizeof(pckt_head);

  /* make packet header */
  pckt_head.tl.type = type;
  pckt_head.tl.len = (CW_UINT32) len;

  pthread_mutex_lock(&ctx->send_mtx);

  /* send packet header */
  if (send_buf(ctx->sock, (char *) &pckt_head, &sz) == SOCK_ER_SEND) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != sizeof(pckt_head)) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }

  ctx->out_bytes += sizeof(pckt_head);

  /* send data */
  sz = len;
  if (send_buf(ctx->sock, (char *) buf, &sz) == SOCK_ER_SEND) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != len) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }

  ctx->out_bytes += len;

  pthread_mutex_unlock(&ctx->send_mtx);

  return CW_ER_OK;
}

CWERROR packet_recv_raw(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type) {
  CW_PACKET_HEADER pckt_head;
  int r, sz = sizeof(pckt_head);

  pthread_mutex_lock(&ctx->recv_mtx);

  /* receve packet header */
  r = recv_buf(ctx->sock, (char *) &pckt_head, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != sizeof(pckt_head))) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += sizeof(pckt_head);

  /* check if there is enaugh space in buffer */
  if ((pckt_head.tl.len > (CW_UINT32) buf_len) || (pckt_head.tl.len == 0)) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  *len = (int) pckt_head.tl.len;
  *type = pckt_head.tl.type;

  /* receve data */
  sz = (int) pckt_head.tl.len;
  r = recv_buf(ctx->sock, buf, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != (int) pckt_head.tl.len)) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += pckt_head.tl.len;

  pthread_mutex_unlock(&ctx->recv_mtx);

  return CW_ER_OK;
}

CWERROR packet_send_crypted(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type) {
  CW_PACKET_HEADER pckt_head;
  CW_UINT8 *tbuf = NULL;
  int sz = sizeof(pckt_head);
  CWERROR err = CW_ER_OK;

  pckt_head.tl.type = type;
  pckt_head.tl.len = (CW_UINT32) len;

  pthread_mutex_lock(&ctx->send_mtx);

  hmac256_update_first(&ctx->hmac256, &pckt_head.tl, sizeof(pckt_head.tl));
  hmac256_update_next(&ctx->hmac256, buf, len);
  hmac256_final(&ctx->hmac256, pckt_head.hmac);
  blowfish_encrypt(&ctx->bf_send, &pckt_head, &pckt_head, sizeof(pckt_head));

  if (send_buf(ctx->sock, (char *) &pckt_head, &sz) == SOCK_ER_SEND) {
    DEBUG_ERROR();
    err = CW_ER_SEND;
    goto err_exit;
  }
  if (sz != sizeof(pckt_head)) {
    DEBUG_ERROR();
    err = CW_ER_SEND;
    goto err_exit;
  }

  ctx->out_bytes += sizeof(pckt_head);

  if ((tbuf = malloc(len)) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_MEMORY;
    goto err_exit;
  }

  blowfish_encrypt(&ctx->bf_send, buf, tbuf, len);

  sz = len;
  if (send_buf(ctx->sock, (char *) tbuf, &sz) == SOCK_ER_SEND) {
    DEBUG_ERROR();
    err = CW_ER_SEND;
    goto err_exit;
  }
  if (sz != len) {
    DEBUG_ERROR();
    err = CW_ER_SEND;
    goto err_exit;
  }

  ctx->out_bytes += len;

  err_exit:

  pthread_mutex_unlock(&ctx->send_mtx);

  if (tbuf) {
    free(tbuf);
  }

  return err;
}

CWERROR packet_recv_crypted(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type) {
  CW_PACKET_HEADER pckt_head;
  CW_UINT8 hmac[HMAC256_DIGEST_LEN];
  int r, sz = sizeof(pckt_head);

  pthread_mutex_lock(&ctx->recv_mtx);

  r = recv_buf(ctx->sock, (char *) &pckt_head, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != sizeof(pckt_head))) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += sizeof(pckt_head);

  /* decrypt packet header */
  blowfish_decrypt(&ctx->bf_recv, &pckt_head, &pckt_head, sizeof(pckt_head));

  if ((pckt_head.tl.len > (CW_UINT32) buf_len) || (pckt_head.tl.len == 0)) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  *len = (int) pckt_head.tl.len;
  *type = pckt_head.tl.type;

  sz = (int) pckt_head.tl.len;
  r = recv_buf(ctx->sock, buf, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != (int) pckt_head.tl.len)) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += pckt_head.tl.len;

  /* decrypt packet */
  blowfish_decrypt(&ctx->bf_recv, buf, buf, (CW_UINT32) pckt_head.tl.len);

  hmac256_update_first(&ctx->hmac256, &pckt_head.tl, sizeof(pckt_head.tl));
  hmac256_update_next(&ctx->hmac256, buf, (CW_UINT32) pckt_head.tl.len);
  hmac256_final(&ctx->hmac256, hmac);

  if (memcmp(pckt_head.hmac, hmac, sizeof(hmac)) != 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_HMAC;
  }

  pthread_mutex_unlock(&ctx->recv_mtx);

  return CW_ER_OK;
}

CWERROR packet_send_mixed(CW_PACKETS_CTX *ctx, const void *buf, const int len, const CW_PACKET_TYPE type) {
  CW_PACKET_HEADER pckt_head;
  int sz = sizeof(pckt_head);

  /* make packet header */
  pckt_head.tl.type = type;
  pckt_head.tl.len = (CW_UINT32) len;

  pthread_mutex_lock(&ctx->send_mtx);

  hmac256_update_first(&ctx->hmac256, &pckt_head.tl, sizeof(pckt_head.tl));
  hmac256_update_next(&ctx->hmac256, buf, len);
  hmac256_final(&ctx->hmac256, pckt_head.hmac);
  blowfish_encrypt(&ctx->bf_send, &pckt_head, &pckt_head, sizeof(pckt_head));

  /* send packet header */
  if (send_buf(ctx->sock, (char *) &pckt_head, &sz) == SOCK_ER_SEND) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != sizeof(pckt_head)) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }

  ctx->out_bytes += sizeof(pckt_head);

  /* send data */
  sz = len;
  if (send_buf(ctx->sock, (char *) buf, &sz) == SOCK_ER_SEND) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }
  if (sz != len) {
    pthread_mutex_unlock(&ctx->send_mtx);
    DEBUG_ERROR();
    return CW_ER_SEND;
  }

  ctx->out_bytes += len;

  pthread_mutex_unlock(&ctx->send_mtx);

  return CW_ER_OK;
}

CWERROR packet_recv_mixed(CW_PACKETS_CTX *ctx, void *buf, const int buf_len, int *len, CW_PACKET_TYPE *type) {
  CW_PACKET_HEADER pckt_head;
  CW_UINT8 hmac[HMAC256_DIGEST_LEN];
  int r, sz = sizeof(pckt_head);

  pthread_mutex_lock(&ctx->recv_mtx);

  /* receve packet header */
  r = recv_buf(ctx->sock, (char *) &pckt_head, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != sizeof(pckt_head))) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += sizeof(pckt_head);

  /* decrypt packet header */
  blowfish_decrypt(&ctx->bf_recv, &pckt_head, &pckt_head, sizeof(pckt_head));

  /* check if there is enaugh space in buffer */
  if ((pckt_head.tl.len > (CW_UINT32) buf_len) || (pckt_head.tl.len == 0)) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_PCKT;
  }

  *len = (int) pckt_head.tl.len;
  *type = pckt_head.tl.type;

  /* receve data */
  sz = (int) pckt_head.tl.len;
  r = recv_buf(ctx->sock, buf, &sz, recv_timeout);
  if (r <= 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    if (r == SOCK_ER_RECV_TIMEOUT) {
      return CW_ER_RECV_TIMEOUT;
    } else if ((r == SOCK_ER_RECV_DISCONN) || (r == SOCK_ER_RECV) || (sz != (int) pckt_head.tl.len)) {
      DEBUG_ERROR();
      return CW_ER_RECV;
    }
  }

  ctx->in_bytes += pckt_head.tl.len;

  hmac256_update_first(&ctx->hmac256, &pckt_head.tl, sizeof(pckt_head.tl));
  hmac256_update_next(&ctx->hmac256, buf, (CW_UINT32) pckt_head.tl.len);
  hmac256_final(&ctx->hmac256, hmac);

  if (memcmp(pckt_head.hmac, hmac, sizeof(hmac)) != 0) {
    pthread_mutex_unlock(&ctx->recv_mtx);
    DEBUG_ERROR();
    return CW_ER_WRONG_HMAC;
  }

  pthread_mutex_unlock(&ctx->recv_mtx);

  return CW_ER_OK;
}
