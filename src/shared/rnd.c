#include "general.h"
#include <math.h>
#include "errors.h"
#include "blowfish.h"
#include "sha512.h"
#include "utils.h"

#include "rnd.h"

static const char _char_tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static RND_CTX rnd;
static CW_BOOL inited = FALSE;

static void __fastcall _rnd_getblock64(void *buffer, const CW_UINT8 needed) {
  SHA512_CTX sha512;
  CW_UINT8 dtbuf[SHA512_DIGEST_LEN];
  time_t t;

  /* initialize SHA-512 */
  sha512_init(&sha512);
  /* get current time */
  t = time(NULL);
  /* generate dtbuf from time */
  sha512_update(&sha512, &t, sizeof(t));
  sha512_final(&sha512, dtbuf);
  t = (time_t) 0;

  /* encrypt dtbuf */
  blowfish_encrypt(&rnd.bf, dtbuf, dtbuf, sizeof(dtbuf));
  /* rnd.seed ^= dtbuf */
  bufs_xor(rnd.seed, dtbuf, sizeof(dtbuf));
  /* encrypt seed */
  blowfish_encrypt(&rnd.bf, rnd.seed, rnd.seed, sizeof(rnd.seed));

  /* generate random buffer from seed */
  memcpy(buffer, rnd.seed, needed);

  /* rnd.seed ^= dtbuf */
  bufs_xor(rnd.seed, dtbuf, sizeof(dtbuf));
  /* encrypt seed */
  blowfish_encrypt(&rnd.bf, rnd.seed, rnd.seed, sizeof(rnd.seed));

  /* wipe sensitive data */
  memset(dtbuf, 0, sizeof(dtbuf));
}

THREAD_PROC(_update_pool_proc) {
  SHA512_CTX sha512;
  CW_UINT8 pool[RANDOM_POOL_SZ], hash[SHA512_DIGEST_LEN];

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  while (TRUE) {
    delay(UPDATE_POOL_TIMEOUT * 1000);

    if (!platform_get_rndbuf(pool)) {
      DEBUG_ERROR();
      continue;
    }
    sha512_init(&sha512);
    sha512_update(&sha512, pool, sizeof(pool));
    sha512_final(&sha512, hash);

    pthread_mutex_lock(&rnd.r_mtx);
    bufs_xor(rnd.seed, hash, sizeof(hash));
    pthread_mutex_unlock(&rnd.r_mtx);

    memset(pool, 0, sizeof(pool));
    memset(hash, 0, sizeof(hash));
  }

  return THREAD_RET;
}


CWERROR rnd_init(void) {
  SHA512_CTX sha512;
  CW_UINT8 pool[RANDOM_POOL_SZ], key[SHA512_DIGEST_LEN];
  CWERROR err = CW_ER_OK;

  mlock(&rnd.seed, sizeof(rnd.seed));
  mlock(key, sizeof(key));
  mlock(pool, sizeof(pool));

  MUTEX_INIT(rnd.r_mtx);
  pthread_mutex_init(&rnd.r_mtx, NULL);

  if (!platform_get_rndbuf(pool)) {
    DEBUG_ERROR();
    err = CW_ER_RND;
    goto err_exit;
  }

  /* generate seed from 1st part of random buffer */
  sha512_init(&sha512);
  sha512_update(&sha512, pool, sizeof(pool) / 2);
  sha512_final(&sha512, rnd.seed);

  /* generate key from 2nd part of random buffer */
  sha512_init(&sha512);
  sha512_update(&sha512, &pool[sizeof(pool) / 2], sizeof(pool) - (sizeof(pool) / 2));
  sha512_final(&sha512, key);

  /* initialize cipher */
  blowfish_init(&rnd.bf, key, BLOWFISH_KEY_LEN, &key[BLOWFISH_KEY_LEN]);

  rnd.upool_thrd = PTHREAD_INITIALIZER;
  if (!THREAD_SUCCESS(CREATE_THREAD(rnd.upool_thrd, _update_pool_proc, NULL))) {
    DEBUG_ERROR();
    err = CW_ER_CREATE_THREAD;
    goto err_exit;
  }
  pthread_detach(rnd.upool_thrd);

  inited = TRUE;

  err_exit:

  memset(key, 0, sizeof(key));
  memset(pool, 0, sizeof(pool));

  munlock(key, sizeof(key));
  munlock(pool, sizeof(pool));

  if (err != CW_ER_OK) {
    if (rnd.upool_thrd != PTHREAD_INITIALIZER) {
      pthread_cancel(rnd.upool_thrd);
    }
    blowfish_final(&rnd.bf);
    munlock(&rnd.seed, sizeof(rnd.seed));
    pthread_mutex_destroy(&rnd.r_mtx);
  }

  return err;
}

void rnd_getbytes(void *buffer, const CW_UINT32 needed) {
  register CW_UINT8 *pb = (CW_UINT8 *) buffer;
  register CW_UINT32 blck_cnt = needed / SHA512_DIGEST_LEN;
  CW_UINT8 tail_len = (CW_UINT8) (needed % SHA512_DIGEST_LEN);
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&rnd.r_mtx);

  while (blck_cnt--) {
    _rnd_getblock64(pb, SHA512_DIGEST_LEN);
    pb += SHA512_DIGEST_LEN;
  }
  if (tail_len > 0) {
    _rnd_getblock64(pb, tail_len);
  }

  pthread_mutex_unlock(&rnd.r_mtx);
}

CWERROR rnd_getchars(char *buffer, const CW_UINT32 needed) {
  register char *t_buf = NULL;
  register CW_UINT32 i;
  register CW_UINT8 b;
  CWERROR err = CW_ER_OK;

  pthread_mutex_lock(&rnd.r_mtx);

  if ((t_buf = malloc(needed)) == NULL) {
    DEBUG_ERROR();
    pthread_mutex_unlock(&rnd.r_mtx);
    return CW_ER_MEMORY;
  }

  rnd_getbytes(t_buf, needed);

  for (i = 0; i < needed; i++) {
    b = (CW_UINT8) (t_buf[i] % (sizeof(_char_tbl) - 1));
    buffer[i] = _char_tbl[b];
  }
  buffer[needed] = '\0';

  free(t_buf);

  pthread_mutex_unlock(&rnd.r_mtx);

  return CW_ER_OK;
}

void rnd_final(void) {
  if (!inited)
    return;

  pthread_mutex_lock(&rnd.r_mtx);

  pthread_cancel(rnd.upool_thrd);
  blowfish_final(&rnd.bf);
  memset(&rnd.seed, 0, sizeof(rnd.seed));
  munlock(&rnd.seed, sizeof(rnd.seed));

  pthread_mutex_destroy(&rnd.r_mtx);
}
