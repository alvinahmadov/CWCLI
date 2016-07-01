#include "general.h"
#include "errors.h"

#include "active_buf.h"

CWERROR active_buf_init(CW_ACTIVE_BUFFER *ab,
                        const CW_UINT32 size,
                        AB_ON_FULL_FUNC on_full_func) {
  if ((ab->buf = (CW_UINT8 *) malloc(size)) == NULL) {
    DEBUG_ERROR();
    return CW_ER_MEMORY;
  }

  ab->pb = 0;
  ab->sz = size;
  ab->on_full_func = on_full_func;

  return CW_ER_OK;
}

CWERROR active_buf_put(CW_ACTIVE_BUFFER *ab,
                       const CW_UINT8 *data,
                       const CW_UINT32 size,
                       void *param) {
  register CW_UINT32 s = ab->sz - ab->pb, pdt = 0, n;
  CW_BUFFER buf = {ab->sz, ab->buf};
  CWERROR err;

  if (size <= s) {
    memcpy(&(ab->buf[ab->pb]), data, size);
    ab->pb += size;
    if (ab->pb == ab->sz) {
      ab->pb = 0;
      if ((err = ab->on_full_func(&buf, param)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
    }
  } else {
    memcpy(&(ab->buf[ab->pb]), data, s);
    ab->pb = 0;
    pdt += s;
    if ((err = ab->on_full_func(&buf, param)) != CW_ER_OK) {
      DEBUG_ERROR();
      return err;
    }
    n = (size - s) / ab->sz;
    while (n--) {
      memcpy(&(ab->buf[ab->pb]), &data[pdt], ab->sz);
      pdt += ab->sz;
      if ((err = ab->on_full_func(&buf, param)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
      }
    }
    n = (size - s) % ab->sz;
    if (n > 0) {
      memcpy(&(ab->buf[ab->pb]), &data[pdt], n);
      ab->pb += n;
      if (ab->pb == ab->sz) {
        if ((err = ab->on_full_func(&buf, param)) != CW_ER_OK) {
          DEBUG_ERROR();
          return err;
        }
      }
    }
  }

  return CW_ER_OK;
}

CWERROR active_buf_flush(CW_ACTIVE_BUFFER *ab, void *param) {
  CW_BUFFER buf = {ab->pb, ab->buf};
  CWERROR err;

  if (ab->pb > 0) {
    if ((err = ab->on_full_func(&buf, param)) != CW_ER_OK) {
      DEBUG_ERROR();
      return err;
    }
    ab->pb = 0;
  }

  return CW_ER_OK;
}

void active_buf_final(CW_ACTIVE_BUFFER *ab) {
  memset(ab->buf, 0, ab->sz);
  free(ab->buf);
}
