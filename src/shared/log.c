#include "general.h"
#include <stdarg.h>
#include "errors.h"

#include "log.h"

static pthread_mutex_t w_mtx;
static FILE *flog = NULL;

CWERROR log_open(const char *fname) {
  if ((flog = fopen(fname, "w")) == NULL) {
    return CW_ER_OPEN_FILE;
  }

  MUTEX_INIT(w_mtx);
  pthread_mutex_init(&w_mtx, NULL);

  return CW_ER_OK;
}

void log_write(char *fmt, ...) {
  struct tm *stm;
  time_t t;
  va_list ap;
  char *p, *sval;
  int ival;
  unsigned long uval;
  long long llval;
  unsigned long long ullval;

  pthread_mutex_lock(&w_mtx);

  t = time(NULL);
  stm = localtime(&t);

  fprintf(flog,
          "[%02d/%02d/%04d %02d:%02d:%02d]: ",
          stm->tm_mday,
          stm->tm_mon + 1,
          stm->tm_year + 1900,
          stm->tm_hour,
          stm->tm_min,
          stm->tm_sec);

  va_start(ap, fmt);

  for (p = fmt; *p; p++) {
    if (*p != '%') {
      fputc(*p, flog);
      continue;
    }
    switch (*++p) {
      case 'd':
        ival = va_arg(ap, int);
        fprintf(flog, "%d", ival);
        break;
      case 'u':
        uval = va_arg(ap, unsigned
            long);
        fprintf(flog, "%u", uval);
        break;
      case 'q':
        llval = va_arg(ap, long
            long);
#if defined(_WIN32) || defined(WIN32)
        fprintf(flog, "%I64d", llval);
#else
        fprintf(flog, "%lld", llval);
#endif
        break;
      case 'Q':
        ullval = va_arg(ap, unsigned
            long
            long);
#if defined(_WIN32) || defined(WIN32)
        fprintf(flog, "%I64u", ullval);
#else
        fprintf(flog, "%llu", ullval);
#endif
        break;
      case 's':
        for (sval = va_arg(ap, char *); *sval; sval++)
          fputc(*sval, flog);
        break;
      default:
        fputc(*p, flog);
        break;
    }
  }

  fflush(flog);
  va_end(ap);

  pthread_mutex_unlock(&w_mtx);
}

void log_close(void) {
  pthread_mutex_lock(&w_mtx);

  fflush(flog);
  fclose(flog);

  pthread_mutex_destroy(&w_mtx);
}
