#ifndef _WIN32

#include <sys/mman.h>

#endif

#include "general.h"
#include "secmem.h"


void __inline *sec_malloc(const size_t n) {
  register void *p = NULL;

  if ((p = malloc(n)) != NULL) {
    mlock(p, n);
  }

  return p;
}

void __inline sec_free(void *p, const size_t n) {
  if (p) {
    memset(p, 0, n);
    munlock(p, n);
    free(p);
  }
}

