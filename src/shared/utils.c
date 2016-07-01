#include "general.h"

#include "utils.h"

void __inline bufs_xor(void *b1, void *b2, CW_UINT32 len) {
  register CW_UINT8 *bb1 = (CW_UINT8 *) b1, *bb2 = (CW_UINT8 *) b2;

  while (len--)
    *bb1++ ^= *bb2++;
}

char __inline *strcpy_s(char *dst, const char *src, const size_t count) {
  if (strlen(src) >= count)
    return NULL;
  else
    return strcpy(dst, src);
}

wchar_t __inline *wcscpy_s(wchar_t *dst, const wchar_t *src, const size_t count) {
  if (wcslen(src) >= count)
    return NULL;
  else
    return wcscpy(dst, src);
}

CW_BOOL atoul(CW_UINT32 *res, const char *nptr) {
  char *s = NULL;

  *res = strtoul(nptr, &s, 10);
  if (strcmp(nptr, s) == 0) {
    DEBUG_ERROR();
    return FALSE;
  }

  return TRUE;
}

CW_INT64 atoi64(const char *nptr) {
  register char *s = (char *) nptr;
  CW_INT64 acc = 0;
  int neg = 0;

  while (isspace((int) *s))
    s++;

  if (*s == '-') {
    neg = 1;
    s++;
  } else if (*s == '+')
    s++;

  while (isdigit((int) *s)) {
    acc = 10 * acc + ((int) *s - '0');
    s++;
  }

  if (neg)
    acc *= -1;

  return acc;
}
