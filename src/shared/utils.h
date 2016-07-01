#ifndef _UTILS_H_
#define _UTILS_H_

void bufs_xor(void *b1, void *b2, CW_UINT32 len); /* b1 = b1 ^ b2 */
char *strcpy_s(char *dst, const char *src, const size_t count);
wchar_t *wcscpy_s(wchar_t *dst, const wchar_t *src, const size_t count);
CW_BOOL atoul(CW_UINT32 *res, const char *nptr);
CW_INT64 atoi64(const char *nptr);

#endif
