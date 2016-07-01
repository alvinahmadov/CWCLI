#ifndef __BASE64_H__
#define __BASE64_H__

#include <stddef.h>

#define BASE64_LENGTH(inlen) ((((inlen) + 2) / 3) * 4)

void base64_encode(const char *in, size_t inlen,
                   char *out, size_t outlen);

size_t base64_encode_alloc(const char *in, size_t inlen, char **out);

#endif
