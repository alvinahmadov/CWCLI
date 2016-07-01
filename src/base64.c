/* base64.c -- Encode binary data using printable characters.
   Copyright (C) 1999, 2000, 2001, 2004, 2005, 2006 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Simon Josefsson.  Partially adapted from GNU MailUtils
 * (mailbox/filter_trans.c, as of 2004-11-28).  Improved by review
 * from Paul Eggert, Bruno Haible, and Stepan Kasal.
 *
 * See also RFC 3548 <http://www.ietf.org/rfc/rfc3548.txt>.
 *
 * Be careful with error checking.  Here is how you would typically
 * use these functions:
 *
 * bool ok = base64_decode_alloc (in, inlen, &out, &outlen);
 * if (!ok)
 *   FAIL: input was not valid base64
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN
 *
 * size_t outlen = base64_encode_alloc (in, inlen, &out);
 * if (out == NULL && outlen == 0 && inlen != 0)
 *   FAIL: input too long
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN.
 *
 */

/* Get prototype. */
#include "base64.h"

/* Get malloc. */
#include <stdlib.h>

/* Get UCHAR_MAX. */
#include <limits.h>

/* C89 compliant way to cast 'char' to 'unsigned char'. */
static __inline unsigned char
to_uchar(char ch) {
  return ch;
}

/* Base64 encode IN array of size INLEN into OUT array of size OUTLEN.
   If OUTLEN is less than BASE64_LENGTH(INLEN), write as many bytes as
   possible.  If OUTLEN is larger than BASE64_LENGTH(INLEN), also zero
   terminate the output buffer. */
void
base64_encode(const char *in, size_t inlen,
              char *out, size_t outlen) {
  static const char b64str[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  while (inlen && outlen) {
    *out++ = b64str[(to_uchar(in[0]) >> 2) & 0x3f];
    if (!--outlen)
      break;
    *out++ = b64str[((to_uchar(in[0]) << 4)
                     + (--inlen ? to_uchar(in[1]) >> 4 : 0))
                    & 0x3f];
    if (!--outlen)
      break;
    *out++ =
        (inlen
         ? b64str[((to_uchar(in[1]) << 2)
                   + (--inlen ? to_uchar(in[2]) >> 6 : 0))
                  & 0x3f]
         : '=');
    if (!--outlen)
      break;
    *out++ = inlen ? b64str[to_uchar(in[2]) & 0x3f] : '=';
    if (!--outlen)
      break;
    if (inlen)
      inlen--;
    if (inlen)
      in += 3;
  }

  if (outlen)
    *out = '\0';
}

/* Allocate a buffer and store zero terminated base64 encoded data
   from array IN of size INLEN, returning BASE64_LENGTH(INLEN), i.e.,
   the length of the encoded data, excluding the terminating zero.  On
   return, the OUT variable will hold a pointer to newly allocated
   memory that must be deallocated by the caller.  If output string
   length would overflow, 0 is returned and OUT is set to NULL.  If
   memory allocation failed, OUT is set to NULL, and the return value
   indicates length of the requested memory block, i.e.,
   BASE64_LENGTH(inlen) + 1. */
size_t
base64_encode_alloc(const char *in, size_t inlen, char **out) {
  size_t outlen = 1 + BASE64_LENGTH (inlen);

  /* Check for overflow in outlen computation.
   *
   * If there is no overflow, outlen >= inlen.
   *
   * If the operation (inlen + 2) overflows then it yields at most +1, so
   * outlen is 0.
   *
   * If the multiplication overflows, we lose at least half of the
   * correct value, so the result is < ((inlen + 2) / 3) * 2, which is
   * less than (inlen + 2) * 0.66667, which is less than inlen as soon as
   * (inlen > 4).
   */
  if (inlen > outlen) {
    *out = NULL;
    return 0;
  }

  *out = (char *) malloc(outlen);
  if (!*out)
    return outlen;

  base64_encode(in, inlen, *out, outlen);

  return outlen - 1;
}
