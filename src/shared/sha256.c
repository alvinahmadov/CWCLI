#include <string.h>

#include "general.h"

#include "sha256.h"

static CW_UINT32 __inline Ch(CW_UINT32 x, CW_UINT32 y, CW_UINT32 z) {
  return z ^ (x & (y ^ z));
}

static CW_UINT32 __inline Maj(CW_UINT32 x, CW_UINT32 y, CW_UINT32 z) {
  return (x & y) | (z & (x | y));
}

static CW_UINT32 __inline RORULONG(CW_UINT32 x, CW_UINT32 y) {
  return (x >> y) | (x << (32 - y));
}

#define e0(x)       (RORULONG(x, 2) ^ RORULONG(x,13) ^ RORULONG(x,22))
#define e1(x)       (RORULONG(x, 6) ^ RORULONG(x,11) ^ RORULONG(x,25))
#define s0(x)       (RORULONG(x, 7) ^ RORULONG(x,18) ^ (x >> 3))
#define s1(x)       (RORULONG(x,17) ^ RORULONG(x,19) ^ (x >> 10))

#define H0         0x6a09e667
#define H1         0xbb67ae85
#define H2         0x3c6ef372
#define H3         0xa54ff53a
#define H4         0x510e527f
#define H5         0x9b05688c
#define H6         0x1f83d9ab
#define H7         0x5be0cd19

static __inline void LOAD_OP(int I, CW_UINT32 *W, const CW_UINT8 *input) {
  CW_UINT32 t1 = input[(4 * I)] & 0xff;

  t1 <<= 8;
  t1 |= input[(4 * I) + 1] & 0xff;
  t1 <<= 8;
  t1 |= input[(4 * I) + 2] & 0xff;
  t1 <<= 8;
  t1 |= input[(4 * I) + 3] & 0xff;
  W[I] = t1;
}

static __inline void BLEND_OP(int I, CW_UINT32 *W) {
  W[I] = s1(W[I - 2]) + W[I - 7] + s0(W[I - 15]) + W[I - 16];
}

static void sha256_transform(CW_UINT32 *state, const CW_UINT8 *input) {
  CW_UINT32 a, b, c, d, e, f, g, h, t1, t2;
  CW_UINT32 W[64];
  int i;

  /* load the input */
  for (i = 0; i < 16; i++)
    LOAD_OP(i, W, input);

  /* now blend */
  for (i = 16; i < 64; i++)
    BLEND_OP(i, W);

  /* load the state into our registers */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  /* now iterate */
  t1 = h + e1(e) + Ch(e, f, g) + 0x428a2f98 + W[0];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0x71374491 + W[1];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0xb5c0fbcf + W[2];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0xe9b5dba5 + W[3];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x3956c25b + W[4];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0x59f111f1 + W[5];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x923f82a4 + W[6];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0xab1c5ed5 + W[7];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0xd807aa98 + W[8];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0x12835b01 + W[9];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0x243185be + W[10];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0x550c7dc3 + W[11];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x72be5d74 + W[12];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0x80deb1fe + W[13];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x9bdc06a7 + W[14];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0xc19bf174 + W[15];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0xe49b69c1 + W[16];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0xefbe4786 + W[17];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0x0fc19dc6 + W[18];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0x240ca1cc + W[19];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x2de92c6f + W[20];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0x4a7484aa + W[21];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x5cb0a9dc + W[22];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0x76f988da + W[23];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0x983e5152 + W[24];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0xa831c66d + W[25];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0xb00327c8 + W[26];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0xbf597fc7 + W[27];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0xc6e00bf3 + W[28];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0xd5a79147 + W[29];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x06ca6351 + W[30];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0x14292967 + W[31];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0x27b70a85 + W[32];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0x2e1b2138 + W[33];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0x4d2c6dfc + W[34];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0x53380d13 + W[35];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x650a7354 + W[36];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0x766a0abb + W[37];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x81c2c92e + W[38];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0x92722c85 + W[39];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0xa2bfe8a1 + W[40];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0xa81a664b + W[41];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0xc24b8b70 + W[42];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0xc76c51a3 + W[43];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0xd192e819 + W[44];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0xd6990624 + W[45];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0xf40e3585 + W[46];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0x106aa070 + W[47];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0x19a4c116 + W[48];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0x1e376c08 + W[49];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0x2748774c + W[50];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0x34b0bcb5 + W[51];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x391c0cb3 + W[52];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0x4ed8aa4a + W[53];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0x5b9cca4f + W[54];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0x682e6ff3 + W[55];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  t1 = h + e1(e) + Ch(e, f, g) + 0x748f82ee + W[56];
  t2 = e0(a) + Maj(a, b, c);
  d += t1;
  h = t1 + t2;
  t1 = g + e1(d) + Ch(d, e, f) + 0x78a5636f + W[57];
  t2 = e0(h) + Maj(h, a, b);
  c += t1;
  g = t1 + t2;
  t1 = f + e1(c) + Ch(c, d, e) + 0x84c87814 + W[58];
  t2 = e0(g) + Maj(g, h, a);
  b += t1;
  f = t1 + t2;
  t1 = e + e1(b) + Ch(b, c, d) + 0x8cc70208 + W[59];
  t2 = e0(f) + Maj(f, g, h);
  a += t1;
  e = t1 + t2;
  t1 = d + e1(a) + Ch(a, b, c) + 0x90befffa + W[60];
  t2 = e0(e) + Maj(e, f, g);
  h += t1;
  d = t1 + t2;
  t1 = c + e1(h) + Ch(h, a, b) + 0xa4506ceb + W[61];
  t2 = e0(d) + Maj(d, e, f);
  g += t1;
  c = t1 + t2;
  t1 = b + e1(g) + Ch(g, h, a) + 0xbef9a3f7 + W[62];
  t2 = e0(c) + Maj(c, d, e);
  f += t1;
  b = t1 + t2;
  t1 = a + e1(f) + Ch(f, g, h) + 0xc67178f2 + W[63];
  t2 = e0(b) + Maj(b, c, d);
  e += t1;
  a = t1 + t2;

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;

  /* clear any sensitive info... */
  a = b = c = d = e = f = g = h = t1 = t2 = 0;
  memset(W, 0, 64 * sizeof(CW_UINT32));
}

void sha256_init(SHA256_CTX *ctx) {
  mlock(ctx, sizeof(SHA256_CTX));

  ctx->state[0] = H0;
  ctx->state[1] = H1;
  ctx->state[2] = H2;
  ctx->state[3] = H3;
  ctx->state[4] = H4;
  ctx->state[5] = H5;
  ctx->state[6] = H6;
  ctx->state[7] = H7;
  ctx->count[0] = ctx->count[1] = 0;
  memset(ctx->buf, 0, sizeof(ctx->buf));
}

void sha256_update(SHA256_CTX *ctx, const void *buffer, CW_UINT32 len) {
  const register CW_UINT8 *pbuf = (CW_UINT8 *) buffer;
  unsigned int i, index, part_len;

  /* Compute number of UBYTEs mod 128 */
  index = (unsigned int) ((ctx->count[0] >> 3) & 0x3f);

  /* Update number of bits */
  if ((ctx->count[0] += (len << 3)) < (len << 3)) {
    ctx->count[1]++;
    ctx->count[1] += (len >> 29);
  }

  part_len = 64 - index;

  /* Transform as many times as possible. */
  if (len >= part_len) {
    memcpy(&ctx->buf[index], pbuf, part_len);
    sha256_transform(ctx->state, ctx->buf);
    for (i = part_len; i + 63 < len; i += 64)
      sha256_transform(ctx->state, &pbuf[i]);
    index = 0;
  } else {
    i = 0;
  }

  /* Buffer remaining input */
  memcpy(&ctx->buf[index], &pbuf[i], len - i);
}

void __inline sha256_burn(SHA256_CTX *ctx) {
  memset(ctx, 0, sizeof(SHA256_CTX));
  munlock(ctx, sizeof(SHA256_CTX));
}

void sha256_final(SHA256_CTX *ctx, void *result) {
  CW_UINT8 *out = (CW_UINT8 *) result;
  CW_UINT8 bits[8];
  unsigned int index, pad_len, t;
  int i, j;
  static const CW_UINT8 padding[64] = {0x80,};

  /* Save number of bits */
  t = ctx->count[0];
  bits[7] = t;
  t >>= 8;
  bits[6] = t;
  t >>= 8;
  bits[5] = t;
  t >>= 8;
  bits[4] = t;
  t = ctx->count[1];
  bits[3] = t;
  t >>= 8;
  bits[2] = t;
  t >>= 8;
  bits[1] = t;
  t >>= 8;
  bits[0] = t;

  /* Pad out to 56 mod 64. */
  index = (ctx->count[0] >> 3) & 0x3f;
  pad_len = (index < 56) ? (56 - index) : ((64 + 56) - index);
  sha256_update(ctx, padding, pad_len);

  /* Append length (before padding) */
  sha256_update(ctx, bits, 8);

  /* Store state in digest */
  for (i = j = 0; i < 8; i++, j += 4) {
    t = ctx->state[i];
    out[j + 3] = t;
    t >>= 8;
    out[j + 2] = t;
    t >>= 8;
    out[j + 1] = t;
    t >>= 8;
    out[j] = t;
  }

  memset(ctx, 0, sizeof(SHA256_CTX));
  munlock(ctx, sizeof(SHA256_CTX));
}
