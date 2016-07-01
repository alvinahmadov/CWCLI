#include <string.h>

#include "general.h"

#include "sha512.h"

static const CW_UINT64 K[80] = {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL,
    0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL,
    0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL,
    0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL,
    0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL,
    0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static CW_UINT64 __inline Ch(CW_UINT64 x, CW_UINT64 y, CW_UINT64 z) {
  return z ^ (x & (y ^ z));
}

static CW_UINT64 __inline Maj(CW_UINT64 x, CW_UINT64 y, CW_UINT64 z) {
  return (x & y) | (z & (x | y));
}

static CW_UINT64 __inline RORUINT64(CW_UINT64 x, CW_UINT64 y) {
  return (x >> y) | (x << (64 - y));
}

#define e0(x)    (RORUINT64(x,28) ^ RORUINT64(x,34) ^ RORUINT64(x,39))
#define e1(x)    (RORUINT64(x,14) ^ RORUINT64(x,18) ^ RORUINT64(x,41))
#define s0(x)    (RORUINT64(x, 1) ^ RORUINT64(x, 8) ^ (x >> 7))
#define s1(x)    (RORUINT64(x,19) ^ RORUINT64(x,61) ^ (x >> 6))

#define H0    0x6a09e667f3bcc908ULL
#define H1    0xbb67ae8584caa73bULL
#define H2    0x3c6ef372fe94f82bULL
#define H3    0xa54ff53a5f1d36f1ULL
#define H4    0x510e527fade682d1ULL
#define H5    0x9b05688c2b3e6c1fULL
#define H6    0x1f83d9abfb41bd6bULL
#define H7    0x5be0cd19137e2179ULL

static void __inline LOAD_OP(int I, CW_UINT64 *W, const CW_UINT8 *input) {
  register CW_UINT64 t1 = input[8 * I] & 0xff;

  t1 <<= 8;
  t1 |= input[(8 * I) + 1] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 2] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 3] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 4] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 5] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 6] & 0xff;
  t1 <<= 8;
  t1 |= input[(8 * I) + 7] & 0xff;
  W[I] = t1;
}

static void __inline BLEND_OP(int I, CW_UINT64 *W) {
  W[I] = s1(W[I - 2]) + W[I - 7] + s0(W[I - 15]) + W[I - 16];
}

static void sha512_transform(CW_UINT64 *state, const CW_UINT8 *input) {
  register CW_UINT64 a, b, c, d, e, f, g, h, t1, t2;
  CW_UINT64 W[80];
  register int i;

  /* load the input */
  for (i = 0; i < 16; i++)
    LOAD_OP(i, W, input);

  for (i = 16; i < 80; i++)
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
  for (i = 0; i < 80; i += 8) {
    t1 = h + e1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 = e0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
    t1 = g + e1(d) + Ch(d, e, f) + K[i + 1] + W[i + 1];
    t2 = e0(h) + Maj(h, a, b);
    c += t1;
    g = t1 + t2;
    t1 = f + e1(c) + Ch(c, d, e) + K[i + 2] + W[i + 2];
    t2 = e0(g) + Maj(g, h, a);
    b += t1;
    f = t1 + t2;
    t1 = e + e1(b) + Ch(b, c, d) + K[i + 3] + W[i + 3];
    t2 = e0(f) + Maj(f, g, h);
    a += t1;
    e = t1 + t2;
    t1 = d + e1(a) + Ch(a, b, c) + K[i + 4] + W[i + 4];
    t2 = e0(e) + Maj(e, f, g);
    h += t1;
    d = t1 + t2;
    t1 = c + e1(h) + Ch(h, a, b) + K[i + 5] + W[i + 5];
    t2 = e0(d) + Maj(d, e, f);
    g += t1;
    c = t1 + t2;
    t1 = b + e1(g) + Ch(g, h, a) + K[i + 6] + W[i + 6];
    t2 = e0(c) + Maj(c, d, e);
    f += t1;
    b = t1 + t2;
    t1 = a + e1(f) + Ch(f, g, h) + K[i + 7] + W[i + 7];
    t2 = e0(b) + Maj(b, c, d);
    e += t1;
    a = t1 + t2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;

  /* erase our data */
  a = b = c = d = e = f = g = h = t1 = t2 = 0;
  memset(W, 0, 80 * sizeof(CW_UINT64));
}

void sha512_init(SHA512_CTX *ctx) {
  mlock(ctx, sizeof(SHA512_CTX));

  ctx->state[0] = H0;
  ctx->state[1] = H1;
  ctx->state[2] = H2;
  ctx->state[3] = H3;
  ctx->state[4] = H4;
  ctx->state[5] = H5;
  ctx->state[6] = H6;
  ctx->state[7] = H7;
  ctx->count[0] = ctx->count[1] = ctx->count[2] = ctx->count[3] = 0;
  memset(ctx->buf, 0, sizeof(ctx->buf));
}

void sha512_update(SHA512_CTX *ctx, const void *buffer, CW_UINT32 len) {
  CW_UINT8 *data = (CW_UINT8 *) buffer;
  CW_UINT32 i, index, part_len;

  /* Compute number of UBYTEs mod 128 */
  index = (CW_UINT32) ((ctx->count[0] >> 3) & 0x7F);

  /* Update number of bits */
  if ((ctx->count[0] += (len << 3)) < (len << 3)) {
    if ((ctx->count[1] += 1) < 1) if ((ctx->count[2] += 1) < 1)
      ctx->count[3]++;
    ctx->count[1] += (len >> 29);
  }

  part_len = 128 - index;

  /* Transform as many times as possible. */
  if (len >= part_len) {
    memcpy(&ctx->buf[index], data, part_len);
    sha512_transform(ctx->state, ctx->buf);

    for (i = part_len; i + 127 < len; i += 128)
      sha512_transform(ctx->state, &data[i]);

    index = 0;
  } else {
    i = 0;
  }

  /* Buffer remaining input */
  memcpy(&ctx->buf[index], &data[i], len - i);
}

void __inline sha512_burn(SHA512_CTX *ctx) {
  memset(ctx, 0, sizeof(SHA512_CTX));
  munlock(ctx, sizeof(SHA512_CTX));
}

void sha512_final(SHA512_CTX *ctx, void *result) {
  static CW_UINT8 padding[128] = {0x80,};

  CW_UINT8 *hash = (CW_UINT8 *) result;

  register CW_UINT32 t;
  register CW_UINT64 t2;
  CW_UINT8 bits[128];
  CW_UINT32 index, pad_len;
  register int i, j;

  index = pad_len = t = i = j = 0;
  t2 = 0;

  /* Save number of bits */
  t = ctx->count[0];
  bits[15] = (CW_UINT8) t;
  t >>= 8;
  bits[14] = (CW_UINT8) t;
  t >>= 8;
  bits[13] = (CW_UINT8) t;
  t >>= 8;
  bits[12] = (CW_UINT8) t;
  t = ctx->count[1];
  bits[11] = (CW_UINT8) t;
  t >>= 8;
  bits[10] = (CW_UINT8) t;
  t >>= 8;
  bits[9] = (CW_UINT8) t;
  t >>= 8;
  bits[8] = (CW_UINT8) t;
  t = ctx->count[2];
  bits[7] = (CW_UINT8) t;
  t >>= 8;
  bits[6] = (CW_UINT8) t;
  t >>= 8;
  bits[5] = (CW_UINT8) t;
  t >>= 8;
  bits[4] = (CW_UINT8) t;
  t = ctx->count[3];
  bits[3] = (CW_UINT8) t;
  t >>= 8;
  bits[2] = (CW_UINT8) t;
  t >>= 8;
  bits[1] = (CW_UINT8) t;
  t >>= 8;
  bits[0] = (CW_UINT8) t;

  /* Pad out to 112 mod 128. */
  index = (ctx->count[0] >> 3) & 0x7f;
  pad_len = (index < 112) ? (112 - index) : ((128 + 112) - index);
  sha512_update(ctx, padding, pad_len);

  /* Append length (before padding) */
  sha512_update(ctx, bits, 16);

  /* Store state in digest */
  for (i = j = 0; i < 8; i++, j += 8) {
    t2 = ctx->state[i];
    hash[j + 7] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 6] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 5] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 4] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 3] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 2] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j + 1] = (CW_UINT8) t2 & 0xff;
    t2 >>= 8;
    hash[j] = (CW_UINT8) t2 & 0xff;
  }

  memset(ctx, 0, sizeof(SHA512_CTX));
  munlock(ctx, sizeof(SHA512_CTX));
}
