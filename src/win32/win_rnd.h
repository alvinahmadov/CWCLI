#ifndef _WIN_RND_H_
#define _WIN_RND_H_

#define RANDOM_POOL_SZ  (SHA512_DIGEST_LEN * 4)

CW_BOOL win32_get_random_pool(CW_UINT8 *buf);

#endif _WIN_RND_H_
