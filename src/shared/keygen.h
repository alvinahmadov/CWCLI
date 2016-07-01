#ifndef _KEYGEN_H_
#define _KEYGEN_H_

#define RND_BUF_SZ 64

CWERROR gen_keys(RSA_PUBLIC_KEY *ku, 
				 RSA_PRIVATE_KEY *kr,
				 CW_UINT8 *efs_k,
				 const int kpair_sz);
#endif
