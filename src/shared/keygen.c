#include <stdio.h>
#include <string.h>
#include <time.h>

#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "crypto.h"

#include "keygen.h"

CWERROR gen_keys(RSA_PUBLIC_KEY *ku,
                 RSA_PRIVATE_KEY *kr,
                 CW_UINT8 *efs_k,
                 const int kpair_sz) {
  RSA_RANDOM_STRUCT rnd_struct;
  RSA_PROTO_KEY proto_key;
  CW_UINT8 rndbuf[RND_BUF_SZ];
  unsigned int needed = 1;
  CWERROR err = CW_ER_OK;

  /* generate RSA keypair */

  R_RandomInit(&rnd_struct);
  while (needed) {
    rnd_getbytes(rndbuf, sizeof(rndbuf));
    R_RandomUpdate(&rnd_struct, rndbuf, sizeof(rndbuf));
    R_GetRandomBytesNeeded(&needed, &rnd_struct);
  }
  proto_key.bits = kpair_sz;
  proto_key.useFermat4 = 1;
  if (R_GeneratePEMKeys(ku, kr, &proto_key, &rnd_struct)) {
    R_RandomFinal(&rnd_struct);
    DEBUG_ERROR();
    return CW_ER_RSA_KEYGEN;
  }
  R_RandomFinal(&rnd_struct);
  memset(rndbuf, 0, sizeof(rndbuf));

  /* generate EFS key */
  if (efs_k) {
    rnd_getbytes(efs_k, EFS_KEY_LEN);
  }

  return CW_ER_OK;
}
