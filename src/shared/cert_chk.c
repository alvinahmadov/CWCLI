#include "general.h"
#include "errors.h"
#include "crypto.h"

#include "cert_struct.h"
#include "cert_chk.h"

CWERROR cert_check(const CW_CERT *cert,
                   RSA_PUBLIC_KEY *ku,
                   const CW_CERT_TYPE chk_type) {
  SHA256_CTX sha256;
  CW_UINT8 my_cert_hash[SHA256_DIGEST_LEN], cert_hash[MAX_RSA_BLOCK_LEN];
  time_t tm;
  unsigned int dec_len;

  if (cert->version != CURRENT_CERT_FORMAT_VERSION) {
    DEBUG_ERROR();
    return CW_ER_WRONG_CERT_VERSION;
  }

  if (cert->ext.type != chk_type) {
    DEBUG_ERROR();
    return CW_ER_WRONG_CERT;
  }

  tm = time(NULL);
  if ((difftime(cert->valid_until, tm) <= 0) || (difftime(tm, cert->valid_from) <= 0)) {
    DEBUG_ERROR();
    return CW_ER_CERT_TIMEOUT;
  }

  /* get certificate hash */
  sha256_init(&sha256);
  sha256_update(&sha256, cert, sizeof(CW_CERT) - sizeof(cert->sign));
  sha256_final(&sha256, my_cert_hash);

  RSAPublicDecrypt(cert_hash, &dec_len, (unsigned char *) cert->sign.data, cert->sign.len, ku);
  if (dec_len != SHA256_DIGEST_LEN) {
    DEBUG_ERROR();
    return CW_ER_WRONG_CERT;
  }

  if (memcmp(my_cert_hash, cert_hash, sizeof(my_cert_hash)) != 0) {
    DEBUG_ERROR();
    return CW_ER_WRONG_CERT;
  }

  return CW_ER_OK;
}
