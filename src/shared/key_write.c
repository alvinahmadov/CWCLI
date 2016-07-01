#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "crypto.h"
#include "cert_struct.h"
#include "futils.h"

#include "key_rw.h"

CWERROR cert_write(CW_CERT *cert, const char *fname) {
  CW_CERT_FILE cf;
  CWERROR err;

  memset(&cf, 0, sizeof(cf));

  cf.head.sgn = CERT_SIGN;
  cf.head.version = CURRENT_CERTFILE_FORMAT_VERSION;

  memcpy(&cf.cert, cert, sizeof(CW_CERT));

  if ((err = write_file(&cf, sizeof(cf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

CWERROR ku_write(RSA_PUBLIC_KEY *ku, const char *fname) {
  CW_KU_FILE kf;
  CWERROR err;

  memset(&kf, 0, sizeof(kf));

  kf.head.sgn = KU_SIGN;
  kf.head.version = CURRENT_KEYFILE_FORMAT_VERSION;

  memcpy(&kf.ku, ku, sizeof(RSA_PUBLIC_KEY));

  if ((err = write_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  return CW_ER_OK;
}

CWERROR kr_write(RSA_PRIVATE_KEY *kr, const char *fname, const char *passwd) {
  SHA256_CTX sha256;
  SHA512_CTX sha512;
  BLOWFISH_CTX bfish;
  CW_UINT8 key[SHA512_DIGEST_LEN];
  CW_KR_FILE kf;
  int n = PKCS_ITERATION_CNT;
  CWERROR err = CW_ER_OK;

  memset(&kf, 0, sizeof(kf));

  mlock(key, sizeof(key));
  mlock(&kf, sizeof(kf));

  kf.head.sgn = KR_SIGN;
  kf.head.version = CURRENT_KEYFILE_FORMAT_VERSION;
  rnd_getbytes(kf.head.pkcs_pad, sizeof(kf.head.pkcs_pad));

  memcpy(&kf.kr, kr, sizeof(RSA_PRIVATE_KEY));

  /* get private key hash */
  sha256_init(&sha256);
  sha256_update(&sha256, &kf.head, sizeof(kf.head));
  sha256_update(&sha256, &kf.kr, sizeof(kf.kr));
  sha256_final(&sha256, kf.hash);

  /* get password hash  (PKCS 5.1) */
  sha512_init(&sha512);
  sha512_update(&sha512, passwd, (CW_UINT32) strlen(passwd));
  sha512_update(&sha512, kf.head.pkcs_pad, sizeof(kf.head.pkcs_pad));
  sha512_final(&sha512, key);
  while (n--) {
    sha512_init(&sha512);
    sha512_update(&sha512, key, sizeof(key));
    sha512_final(&sha512, key);
  }

  BLOWFISH_ENCRYPT(bfish, key, &kf.hash, sizeof(kf) - sizeof(kf.head));

  /* write file */
  if ((err = write_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  memset(key, 0, sizeof(key));
  memset(&kf, 0, sizeof(kf));
  munlock(key, sizeof(key));
  munlock(&kf, sizeof(kf));

  return err;
}

CWERROR efsk_write(CW_UINT8 *efs_k, const char *fname, const char *passwd) {
  SHA256_CTX sha256;
  SHA512_CTX sha512;
  BLOWFISH_CTX bfish;
  CW_UINT8 key[SHA512_DIGEST_LEN];
  CW_EFSKEY_FILE kf;
  int n = PKCS_ITERATION_CNT;
  CWERROR err = CW_ER_OK;

  memset(&kf, 0, sizeof(kf));

  mlock(key, sizeof(key));
  mlock(&kf, sizeof(kf));

  kf.head.sgn = EFSK_SIGN;
  kf.head.version = CURRENT_EFSKEY_FORMAT_VERSION;
  rnd_getbytes(kf.head.pkcs_pad, sizeof(kf.head.pkcs_pad));

  memcpy(kf.efs_k, efs_k, sizeof(kf.efs_k));

  /* get private key hash */
  sha256_init(&sha256);
  sha256_update(&sha256, &kf.head, sizeof(kf.head));
  sha256_update(&sha256, kf.efs_k, sizeof(kf.efs_k));
  sha256_final(&sha256, kf.hash);

  /* get password hash  (PKCS 5.1) */
  sha512_init(&sha512);
  sha512_update(&sha512, passwd, (CW_UINT32) strlen(passwd));
  sha512_update(&sha512, kf.head.pkcs_pad, sizeof(kf.head.pkcs_pad));
  sha512_final(&sha512, key);
  while (n--) {
    sha512_init(&sha512);
    sha512_update(&sha512, key, sizeof(key));
    sha512_final(&sha512, key);
  }

  BLOWFISH_ENCRYPT(bfish, key, &kf.hash, sizeof(kf) - sizeof(kf.head));

  /* write file */
  if ((err = write_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  memset(key, 0, sizeof(key));
  memset(&kf, 0, sizeof(kf));
  munlock(key, sizeof(key));
  munlock(&kf, sizeof(kf));

  return err;
}

CWERROR chpass(const char *kr_fname,
               const char *efsk_fname,
               const char *passwd,
               const char *new_passwd) {
  RSA_PRIVATE_KEY kr;
  CW_UINT8 efs_k[EFS_KEY_LEN];
  CWERROR err = CW_ER_OK;

  mlock(&kr, sizeof(kr));
  mlock(efs_k, sizeof(efs_k));

  if ((err = kr_read(&kr, kr_fname, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = kr_write(&kr, kr_fname, new_passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = efsk_read(efs_k, efsk_fname, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if ((err = efsk_write(efs_k, efsk_fname, new_passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }


  err_exit:

  memset(&kr, 0, sizeof(kr));
  memset(efs_k, 0, sizeof(efs_k));
  munlock(&kr, sizeof(kr));
  munlock(efs_k, sizeof(efs_k));

  return err;
}
