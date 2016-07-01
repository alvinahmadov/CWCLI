#include "general.h"
#include "errors.h"
#include "crypto.h"
#include "cert_struct.h"
#include "futils.h"

#include "key_rw.h"

CWERROR cert_read(CW_CERT *cert, const char *fname) {
  CW_CERT_FILE cf;
  CWERROR err;

  if ((err = read_file(&cf, sizeof(cf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  if (cf.head.sgn != CERT_SIGN) {
    DEBUG_ERROR();
    return CW_ER_WRONG_KU_FILE;
  }

  if (cf.head.version != CURRENT_CERTFILE_FORMAT_VERSION) {
    DEBUG_ERROR();
    return CW_ER_KU_VERSION;
  }

  memcpy(cert, &cf.cert, sizeof(CW_CERT));

  return CW_ER_OK;
}

CWERROR ku_read(RSA_PUBLIC_KEY *ku, const char *fname) {
  CW_KU_FILE kf;
  CWERROR err;

  if ((err = read_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    return err;
  }

  if (kf.head.sgn != KU_SIGN) {
    DEBUG_ERROR();
    return CW_ER_WRONG_KU_FILE;
  }

  if (kf.head.version != CURRENT_KEYFILE_FORMAT_VERSION) {
    DEBUG_ERROR();
    return CW_ER_KU_VERSION;
  }

  memcpy(ku, &kf.ku, sizeof(RSA_PUBLIC_KEY));

  return CW_ER_OK;
}

CWERROR kr_read(RSA_PRIVATE_KEY *kr, const char *fname, const char *passwd) {
  SHA256_CTX sha256;
  SHA512_CTX sha512;
  BLOWFISH_CTX bfish;
  CW_UINT8 key[SHA512_DIGEST_LEN];
  CW_UINT8 hash[SHA256_DIGEST_LEN];
  CW_KR_FILE kf;
  int n = PKCS_ITERATION_CNT;
  CWERROR err = CW_ER_OK;

  mlock(key, sizeof(key));
  mlock(hash, sizeof(hash));
  mlock(&kf, sizeof(kf));

  /* read file */
  if ((err = read_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

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

  BLOWFISH_DECRYPT(bfish, key, &kf.hash, sizeof(kf) - sizeof(kf.head));

  /* get private key hash */
  sha256_init(&sha256);
  sha256_update(&sha256, &kf.head, sizeof(kf.head));
  sha256_update(&sha256, &kf.kr, sizeof(kf.kr));
  sha256_final(&sha256, hash);

  /* compare private key hashes */
  if (memcmp(hash, kf.hash, sizeof(kf.hash)) != 0) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_KR_FILE;
    goto err_exit;
  }

  if (kf.head.sgn != KR_SIGN) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_KR_FILE;
    goto err_exit;
  }
  if (kf.head.version != CURRENT_KEYFILE_FORMAT_VERSION) {
    DEBUG_ERROR();
    err = CW_ER_KR_VERSION;
    goto err_exit;
  }

  /* copy key to destination buffer */
  memcpy(kr, &kf.kr, sizeof(RSA_PRIVATE_KEY));

  err_exit:

  memset(key, 0, sizeof(key));
  memset(hash, 0, sizeof(hash));
  memset(&kf, 0, sizeof(kf));
  munlock(key, sizeof(key));
  munlock(hash, sizeof(hash));
  munlock(&kf, sizeof(kf));

  return err;
}

CWERROR kr_read_ex(RSA_PRIVATE_KEY *kr, const char *fname, const char *key_file) {
  FILE *fkey = NULL;
  char passwd[MAX_PASSWORD_LEN + 1];
  CWERROR err = CW_ER_OK;

  mlock(passwd, sizeof(passwd));

  if ((fkey = fopen(key_file, "rt")) == NULL) {
    DEBUG_ERROR();
    err = CW_ER_OPEN_FILE;
    goto err_exit;
  }
  fgets(passwd, MAX_PASSWORD_LEN, fkey);
  fclose(fkey);

  if ((err = kr_read(kr, fname, passwd)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

  err_exit:

  memset(passwd, 0, sizeof(passwd));
  munlock(passwd, sizeof(passwd));

  return err;
}

CWERROR efsk_read(CW_UINT8 *efs_k, const char *fname, const char *passwd) {
  SHA256_CTX sha256;
  SHA512_CTX sha512;
  BLOWFISH_CTX bfish;
  CW_UINT8 key[SHA512_DIGEST_LEN];
  CW_UINT8 hash[SHA256_DIGEST_LEN];
  CW_EFSKEY_FILE kf;
  int n = PKCS_ITERATION_CNT;
  CWERROR err = CW_ER_OK;

  mlock(key, sizeof(key));
  mlock(hash, sizeof(hash));
  mlock(&kf, sizeof(kf));

  /* read file */
  if ((err = read_file(&kf, sizeof(kf), fname)) != CW_ER_OK) {
    DEBUG_ERROR();
    goto err_exit;
  }

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

  BLOWFISH_DECRYPT(bfish, key, &kf.hash, sizeof(kf) - sizeof(kf.head));

  /* get private key hash */
  sha256_init(&sha256);
  sha256_update(&sha256, &kf.head, sizeof(kf.head));
  sha256_update(&sha256, kf.efs_k, sizeof(kf.efs_k));
  sha256_final(&sha256, hash);

  /* compare private key hashes */
  if (memcmp(hash, kf.hash, sizeof(kf.hash)) != 0) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_KR_FILE;
    goto err_exit;
  }

  if (kf.head.sgn != EFSK_SIGN) {
    DEBUG_ERROR();
    err = CW_ER_WRONG_KR_FILE;
    goto err_exit;
  }
  if (kf.head.version != CURRENT_EFSKEY_FORMAT_VERSION) {
    DEBUG_ERROR();
    err = CW_ER_KR_VERSION;
    goto err_exit;
  }

  /* copy key to destination buffer */
  memcpy(efs_k, kf.efs_k, sizeof(kf.efs_k));

  err_exit:

  memset(key, 0, sizeof(key));
  memset(hash, 0, sizeof(hash));
  memset(&kf, 0, sizeof(kf));
  munlock(key, sizeof(key));
  munlock(hash, sizeof(hash));
  munlock(&kf, sizeof(kf));

  return err;
}
