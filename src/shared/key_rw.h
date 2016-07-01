#ifndef _KEY_RW_H_
#define _KEY_RW_H_

#define CURRENT_KEYFILE_FORMAT_VERSION  0x01
#define CURRENT_CERTFILE_FORMAT_VERSION 0x01
#define CURRENT_EFSKEY_FORMAT_VERSION   0x01

#define CERT_SIGN   0x5243  /* "CR" */
#define KU_SIGN     0x554B    /* "KU" */
#define KR_SIGN        0x524B    /* "KR" */
#define EFSK_SIGN   0x454B  /* "EK" */

#define PKCS_PAD_LEN         8
#define PKCS_ITERATION_CNT   999

typedef struct {
    struct {
        CW_UINT16 sgn;
        CW_UINT8 version;
    } head;
    RSA_PUBLIC_KEY ku;
} CW_KU_FILE;

typedef struct {
    struct {
        CW_UINT16 sgn;
        CW_UINT8 version;
    } head;
    CW_CERT cert;
} CW_CERT_FILE;

typedef struct {
    struct {
        CW_UINT16 sgn;
        CW_UINT8 version;
        CW_UINT8 pkcs_pad[PKCS_PAD_LEN];
    } head;
    CW_UINT8 hash[SHA256_DIGEST_LEN];
    RSA_PRIVATE_KEY kr;
} CW_KR_FILE;

typedef struct {
    struct {
        CW_UINT16 sgn;
        CW_UINT8 version;
        CW_UINT8 pkcs_pad[PKCS_PAD_LEN];
    } head;
    CW_UINT8 hash[SHA256_DIGEST_LEN];
    CW_UINT8 efs_k[EFS_KEY_LEN];
} CW_EFSKEY_FILE;


CWERROR cert_read(CW_CERT *cert, const char *fname);

CWERROR cert_write(CW_CERT *cert, const char *fname);

CWERROR ku_read(RSA_PUBLIC_KEY *ku, const char *fname);

CWERROR ku_write(RSA_PUBLIC_KEY *ku, const char *fname);

CWERROR kr_read(RSA_PRIVATE_KEY *kr, const char *fname, const char *passwd);

CWERROR kr_read_ex(RSA_PRIVATE_KEY *kr, const char *fname, const char *key_file);

CWERROR kr_write(RSA_PRIVATE_KEY *kr, const char *fname, const char *passwd);

CWERROR efsk_read(CW_UINT8 *efs_k, const char *fname, const char *passwd);

CWERROR efsk_write(CW_UINT8 *efs_k, const char *fname, const char *passwd);

CWERROR chpass(const char *kr_fname,
               const char *efsk_fname,
               const char *passwd,
               const char *new_passwd);

#endif
