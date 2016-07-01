#ifndef _CERT_STRUCT_H_
#define _CERT_STRUCT_H_

#define CURRENT_CERT_FORMAT_VERSION     0x0200


#define CERT_SERIAL_NUMBER_SZ   16
#define CERT_MAX_NAME_LEN       100
#define CERT_MAX_EMAIL_LEN      128

typedef enum {
    CT_ROOT, CT_SERVER, CT_USER
} CW_CERT_TYPE;

#include "align1.h"

typedef struct {
    CW_UINT32 sid;
    CW_UINT32 uid;
} CW_CERT_OBJECT_ID;

typedef struct {
    CW_UINT8 admin        : 1;
    CW_UINT8 _reserved    : 7;
} CW_CERT_FLAGS;

typedef struct {
    CW_CERT_TYPE type;
    CW_CERT_FLAGS flags;
    char subj_email[CERT_MAX_EMAIL_LEN + 1];
} CW_CERT_EXTENSIONS;

typedef struct {
    CW_UINT16 version;
    CW_UINT8 sn[CERT_SERIAL_NUMBER_SZ];
    time_t valid_from;
    time_t valid_until;
    char issr_name[CERT_MAX_NAME_LEN + 1];
    char subj_name[CERT_MAX_NAME_LEN + 1];
    CW_CERT_OBJECT_ID issr_id;
    CW_CERT_OBJECT_ID subj_id;
    CW_CERT_EXTENSIONS ext;
    RSA_PUBLIC_KEY ku;
    CW_RSA_ENCRYPTED_DATA sign;
} CW_CERT;

#include "align_def.h"

#endif