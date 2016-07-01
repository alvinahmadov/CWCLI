#ifndef _PACKETS_STRUCT_H_
#define _PACKETS_STRUCT_H_

#define CURRENT_PROTOCOL_VERSION            0x04
#define CURRENT_MESSAGE_FORMAT_VERSION      0x02
#define CURRENT_EFS_FORMAT_VERSION          0x01

#define MAX_INFO_HEAD_LEN           50
#define MAX_INFO_URL_LEN            128
#define MAX_INFO_TEXT_SZ            (25 * 1024 * 1024)

#define	MAX_NAME_LEN		        60
#define MAX_EMAIL_LEN		        128

#define PCKT_TEST_STRING	        "ABCDEFGHIabcdefghi1234567890!="

/* packet types */

#define PT_ERROR							0
#define PT_PING								1
#define	PT_TEST								2
/*---*/
#define PT_SRV_LOGIN1						3
#define PT_SRV_LOGIN1_RESP					4
#define PT_SRV_LOGIN2						5
#define PT_CLI_REG1							6
#define PT_CLI_REG1_RESP					7
#define PT_CLI_REG2							8
#define PT_CLI_LOGIN1						9
#define PT_CLI_LOGIN1_RESP					10
#define PT_CLI_LOGIN2						11
/*---*/
#define PT_LOGOUT							12
/*---*/
#define PT_MESSAGE							13
#define PT_GET_SERVER_INFO			        14
#define PT_GET_SERVER_INFO_RESP		        15
#define PT_GET_ONLINE_STATUS                16
#define PT_GET_ONLINE_STATUS_RESP           17
#define	PT_GET_USER_INFO					18
#define PT_GET_USER_INFO_RESP				19
#define PT_GET_MESSAGES						20
#define PT_GET_MESSAGES_RESP				21
#define PT_GET_STORAGE_INFO                 22
#define PT_GET_STORAGE_INFO_RESP            23
/*---*/
#define PT_ADMIN_CMD						24
#define PT_ADMIN_CMD_RESP					25
/*---*/
#define PT_TEXT								26
#define PT_FILE								27
/*---*/
#define PT_REPORT							28
/*---*/
#define PT_GET_INFO                         29
#define PT_GET_INFO_RESP                    30
/*---*/
#define PT_MK_CERT                          31 
#define PT_MK_CERT_RESP                     32
/*---*/
#define PT_EFS_CD                           33
#define PT_EFS_CDUP                         34
#define PT_EFS_CDROOT                       35
#define PT_EFS_MKDIR                        36
#define PT_EFS_ADDFILE                      37
#define PT_EFS_LIST                         38
#define PT_EFS_LIST_RESP                    39
#define PT_EFS_DELETE                       40
#define PT_EFS_GET                          41
#define PT_EFS_GET_RESP                     42

/* report codes */

#define RC_NOT_DELIVERED	                0
#define RC_QUOTA			                1
#define RC_MSG_SIZE_LIMIT	                2


/* packet error codes */

typedef enum {
	PE_OK,
	PE_INTERNAL,
	PE_VERSION,
	PE_LOCKED,
	PE_ACCESS_DENIED,
	PE_CERT_VERSION,
	PE_WRONG_CERT,
	PE_CERT_TIMEOUT,
	PE_PCKT_CONTENT,
	PE_REG_USER_EXISTS,
	PE_NO_QUERIED_INFO,
	PE_NO_RCPT,
	PE_QUOTA,	
	PE_SIZE_LIMIT,
	PE_HAS_CERT,
	PE_MK_CERT,
	PE_EFS
} CW_PE_CODE;

typedef enum {ET_DIR, ET_FILE} CW_EFS_OBJECT_TYPE;

#include "align1.h"

typedef struct {
	CW_PE_CODE code;
} CW_ERROR_PACKET;

typedef struct {
	char str[sizeof(PCKT_TEST_STRING)];
} CW_TEST_PACKET;


typedef struct {
    CW_UINT32 cnt;
} CW_LIST_HEAD_PACKET;

typedef struct {
    CW_UINT64 upckd;
    CW_UINT64 pckd;
} CW_MSG_OBJECT_SIZE;

typedef struct {
    wchar_t     head[MAX_INFO_HEAD_LEN + 1];
    char        url[MAX_INFO_URL_LEN + 1];
    CW_UINT32   text_sz;
} CW_INFO_PACKET;

typedef struct {
    CW_UINT32	m_cnt;
    CW_UINT32   f_cnt;
	CW_UINT64	used;
	CW_UINT64	quota;
} CW_STORAGE_INFO;

typedef struct {
    CW_UINT8    pad[RNDSALT_LEN];
    char        name[MAX_PATH + 1];
} CW_EFS_FILE_NAME;

typedef struct {
    CW_INT64            fid;
    CW_EFS_OBJECT_TYPE  type;
    CW_EFS_FILE_NAME    fname;
    CW_UINT64	        sz;
    char                add_dt[MAX_TIMESTAMP_LEN + 1];
} CW_EFS_FILE_INFO_PACKET;

typedef struct {
    CW_UINT8            s_key[SESSION_KEY_LEN];
    CW_UINT8            version;
    CW_MSG_OBJECT_SIZE  sz;
    CW_UINT8            _reserved[8];
} CW_EFS_FILE_BEGIN_HEAD;

typedef struct {
    CW_UINT8    hash[SHA256_DIGEST_LEN];
} CW_EFS_FILE_END_HEAD;

typedef struct {
    CW_UINT16	l_port;
	CW_UINT16   kbps;  
} CW_LOGIN_AD_DATA;

typedef struct {
    time_t      c_time;
	CW_UINT64	max_msg_sz;
	CW_UINT64   max_file_sz;
	CW_UINT16   kbps;
} CW_LOGIN_RESP_AD_DATA;

typedef struct {
	CW_RSA_ENCRYPTED_DATA	e_skey;
	CW_RSA_ENCRYPTED_DATA	sgn_a;
	CW_UINT8				version;
	CW_UINT32				sid;
	CW_UINT32				uid;
	CW_UINT32				r_a;
	CW_LOGIN_AD_DATA        a_info;
	CW_UINT8				skey_a[SESSION_KEY_LEN];
} CW_LOGIN1_PACKET;

typedef struct {
	CW_RSA_ENCRYPTED_DATA	e_skey;
	CW_RSA_ENCRYPTED_DATA	sgn_s;
	CW_UINT32				r_a;
	CW_UINT32				r_s;
	CW_LOGIN_RESP_AD_DATA	a_info;
	CW_UINT8				skey_s[SESSION_KEY_LEN];
} CW_LOGIN1_RESP_PACKET;

typedef struct {
	CW_RSA_ENCRYPTED_DATA r_s;
} CW_LOGIN2_PACKET;

typedef struct {
	CW_RSA_ENCRYPTED_DATA	e_skey;
	CW_UINT8				hash[SHA256_DIGEST_LEN];
	CW_UINT8				version;
	char					name[MAX_NAME_LEN + 1];
	char					email[MAX_EMAIL_LEN + 1];
	RSA_PUBLIC_KEY			ku_a;
	CW_UINT32				r_a;
} CW_CLI_REG1_PACKET;

typedef struct {
	CW_RSA_ENCRYPTED_DATA	e_skey;
	CW_RSA_ENCRYPTED_DATA	sgn_s;
	CW_UINT32				sid_a;
	CW_UINT32				uid_a;
	CW_UINT32				r_a;
	CW_UINT32				r_s;
} CW_CLI_REG1_RESP_PACKET;

typedef struct {
	CW_RSA_ENCRYPTED_DATA r_s;
} CW_CLI_REG2_PACKET;

typedef struct {
    CW_RSA_ENCRYPTED_DATA	sgn;
    CW_UINT32               sid;
    CW_UINT32               uid;
	char					name[MAX_NAME_LEN + 1];
	char					email[MAX_EMAIL_LEN + 1];
	CW_CERT_FLAGS           flags;
	RSA_PUBLIC_KEY			ku;
} CW_MK_CERT_PACKET;

typedef struct {
	IN_ADDR	ip;
	int		port;
	CW_CERT cert;
	CW_BOOL	locked;
} CW_SERVER_INFO;

typedef struct {
	CW_BOOL				online;
	CW_BOOL				locked;
	IN_ADDR				ip;
	CW_UINT16			l_port;
	RSA_PUBLIC_KEY		ku;
	CW_BOOL				has_cert;
	CW_CERT				cert;
	char                name[MAX_NAME_LEN + 1];
	char	            email[MAX_EMAIL_LEN + 1];
} CW_EXTERNAL_USER_INFO;

typedef struct {
    CW_INT64        gid;
	CW_BOOL			locked;
	RSA_PUBLIC_KEY	ku;
	CW_BOOL			has_cert;
	CW_CERT			cert;
	char            name[MAX_NAME_LEN + 1];
	char	        email[MAX_EMAIL_LEN + 1];
} CW_INTERNAL_USER_INFO;

typedef struct {
    CW_RSA_ENCRYPTED_DATA   _e_skey;
    CW_RSA_ENCRYPTED_DATA   arbitr_sgn;
    struct {
        struct {
            CW_UINT32 sid;
            CW_UINT32 uid;
        } from;
        struct {
            CW_UINT32 sid;
            CW_UINT32 uid;
        } rcpt;
        CW_UINT64       size;
        time_t          s_time;
        RSA_PUBLIC_KEY  u_ku;
        CW_BOOL         has_cert;
        CW_CERT         u_cert; 
        CW_UINT8        _reserved[8];  
    } e_hdr;
    CW_RSA_ENCRYPTED_DATA   e_skey;
	CW_RSA_ENCRYPTED_DATA	sgn;
	struct {
        CW_UINT8    version;
	    struct {
            CW_UINT32 sid;
            CW_UINT32 uid;
	    } from;
	    struct {
            CW_UINT32 sid;
            CW_UINT32 uid;
        } rcpt;
	    time_t         mk_time;
	    CW_UINT32      attach_cnt;
	    CW_UINT8       _reserved[8];
    } i_hdr;
} CW_MSG_PACKET_HEADER;

typedef struct {
	CW_MSG_OBJECT_SIZE	sz;
} CW_MSG_TEXT_HEADER;

typedef struct {
	CW_UINT8	        siv[BLOWFISH_IV_LEN];
	CRC32               crc;
	CW_MSG_OBJECT_SIZE	sz;
	char		        name[MAX_PATH + 1];
} CW_FILE_HEADER;

typedef struct {
	CW_UINT32	msg_cnt;
	CW_UINT64	total_sz;
} CW_MSGS_STREAM_HEADER;

typedef struct {
	CW_UINT32	rcpt_sid;
	CW_UINT32	rcpt_uid;
	CW_UINT32	code;
} CW_REPORT_PACKET;

#include "align_def.h"
#endif
