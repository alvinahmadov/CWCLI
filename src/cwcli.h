#ifndef _CLI_H_
#define _CLI_H_


#define CLIENT_LOG_FILE_NAME    "cwcli.log"
#define CLIENT_DB_FILE_NAME        "work.db"

#define TIME_DIFF               180.0
#define FILE_BUF_SZ             65536
#define WIPE_BUF_SZ             8196
#define MAX_TEXT_IN_MAIL_LEN    (10 * 1024 * 1024) /* 5MB because of wchars */
#define MAX_ATTACHED_FILES_CNT    0xFFFFFFFFUL

#define MAX_IP_LEN              sizeof("255.255.255.255")

#define QRND()                  ((CW_UINT32)time(NULL))

#define WIPE_BYTE_1             0x00
#define WIPE_BYTE_2             0xFF


typedef void *CW_MSGVIEW_HANDLE;
typedef void *CW_CONN_HANDLE;

typedef enum {
    CM_DIRECT, CM_SOCKS5, CM_HTTP
} CW_CONNECT_MODE;


typedef CW_BOOL (*ON_TIME_COLLISION)(const time_t ct);

typedef void (*SET_PROGRESS)(const CW_UINT64 n);

typedef void (*SET_SUB_PROGRESS)(const CW_UINT64 n);

typedef void (*UPDATE_SUB_PROGRESS)(void);

typedef void (*UPDATE_PROGRESS)(void);


typedef struct {
    CW_UINT64 size;
    char *name;
} CW_MSG_FILE;

typedef struct {
    CW_UINT64 pckd_sz;
    CW_UINT64 upckd_sz;
    char *name;
} CW_MSG_FILE_INFO;

typedef struct {
    CW_UINT32 from_sid;
    CW_UINT32 from_uid;
    CW_UINT32 rcpt_sid;
    CW_UINT32 rcpt_uid;
    CW_BOOL has_cert;
    CW_UINT8 cert_sn[CERT_SERIAL_NUMBER_SZ];
    time_t mk_time;
    time_t s_time;
    CW_UINT64 size;
    wchar_t *text;
    CW_UINT32 text_len;
    CW_MSG_FILE_INFO *files;
    CW_UINT32 files_cnt;
} CW_MSG_DATA;

typedef struct {
    CW_BOOL online;
    CW_BOOL locked;
    IN_ADDR ip;
    CW_UINT16 l_port;
    char name[MAX_NAME_LEN + 1];
    char email[MAX_EMAIL_LEN + 1];
    CW_BOOL has_cert;
    struct {
        CW_UINT8 sn[CERT_SERIAL_NUMBER_SZ];
        time_t valid_from;
        time_t valid_until;
        char issr_name[CERT_MAX_NAME_LEN + 1];
        char subj_name[CERT_MAX_NAME_LEN + 1];
        char subj_email[CERT_MAX_EMAIL_LEN + 1];
        CW_CERT_TYPE type;
        CW_CERT_FLAGS flags;
    } cert_info;
} CW_USER_INFO;

typedef struct {
    CW_INFO_PACKET pckt;
    CW_UINT8 text[MAX_INFO_TEXT_SZ];
} CW_INFO_BLOCK;

typedef struct {
    FILE *fmsg;
    CW_UINT8 skey[SESSION_KEY_LEN];
    CW_MSG_PACKET_HEADER msg_head;
    CW_MSG_TEXT_HEADER text_head;
    wchar_t *text;
    CW_FILE_HEADER *file_heads;
} CW_MSGVIEW;

typedef struct {
    char work_dir[MAX_PATH + 1];
    CW_UINT32 sid;
    CW_UINT32 uid;
    CW_CERT root_cert;
    CW_CERT serv_cert;
    RSA_PUBLIC_KEY ku;
    RSA_PRIVATE_KEY kr;
    CW_UINT8 efs_key[EFS_KEY_LEN];
    CW_PACKETS_CTX srv_pctx;
    CW_UINT64 max_msg_sz;
    CW_UINT64 max_file_sz;
    CW_UINT16 kbps;
    CW_UINT8 comp_level;
    CW_UINT32 ping_timeout;
    pthread_t ping_thrd;
    pthread_mutex_t api_mtx;
} CW_CLIENT;

DLLEXPORT
    CWERROR;

DLLCALL client_keygen(const char *work_dir,
                      const char *ku_file,
                      const char *kr_file,
                      const char *efs_file,
                      const char *passwd,
                      const int kpair_sz);

DLLEXPORT
    CWERROR;

DLLCALL client_chpass(const char *work_dir,
                      const char *kr_file,
                      const char *efs_file,
                      const char *passwd,
                      const char *new_passwd);

DLLEXPORT
    CWERROR;

DLLCALL client_init(const char *work_dir,
                    const char *root_cert,
                    const char *serv_cert,
                    const char *ku_file,
                    const char *kr_file,
                    const char *efs_file,
                    const char *passwd,
                    const CW_UINT32 ping_timeout,
                    const CW_UINT8 comp_level);

DLLEXPORT
    CWERROR;

DLLCALL client_final(void);

DLLEXPORT
    CWERROR;

DLLCALL client_connect(const CW_CONNECT_MODE conn_mode,
                       const char *serv_addr,
                       const CW_UINT16 serv_port,
                       const char *proxy_addr,
                       const CW_UINT16 proxy_port,
                       const char *proxy_user,
                       const char *proxy_passwd,
                       const long recv_timeout);

DLLEXPORT
    CWERROR;

DLLCALL client_register(CW_UINT32 *sid, CW_UINT32 *uid, const char *name, const char *email);

DLLEXPORT
    CWERROR;

DLLCALL client_login(CW_UINT64 *max_msg_sz,
                     CW_UINT64 *max_file_sz,
                     const CW_UINT32 sid,
                     const CW_UINT32 uid,
                     const CW_UINT16 l_port,
                     const CW_UINT16 kbps,
                     ON_TIME_COLLISION on_time_col);

DLLEXPORT
    CWERROR;

DLLCALL client_logout(void);

DLLEXPORT
void DLLCALL client_get_stat(CW_UINT64* in_bytes, CW_UINT64 *out_bytes );


DLLEXPORT
    CWERROR;

DLLCALL client_request_cert(void);

DLLEXPORT
    CWERROR;

DLLCALL client_get_user_info(CW_USER_INFO *u_info,
                             const CW_UINT32 sid,
                             const CW_UINT32 uid);

DLLEXPORT
    CWERROR;

DLLCALL client_get_user_status(CW_BOOL *res,
                               const CW_UINT32 sid,
                               const CW_UINT32 uid);

DLLEXPORT
    CWERROR;

DLLCALL client_get_info(CW_INFO_BLOCK **info, CW_UINT32 *info_cnt);


DLLEXPORT
    CWERROR;

DLLCALL client_outbox_put(CW_INT64 *mid,
                          const CW_UINT32 sid,
                          const CW_UINT32 uid,
                          const wchar_t *text,
                          const CW_UINT32 text_len, /* in wchar_t-s */
                          const CW_MSG_FILE *files,
                          const CW_UINT32 f_cnt,
                          SET_PROGRESS set_progr,
                          UPDATE_PROGRESS updt_progr);

DLLEXPORT
    CWERROR;

DLLCALL client_get_storage_info(CW_STORAGE_INFO *mb_info);

DLLEXPORT
    CWERROR;

DLLCALL client_get_messages(SET_PROGRESS set_progr,
                            UPDATE_PROGRESS updt_progr,
                            SET_SUB_PROGRESS set_sub_progr,
                            UPDATE_SUB_PROGRESS updt_sub_progr);

DLLEXPORT
    CWERROR;

DLLCALL client_send_messages(const CW_INT64 mid,
                             SET_PROGRESS set_progr,
                             UPDATE_PROGRESS updt_progr,
                             SET_SUB_PROGRESS set_sub_progr,
                             UPDATE_SUB_PROGRESS updt_sub_progr);


DLLEXPORT
    CWERROR;

DLLCALL client_mailbox_read(CW_MSG_DESC **inbox,
                            CW_UINT32 *inbox_cnt,
                            CW_MSG_DESC **outbox,
                            CW_UINT32 *outbox_cnt,
                            CW_MSG_DESC **sent,
                            CW_UINT32 *sent_cnt,
                            CW_REPORT **reports,
                            CW_UINT32 *rep_cnt);

DLLEXPORT
    CWERROR;

DLLCALL client_inbox_set_read(CW_MSG_DESC *msg);

DLLEXPORT
    CWERROR;

DLLCALL client_inbox_delete(CW_MSG_DESC *msg);

DLLEXPORT
    CWERROR;

DLLCALL client_outbox_delete(CW_MSG_DESC *msg);

DLLEXPORT
    CWERROR;

DLLCALL client_sent_delete(CW_MSG_DESC *msg);

DLLEXPORT
    CWERROR;

DLLCALL client_report_delete(CW_REPORT *report);


DLLEXPORT
    CWERROR;

DLLCALL client_msgview_create(CW_MSGVIEW_HANDLE *hview,
                              CW_MSG_DESC *msg,
                              const CW_BOOL local_view);

DLLEXPORT
    CWERROR;

DLLCALL client_msgview_qinfo(CW_MSGVIEW_HANDLE hview, CW_MSG_DATA *mdata);

DLLEXPORT
    CWERROR;

DLLCALL client_msgview_extract(CW_MSGVIEW_HANDLE hview,
                               CW_MSG_DATA *mdata,
                               const CW_UINT32 index,
                               const char *fpath,
                               SET_PROGRESS set_progr,
                               UPDATE_PROGRESS updt_progr);

DLLEXPORT
void DLLCALL client_msgview_qfinish(CW_MSG_DATA *mdata);
DLLEXPORT
void DLLCALL client_msgview_free(CW_MSGVIEW_HANDLE hview);


DLLEXPORT
    CWERROR;

DLLCALL client_cont_add(CW_CONTACT *cont);

DLLEXPORT
    CWERROR;

DLLCALL client_cont_update(CW_CONTACT *cont);

DLLEXPORT
    CWERROR;

DLLCALL client_cont_read(CW_CONTACT **cont, CW_UINT32 *cont_cnt);

DLLEXPORT
    CWERROR;

DLLCALL client_cont_read_by_id(CW_CONTACT *cont,
                               CW_BOOL *exists,
                               const CW_UINT32 sid,
                               const CW_UINT32 uid);

DLLEXPORT
    CWERROR;

DLLCALL client_cont_delete(CW_CONTACT *cont);


DLLEXPORT
    CWERROR;

DLLCALL client_efs_cd(const CW_EFS_FILE_INFO_PACKET *fi);

DLLEXPORT
    CWERROR;

DLLCALL client_efs_cdup(void);

DLLEXPORT
    CWERROR;

DLLCALL client_efs_cdroot(void);

DLLEXPORT
    CWERROR;

DLLCALL client_efs_mkdir(const char *dname);

DLLEXPORT
    CWERROR;;

DLLCALL client_efs_addfile(const char *fpath,
                           const CW_UINT64 fsize,
                           SET_PROGRESS set_progr,
                           UPDATE_PROGRESS updt_progr);

DLLEXPORT
    CWERROR;;

DLLCALL client_efs_list(CW_EFS_FILE_INFO_PACKET **list,
                        CW_UINT32 *cnt,
                        SET_PROGRESS set_progr,
                        UPDATE_PROGRESS updt_progr);

DLLEXPORT
    CWERROR;;

DLLCALL client_efs_delete(const CW_EFS_FILE_INFO_PACKET *fi);

DLLEXPORT
    CWERROR;;

DLLCALL client_efs_get(const CW_EFS_FILE_INFO_PACKET *fi,
                       const char *path,
                       SET_PROGRESS set_progr,
                       UPDATE_PROGRESS updt_progr);

DLLEXPORT
    CWERROR;;

DLLCALL client_efs_wipefile(const char *fpath,
                            const CW_UINT64 fsize,
                            SET_PROGRESS set_progr,
                            UPDATE_PROGRESS updt_progr);

#endif
