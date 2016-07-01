#ifndef _QUERY_H_
#define _QUERY_H_
#define MSG_FILE_NAME_LEN	        20

#define MAX_CONTACT_NAME_LEN        50
#define MAX_CONTACT_ADDR_LEN        100
#define MAX_CONTACT_PHONE_LEN       32
#define MAX_CONTACT_WEBADDR_LEN     128
#define MAX_CONTACT_NOTES_LEN       512

typedef struct {
    CW_INT64    mid;
	CW_UINT32	sid;
	CW_UINT32	uid;
	char		add_dt[MAX_TIMESTAMP_LEN + 1];
	CW_BOOL     read_flag;
	CW_UINT64	sz;
	char		file[MSG_FILE_NAME_LEN + 1];
} CW_MSG_DESC;

typedef struct {
	CW_INT64		     rid;
	char		         add_dt[MAX_TIMESTAMP_LEN + 1];
	CW_REPORT_PACKET     pckt;
} CW_REPORT;

typedef struct {
    CW_INT64    cid;
    CW_UINT32   sid;
    CW_UINT32   uid;
    wchar_t     name[MAX_CONTACT_NAME_LEN + 1];
    wchar_t     mname[MAX_CONTACT_NAME_LEN + 1];
    wchar_t     lname[MAX_CONTACT_NAME_LEN + 1];
    wchar_t     addr[MAX_CONTACT_ADDR_LEN + 1];
    wchar_t     phone[MAX_CONTACT_PHONE_LEN + 1];
    wchar_t     mphone[MAX_CONTACT_PHONE_LEN + 1];
    wchar_t     fax[MAX_CONTACT_PHONE_LEN + 1];
    wchar_t     www[MAX_CONTACT_WEBADDR_LEN + 1];
    wchar_t     email[MAX_CONTACT_WEBADDR_LEN + 1];
    wchar_t     comp[MAX_CONTACT_NAME_LEN + 1];
    wchar_t     notes[MAX_CONTACT_NOTES_LEN + 1];
} CW_CONTACT;
CWERROR db_inbox_add(CW_DB_CONNECTION *db, 
                     const CW_UINT32 sid,
                     const CW_UINT32 uid, 
                     const CW_UINT64 size, 
                     const char *file);

CWERROR db_inbox_get_list(CW_DB_CONNECTION *db, 
                          CW_MSG_DESC **dlist, 
                          CW_UINT32 *count);
                          
CWERROR db_inbox_set_read(CW_DB_CONNECTION *db, CW_MSG_DESC *msg);
								
CWERROR db_inbox_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg);

CWERROR db_outbox_add(CW_DB_CONNECTION *db,
                      CW_INT64 *mid,
                      const CW_UINT32 sid,
                      const CW_UINT32 uid,
                      const CW_UINT64 size,
                      const char *file);

CWERROR db_outbox_get_list(CW_DB_CONNECTION *db,
                           CW_MSG_DESC **dlist,
                           CW_UINT32 *count);
                           
CWERROR db_outbox_get_by_id(CW_DB_CONNECTION *db, 
                            CW_MSG_DESC *msg,
                            const CW_INT64 mid);

CWERROR db_outbox_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg);

CWERROR db_sent_add(CW_DB_CONNECTION *db,
                    const CW_UINT32 sid,
                    const CW_UINT32 uid,
                    const CW_UINT64 size,
                    const char *file);

CWERROR db_sent_get_list(CW_DB_CONNECTION *db,
                         CW_MSG_DESC **dlist,
                         CW_UINT32 *count);

CWERROR db_sent_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg);

CWERROR db_report_add(CW_DB_CONNECTION *db,
					  const CW_UINT32 rcpt_sid,
					  const CW_UINT32 rcpt_uid,
					  const CW_UINT32 code);

CWERROR db_reports_get_list(CW_DB_CONNECTION *db, 
                            CW_REPORT **rlist, 
                            CW_UINT32 *count);
					   
CWERROR db_report_delete(CW_DB_CONNECTION *db, CW_REPORT *rept);

CWERROR db_cont_add(CW_DB_CONNECTION *db, CW_CONTACT *cont);

CWERROR db_cont_update(CW_DB_CONNECTION *db, CW_CONTACT *cont);

CWERROR db_cont_get_list(CW_DB_CONNECTION *db,
                         CW_CONTACT **clist,
                         CW_UINT32 *count);
                         
CWERROR db_cont_get_by_id(CW_DB_CONNECTION *db,
                          CW_CONTACT *cont,
                          CW_BOOL *exists,
                          const CW_UINT32 sid,
                          const CW_UINT32 uid);

CWERROR db_cont_delete(CW_DB_CONNECTION *db, CW_CONTACT *cont);

#endif
