#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "utils.h"
#include "futils.h"
#include "shared_list.h"
#include "crypto.h"
#include "cert_struct.h"
#include "packets_struct.h"
#include "sqlite3.h"
#include "db.h"

#include "query.h"

CWERROR db_inbox_add(CW_DB_CONNECTION *db,
                     const CW_UINT32 sid,
                     const CW_UINT32 uid,
                     const CW_UINT64 size,
                     const char *file)
{
	static const char query[] = "INSERT INTO inbox_mail (sid,uid,msg_sz,file) VALUES(?,?,?,?)";
	
	CW_DB_VALUE        binds[4] = {{DB_INT64, (CW_INT64)sid},
                                   {DB_INT64, (CW_INT64)uid},
                                   {DB_INT64, (CW_INT64)size},
                                   {DB_TEXT, 0}};
	CWERROR	           err = CW_ER_OK;
	
	binds[3].value.as_text.len = MSG_FILE_NAME_LEN;
	binds[3].value.as_text.text = (unsigned char *)file;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 4)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_inbox_get_list(CW_DB_CONNECTION *db,
                          CW_MSG_DESC **dlist,
                          CW_UINT32 *count)
{
	static const char query[] = "SELECT mid,sid,uid,datetime(add_dt,'localtime'),read_flag,msg_sz,file FROM inbox_mail ORDER BY add_dt COLLATE NOCASE DESC";

	CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_MSG_DESC        *list = NULL;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, NULL, 0)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }

    if ((n = *count = DB_RESULT_ROW_COUNT(res)) == 0) {
        db_result_free(&res);
        return CW_ER_OK;    
    }
    
    if ((list = *dlist = DLL_MALLOC(sizeof(CW_MSG_DESC) * n)) == NULL) {
		DEBUG_ERROR();
		db_result_free(&res);
		return CW_ER_MEMORY;
	}
	
	row = DB_RESULT_ROW_FIRST(res);
	do {
        list[i].mid = DB_RESULT_AS_INT64(row, 0);
        list[i].sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
        list[i].uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
        if (strcpy_s(list[i].add_dt, DB_RESULT_AS_TEXT(row, 3), sizeof(list[i].add_dt)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
        list[i].read_flag = ((strcmp(DB_RESULT_AS_TEXT(row, 4), "Y") == 0) ? TRUE : FALSE);
	    list[i].sz = (CW_UINT64)DB_RESULT_AS_INT64(row, 5);
	    if (strcpy_s(list[i].file, DB_RESULT_AS_TEXT(row, 6), sizeof(list[i].file)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
        ++i;  
    } while (((row = DB_RESULT_ROW_NEXT(row)) != NULL) && (--n));

    db_result_free(&res);
	
    return CW_ER_OK;
}

CWERROR db_inbox_set_read(CW_DB_CONNECTION *db, CW_MSG_DESC *msg)
{
    static const char query[] = "UPDATE inbox_mail SET read_flag=? WHERE mid=?";
	
    CW_DB_VALUE        binds[2] = {{DB_TEXT, 0},
                                   {DB_INT64, msg->mid}};
    char               flag[2] = {'Y', '\0'};
	CWERROR	           err = CW_ER_OK;
	
	flag[0] = ((msg->read_flag == TRUE) ? 'N' : 'Y');

	binds[0].value.as_text.len = 1;
	binds[0].value.as_text.text = (unsigned char *)flag;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 2)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_inbox_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg)
{
    static const char query[] = "DELETE FROM inbox_mail WHERE mid=?";
	
    CW_DB_VALUE     bind = {DB_INT64, msg->mid};
	CWERROR	        err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_outbox_add(CW_DB_CONNECTION *db,
                      CW_INT64 *mid,
                      const CW_UINT32 sid,
                      const CW_UINT32 uid,
                      const CW_UINT64 size,
                      const char *file)
{
    static const char query[] = "INSERT INTO outbox_mail (sid,uid,msg_sz,file) VALUES(?,?,?,?)";
	
    CW_DB_VALUE        binds[4] = {{DB_INT64, (CW_INT64)sid},
                                   {DB_INT64, (CW_INT64)uid},
                                   {DB_INT64, (CW_INT64)size},
                                   {DB_TEXT, 0}};
	CWERROR	           err = CW_ER_OK;

	binds[3].value.as_text.len = MSG_FILE_NAME_LEN;
	binds[3].value.as_text.text = (unsigned char *)file;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 4)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }
    
    if ((*mid = sqlite3_last_insert_rowid(db)) == 0) {
        DEBUG_ERROR(); 
        err = CW_ER_DB_QUERY;  
    }

	return err;
}

CWERROR db_outbox_get_list(CW_DB_CONNECTION *db,
                           CW_MSG_DESC **dlist,
                           CW_UINT32 *count)
{
	static const char query[] = "SELECT mid,sid,uid,datetime(add_dt,'localtime'),msg_sz,file FROM outbox_mail ORDER BY add_dt COLLATE NOCASE DESC";
	
    CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_MSG_DESC        *list = NULL;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, NULL, 0)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }

    if ((n = *count = DB_RESULT_ROW_COUNT(res)) == 0) {
        db_result_free(&res);
        return CW_ER_OK;
    }

    if ((list = *dlist = DLL_MALLOC(sizeof(CW_MSG_DESC) * n)) == NULL) {
		DEBUG_ERROR();
		db_result_free(&res);
		return CW_ER_MEMORY;
	}

	row = DB_RESULT_ROW_FIRST(res);
	do {
        list[i].mid = DB_RESULT_AS_INT64(row, 0);
        list[i].sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
        list[i].uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
        if (strcpy_s(list[i].add_dt, DB_RESULT_AS_TEXT(row, 3), sizeof(list[i].add_dt)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
	    list[i].sz = (CW_UINT64)DB_RESULT_AS_INT64(row, 4);
	    if (strcpy_s(list[i].file, DB_RESULT_AS_TEXT(row, 5), sizeof(list[i].file)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
        ++i;
    } while (((row = DB_RESULT_ROW_NEXT(row)) != NULL) && (--n));

    db_result_free(&res);

    return CW_ER_OK;
}

CWERROR db_outbox_get_by_id(CW_DB_CONNECTION *db,
                            CW_MSG_DESC *msg,
                            const CW_INT64 mid)
{
    static const char query[] = "SELECT mid,sid,uid,add_dt,msg_sz,file FROM outbox_mail WHERE mid=?";
    
    CW_DB_VALUE        bind = {DB_INT64, mid};
	CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }
	row = DB_RESULT_ROW_FIRST(res);
    
    msg->mid = DB_RESULT_AS_INT64(row, 0);
    msg->sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
    msg->uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
    if (strcpy_s(msg->add_dt, DB_RESULT_AS_TEXT(row, 3), sizeof(msg->add_dt)) == NULL) {
        DEBUG_ERROR();
        db_result_free(&res);
        return CW_ER_INTERNAL;
    }
	msg->sz = (CW_UINT64)DB_RESULT_AS_INT64(row, 4);
	if (strcpy_s(msg->file, DB_RESULT_AS_TEXT(row, 5), sizeof(msg->file)) == NULL) {
        DEBUG_ERROR();
        db_result_free(&res);
        return CW_ER_INTERNAL;
    }

    db_result_free(&res);

    return CW_ER_OK;
}

CWERROR db_outbox_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg)
{
    static const char query[] = "DELETE FROM outbox_mail WHERE mid=?";
	
    CW_DB_VALUE     bind = {DB_INT64, msg->mid};
	CWERROR	        err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}
CWERROR db_sent_add(CW_DB_CONNECTION *db,
                    const CW_UINT32 sid,
                    const CW_UINT32 uid,
                    const CW_UINT64 size,
                    const char *file)
{
    static const char query[] = "INSERT INTO sent_mail (sid,uid,msg_sz,file) VALUES(?,?,?,?)";
    
	CW_DB_VALUE        binds[4] = {{DB_INT64, (CW_INT64)sid},
                                   {DB_INT64, (CW_INT64)uid},
                                   {DB_INT64, (CW_INT64)size},
                                   {DB_TEXT, 0}};
	CWERROR	           err = CW_ER_OK;

	binds[3].value.as_text.len = MSG_FILE_NAME_LEN;
	binds[3].value.as_text.text = (unsigned char *)file;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 4)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_sent_get_list(CW_DB_CONNECTION *db,
                         CW_MSG_DESC **dlist,
                         CW_UINT32 *count)
{
	static const char query[] = "SELECT mid,sid,uid,datetime(add_dt,'localtime'),msg_sz,file FROM sent_mail ORDER BY add_dt COLLATE NOCASE DESC";
	
    CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_MSG_DESC        *list = NULL;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, NULL, 0)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }

    if ((n = *count = DB_RESULT_ROW_COUNT(res)) == 0) {
        db_result_free(&res);
        return CW_ER_OK;
    }

    if ((list = *dlist = DLL_MALLOC(sizeof(CW_MSG_DESC) * n)) == NULL) {
		DEBUG_ERROR();
		db_result_free(&res);
		return CW_ER_MEMORY;
	}

	row = DB_RESULT_ROW_FIRST(res);
	do {
        list[i].mid = DB_RESULT_AS_INT64(row, 0);
        list[i].sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
        list[i].uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
        if (strcpy_s(list[i].add_dt, DB_RESULT_AS_TEXT(row, 3), sizeof(list[i].add_dt)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
	    list[i].sz = (CW_UINT64)DB_RESULT_AS_INT64(row, 4);
	    if (strcpy_s(list[i].file, DB_RESULT_AS_TEXT(row, 5), sizeof(list[i].file)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
        ++i;
    } while (((row = DB_RESULT_ROW_NEXT(row)) != NULL) && (--n));

    db_result_free(&res);

    return CW_ER_OK;
}

CWERROR db_sent_delete(CW_DB_CONNECTION *db, CW_MSG_DESC *msg)
{
    static const char query[] = "DELETE FROM sent_mail WHERE mid=?";
	
    CW_DB_VALUE     bind = {DB_INT64, msg->mid};
	CWERROR	        err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_report_add(CW_DB_CONNECTION *db,
					  const CW_UINT32 rcpt_sid,
					  const CW_UINT32 rcpt_uid,
					  const CW_UINT32 code)
{
	static const char query[] = "INSERT INTO reports (sid,uid,code) VALUES(?,?,?)";
				  
	CW_DB_VALUE        binds[4] = {{DB_INT64, (CW_INT64)rcpt_sid},
                                   {DB_INT64, (CW_INT64)rcpt_uid},
                                   {DB_INT64, (CW_INT64)code}};
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 3)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_reports_get_list(CW_DB_CONNECTION *db,
                            CW_REPORT **rlist,
                            CW_UINT32 *count)
{
	static const char query[] = "SELECT rid,sid,uid,datetime(add_dt,'localtime'),code FROM reports ORDER BY add_dt COLLATE NOCASE DESC";
	    
    CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_REPORT          *list = NULL;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, NULL, 0)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }

    if ((n = *count = DB_RESULT_ROW_COUNT(res)) == 0) {
        db_result_free(&res);
        return CW_ER_OK;
    }

    if ((list = *rlist = DLL_MALLOC(sizeof(CW_REPORT) * n)) == NULL) {
		DEBUG_ERROR();
		db_result_free(&res);
		return CW_ER_MEMORY;
	}

	row = DB_RESULT_ROW_FIRST(res);
	do {
        list[i].rid = DB_RESULT_AS_INT64(row, 0);
        list[i].pckt.rcpt_sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
        list[i].pckt.rcpt_uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
        if (strcpy_s(list[i].add_dt, DB_RESULT_AS_TEXT(row, 3), sizeof(list[i].add_dt)) == NULL) {
            DEBUG_ERROR();
            DLL_FREE(list);
            db_result_free(&res);
            return CW_ER_INTERNAL;
        }
	    list[i].pckt.code = (CW_UINT32)DB_RESULT_AS_INT64(row, 4);
        ++i;
    } while (((row = DB_RESULT_ROW_NEXT(row)) != NULL) && (--n));

    db_result_free(&res);

    return CW_ER_OK;
}

CWERROR db_report_delete(CW_DB_CONNECTION *db, CW_REPORT *rept)
{
    static const char query[] = "DELETE FROM reports WHERE rid=?";
	
    CW_DB_VALUE     bind = {DB_INT64, rept->rid};
	CWERROR	        err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_cont_add(CW_DB_CONNECTION *db, CW_CONTACT *cont)
{
    static const char query[] = "INSERT INTO contacts (sid,uid,name,mname,lname,addr,phone,mphone,fax,www,email,company,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)";

	CW_DB_VALUE        binds[13] = {{DB_INT64, (CW_INT64)cont->sid},
                                    {DB_INT64, (CW_INT64)cont->uid},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}};
	CWERROR	           err = CW_ER_OK;
	
	binds[2].value.as_blob.sz = (wcslen(cont->name) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[2].value.as_blob.blob = cont->name;
	binds[3].value.as_blob.sz = (wcslen(cont->mname) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[3].value.as_blob.blob = cont->mname;
	binds[4].value.as_blob.sz = (wcslen(cont->lname) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[4].value.as_blob.blob = cont->lname;
	binds[5].value.as_blob.sz = (wcslen(cont->addr) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[5].value.as_blob.blob = cont->addr;
	binds[6].value.as_blob.sz = (wcslen(cont->phone) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[6].value.as_blob.blob = cont->phone;
	binds[7].value.as_blob.sz = (wcslen(cont->mphone) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[7].value.as_blob.blob = cont->mphone;
	binds[8].value.as_blob.sz = (wcslen(cont->fax) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[8].value.as_blob.blob = cont->fax;
	binds[9].value.as_blob.sz = (wcslen(cont->www) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[9].value.as_blob.blob = cont->www;
	binds[10].value.as_blob.sz = (wcslen(cont->email) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[10].value.as_blob.blob = cont->email;
	binds[11].value.as_blob.sz = (wcslen(cont->comp) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[11].value.as_blob.blob = cont->comp;
	binds[12].value.as_blob.sz = (wcslen(cont->notes) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[12].value.as_blob.blob = cont->notes;
	
	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 13)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}

CWERROR db_cont_update(CW_DB_CONNECTION *db, CW_CONTACT *cont)
{
    static const char query[] = "UPDATE contacts SET sid=?,uid=?,name=?,mname=?,lname=?,addr=?,phone=?,mphone=?,fax=?,www=?,email=?,company=?,notes=? WHERE cid=?";

	CW_DB_VALUE        binds[14] = {{DB_INT64, (CW_INT64)cont->sid},
                                    {DB_INT64, (CW_INT64)cont->uid},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_BLOB, 0}, {DB_BLOB, 0},
                                    {DB_INT64, (CW_INT64)cont->cid}};
	CWERROR	           err = CW_ER_OK;

	binds[2].value.as_blob.sz = (wcslen(cont->name) * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[2].value.as_blob.blob = cont->name;
	binds[3].value.as_blob.sz = (wcslen(cont->mname) * sizeof(wchar_t))  + sizeof(wchar_t);
	binds[3].value.as_blob.blob = cont->mname;
	binds[4].value.as_blob.sz = (wcslen(cont->lname)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[4].value.as_blob.blob = cont->lname;
	binds[5].value.as_blob.sz = (wcslen(cont->addr)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[5].value.as_blob.blob = cont->addr;
	binds[6].value.as_blob.sz = (wcslen(cont->phone)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[6].value.as_blob.blob = cont->phone;
	binds[7].value.as_blob.sz = (wcslen(cont->mphone)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[7].value.as_blob.blob = cont->mphone;
	binds[8].value.as_blob.sz = (wcslen(cont->fax)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[8].value.as_blob.blob = cont->fax;
	binds[9].value.as_blob.sz = (wcslen(cont->www)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[9].value.as_blob.blob = cont->www;
	binds[10].value.as_blob.sz = (wcslen(cont->email)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[10].value.as_blob.blob = cont->email;
	binds[11].value.as_blob.sz = (wcslen(cont->comp)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[11].value.as_blob.blob = cont->comp;
	binds[12].value.as_blob.sz = (wcslen(cont->notes)  * sizeof(wchar_t)) + sizeof(wchar_t);
	binds[12].value.as_blob.blob = cont->notes;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &binds[0], 14)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;   
}

CWERROR db_cont_get_list(CW_DB_CONNECTION *db,
                         CW_CONTACT **clist,
                         CW_UINT32 *count)
{
    static const char query[] = "SELECT cid,sid,uid,name,mname,lname,addr,phone,mphone,fax,www,email,company,notes FROM contacts";

    CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_CONTACT         *list = NULL;
	CW_UINT32          n, i = 0;
	CWERROR	           err = CW_ER_OK;

	if ((err = db_query(db, &res, query, sizeof(query)-1, NULL, 0)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }

    if ((n = *count = DB_RESULT_ROW_COUNT(res)) == 0) {
        db_result_free(&res);
        return CW_ER_OK;
    }

    if ((list = *clist = DLL_MALLOC(sizeof(CW_CONTACT) * n)) == NULL) {
		DEBUG_ERROR();
		db_result_free(&res);
		return CW_ER_MEMORY;
	}

	row = DB_RESULT_ROW_FIRST(res);
	do {
        list[i].cid = DB_RESULT_AS_INT64(row, 0);
        list[i].sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
        list[i].uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
        #define WSTRCPY(to, n) \
            if (wcscpy_s((to), DB_RESULT_AS_BLOB(row, (n)), sizeof((to))) == NULL) { \
                DEBUG_ERROR(); \
                DLL_FREE(list); \
                db_result_free(&res); \
                return CW_ER_INTERNAL; \
            }
        WSTRCPY(list[i].name, 3);
        WSTRCPY(list[i].mname, 4);
        WSTRCPY(list[i].lname, 5);
        WSTRCPY(list[i].addr, 6);
        WSTRCPY(list[i].phone, 7);
        WSTRCPY(list[i].mphone, 8);
        WSTRCPY(list[i].fax, 9);
        WSTRCPY(list[i].www, 10);
        WSTRCPY(list[i].email, 11);
        WSTRCPY(list[i].comp, 12);
        WSTRCPY(list[i].notes, 13);
        #undef WSTRCPY        
        ++i;
    } while (((row = DB_RESULT_ROW_NEXT(row)) != NULL) && (--n));

    db_result_free(&res);

    return CW_ER_OK;
}

CWERROR db_cont_get_by_id(CW_DB_CONNECTION *db,
                          CW_CONTACT *cont,
                          CW_BOOL *exists,
                          const CW_UINT32 sid,
                          const CW_UINT32 uid)
{
    static const char query[] = "SELECT cid,sid,uid,name,mname,lname,addr,phone,mphone,fax,www,email,company,notes FROM contacts WHERE sid=? AND uid=?";

    CW_DB_RESULT       res;
	CW_DB_RESULT_ROW   *row;
	CW_DB_VALUE        binds[2] = {{DB_INT64, (CW_INT64)sid},
                                   {DB_INT64, (CW_INT64)uid}};
	CWERROR	           err = CW_ER_OK;
	
	*exists = FALSE;

	if ((err = db_query(db, &res, query, sizeof(query)-1, &binds[0], 2)) != CW_ER_OK) {
        DEBUG_ERROR();
        db_result_free(&res);
        return err;
    }
    
    if (DB_RESULT_ROW_COUNT(res) == 0) {
        db_result_free(&res);
        return CW_ER_OK;
    }
    
    row = DB_RESULT_ROW_FIRST(res);
	
    cont->cid = DB_RESULT_AS_INT64(row, 0);
    cont->sid = (CW_UINT32)DB_RESULT_AS_INT64(row, 1);
    cont->uid = (CW_UINT32)DB_RESULT_AS_INT64(row, 2);
    #define WSTRCPY(to, n) \
        if (wcscpy_s((to), DB_RESULT_AS_BLOB(row, (n)), sizeof((to))) == NULL) { \
            DEBUG_ERROR(); \
            db_result_free(&res); \
            return CW_ER_INTERNAL; \
        }
    WSTRCPY(cont->name, 3);
    WSTRCPY(cont->mname, 4);
    WSTRCPY(cont->lname, 5);
    WSTRCPY(cont->addr, 6);
    WSTRCPY(cont->phone, 7);
    WSTRCPY(cont->mphone, 8);
    WSTRCPY(cont->fax, 9);
    WSTRCPY(cont->www, 10);
    WSTRCPY(cont->email, 11);
    WSTRCPY(cont->comp, 12);
    WSTRCPY(cont->notes, 13);
    #undef WSTRCPY
    
    *exists = TRUE;

    db_result_free(&res);
    
    return CW_ER_OK;   
}

CWERROR db_cont_delete(CW_DB_CONNECTION *db, CW_CONTACT *cont)
{
    static const char query[] = "DELETE FROM contacts WHERE cid=?";

    CW_DB_VALUE     bind = {DB_INT64, cont->cid};
	CWERROR	        err = CW_ER_OK;

	if ((err = db_query(db, NULL, query, sizeof(query)-1, &bind, 1)) != CW_ER_OK) {
        DEBUG_ERROR();
        return err;
    }

	return CW_ER_OK;
}
