#ifndef _DB_H_
#define _DB_H_

#define __USE_UTF16_FILE_NAME


#define DB_QUERY_DELAY  3
#define DB_FIRST_ID     1


typedef sqlite3 CW_DB_CONNECTION;


typedef enum {
    DB_INT64 = SQLITE_INTEGER,
    DB_DOUBLE = SQLITE_FLOAT,
    DB_BLOB = SQLITE_BLOB,
    DB_NULL = SQLITE_NULL,
    DB_TEXT = SQLITE3_TEXT
} CW_DB_VALUE_TYPE;

typedef struct {
    int len;
    unsigned char *text;
} CW_DB_TEXT;

typedef struct {
    int sz;
    void *blob;
} CW_DB_BLOB;

typedef struct {
    CW_DB_VALUE_TYPE type;
    union {
        CW_INT64 as_int64;
        double as_double;
        CW_DB_TEXT as_text;
        CW_DB_BLOB as_blob;
        void *as_null;
    } value;
} CW_DB_VALUE;

struct _db_result_row {
    struct _db_result_row *_next;
    CW_INT64 col_cnt;
    CW_DB_VALUE *values;
};
typedef struct _db_result_row CW_DB_RESULT_ROW;

typedef struct {
    CW_INT64 row_cnt;
    CW_DB_RESULT_ROW *first_row;
    CW_DB_RESULT_ROW *last_row;
} CW_DB_RESULT;

#define DB_RESULT_INIT(res) {(res)->row_cnt = 0; (res)->first_row = (res)->last_row = NULL;}
#define DB_ROW_INIT(row)    {(row)->_next = NULL; (row)->col_cnt = 0; (row)->values = NULL;}

#define DB_RESULT_ROW_COUNT(res)        ((res).row_cnt)
#define DB_RESULT_ROW_FIRST(res)        ((res).first_row)
#define DB_RESULT_ROW_NEXT(row)         ((row)->_next)
#define DB_RESULT_COL_TYPE(row, n)      ((row)->values[(n)].type)
#define DB_RESULT_AS_INT64(row, n)      ((row)->values[(n)].value.as_int64)
#define DB_RESULT_AS_DOUBLE(row, n)     ((row)->values[(n)].value.as_double)
#define DB_RESULT_AS_TEXT(row, n)       ((row)->values[(n)].value.as_text.text)
#define DB_RESULT_TEXT_LEN(row, n)      ((row)->values[(n)].value.as_text.len)
#define DB_RESULT_AS_BLOB(row, n)       ((row)->values[(n)].value.as_blob.blob)
#define DB_RESULT_BLOB_SIZE(row, n)     ((row)->values[(n)].value.as_blob.sz)


CWERROR db_init(const char *db_file);

CWERROR db_open(CW_DB_CONNECTION **db);

CWERROR db_close(CW_DB_CONNECTION *db);

CWERROR db_query(CW_DB_CONNECTION *db,
                 CW_DB_RESULT *res,
                 const char *query,
                 const int len,
                 const CW_DB_VALUE *binds,
                 const int b_cnt);

void db_result_free(CW_DB_RESULT *db_res);

#endif