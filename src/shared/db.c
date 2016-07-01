#include "general.h"
#include "errors.h"
#include "futils.h"
#include "utils.h"
#include "crypto.h"
#include "cert_struct.h"
#include "packets_struct.h"
#include "sqlite3.h"

#include "db.h"

static char _db_file[MAX_PATH + 1];

static __inline CW_DB_RESULT_ROW *_row_add(CW_DB_RESULT *db_res) {
  register CW_DB_RESULT_ROW *new_row = NULL;

  if ((new_row = malloc(sizeof(CW_DB_RESULT_ROW))) == NULL) {
    DEBUG_ERROR();
    return NULL;
  }

  DB_ROW_INIT(new_row);

  if (db_res->row_cnt == 0) {
    db_res->first_row = db_res->last_row = new_row;
  } else {
    db_res->last_row->_next = new_row;
    db_res->last_row = new_row;
  }

  return new_row;
}

static __inline CWERROR _fill_current_row(CW_DB_RESULT_ROW *row, sqlite3_stmt *stmt) {
  register int i = 0;

  if ((row->col_cnt = sqlite3_data_count(stmt)) == 0) {
    return CW_ER_OK;
  }

  if ((row->values = malloc(sizeof(CW_DB_VALUE) * row->col_cnt)) == NULL) {
    DEBUG_ERROR();
    return CW_ER_MEMORY;
  }

  for (; i < row->col_cnt; i++) {
    switch (row->values[i].type = sqlite3_column_type(stmt, i)) {
      case SQLITE_INTEGER:
        row->values[i].value.as_int64 = sqlite3_column_int64(stmt, i);
        break;
      case SQLITE_FLOAT:
        row->values[i].value.as_double = sqlite3_column_double(stmt, i);
        break;
      case SQLITE_BLOB:
        if ((row->values[i].value.as_blob.sz = sqlite3_column_bytes(stmt, i)) > 0) {
          if ((row->values[i].value.as_blob.blob = malloc(row->values[i].value.as_blob.sz)) == NULL) {
            DEBUG_ERROR();
            return CW_ER_MEMORY;
          }
          memcpy(row->values[i].value.as_blob.blob, sqlite3_column_blob(stmt, i), row->values[i].value.as_blob.sz);
        }
        break;
      case SQLITE3_TEXT:
        if ((row->values[i].value.as_text.len = sqlite3_column_bytes(stmt, i)) > 0) {
          if ((row->values[i].value.as_text.text = malloc(
              (sizeof(unsigned char) * row->values[i].value.as_text.len) + sizeof(unsigned char))) == NULL) {
            DEBUG_ERROR();
            return CW_ER_MEMORY;
          }
          if (strcpy_s(row->values[i].value.as_text.text, sqlite3_column_text(stmt, i),
                       row->values[i].value.as_text.len + 1) == NULL) {
            DEBUG_ERROR();
            return CW_ER_INTERNAL;
          }
        }
        break;
      case SQLITE_NULL:
        row->values[i].value.as_null = NULL;
        break;
      default:
        DEBUG_ERROR();
        return CW_ER_DB_QUERY;
        break;
    }
  }

  return CW_ER_OK;
}

CWERROR db_init(const char *db_file) {
  if (strcpy_s(_db_file, db_file, sizeof(_db_file)) == NULL) {
    DEBUG_ERROR();
    return CW_ER_OPEN_DB;
  }

  if (sqlite3_enable_shared_cache(1) != SQLITE_OK) {
    DEBUG_ERROR();
    return CW_ER_INTERNAL;
  }

  return CW_ER_OK;
}

CWERROR db_open(CW_DB_CONNECTION **db) {
#ifdef __USE_UTF16_FILE_NAME
  wchar_t w_db_file[MAX_PATH + 1];

  wsprintfW(w_db_file, L"%S", _db_file);

  if (sqlite3_open16(w_db_file, db) != SQLITE_OK) {
    sqlite3_close(*db);
    DEBUG_ERROR();
    return CW_ER_OPEN_DB;
  }
#else
  if (sqlite3_open(_db_file, db) != SQLITE_OK) {
      sqlite3_close(*db);
      DEBUG_ERROR();
      return CW_ER_OPEN_DB;
  }
#endif

  return CW_ER_OK;
}

CWERROR db_close(CW_DB_CONNECTION *db) {
  if (db != NULL) {
    sqlite3_interrupt(db);
    if (sqlite3_close(db) != SQLITE_OK) {
      DEBUG_ERROR();
      return CW_ER_CLOSE_DB;
    }
  }

  return CW_ER_OK;
}

CWERROR db_query(CW_DB_CONNECTION *db,
                 CW_DB_RESULT *res,
                 const char *query,
                 const int len,
                 const CW_DB_VALUE *binds,
                 const int b_cnt) {
  sqlite3_stmt *stmt;
  CW_DB_RESULT_ROW *row;
  register CW_BOOL trying = TRUE;
  register int i = 0, sq_res;
  CWERROR err = CW_ER_OK;

  if (res != NULL) {
    DB_RESULT_INIT(res);
  }

  if (sqlite3_prepare_v2(db, query, len, &stmt, NULL) != SQLITE_OK) {
    DEBUG_ERROR();
    log_write("%s%s\n", "sqlite3_prepare_v2: ", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return CW_ER_DB_QUERY;
  }

  for (; i < b_cnt; i++) {
    switch (binds[i].type) {
      case SQLITE_INTEGER:
        sq_res = sqlite3_bind_int64(stmt, i + 1, binds[i].value.as_int64);
        break;
      case SQLITE_FLOAT:
        sq_res = sqlite3_bind_double(stmt, i + 1, binds[i].value.as_double);
        break;
      case SQLITE_BLOB:
        sq_res = sqlite3_bind_blob(stmt, i + 1, binds[i].value.as_blob.blob, binds[i].value.as_blob.sz, SQLITE_STATIC);
        break;
      case SQLITE3_TEXT:
        sq_res = sqlite3_bind_text(stmt, i + 1, binds[i].value.as_text.text, binds[i].value.as_text.len, SQLITE_STATIC);
        break;
      case SQLITE_NULL:
        sq_res = sqlite3_bind_null(stmt, i + 1);
        break;
      default:
        DEBUG_ERROR();
        sqlite3_finalize(stmt);
        return CW_ER_INTERNAL;
        break;
    }
  }
  if ((b_cnt > 0) && (sq_res != SQLITE_OK)) {
    DEBUG_ERROR();
    sqlite3_finalize(stmt);
    return CW_ER_DB_QUERY;
  }

  while (trying) {
    switch (sqlite3_step(stmt)) {
      case SQLITE_ROW:
        if (res != NULL) {
          if ((row = _row_add(res)) == NULL) {
            DEBUG_ERROR();
            sqlite3_finalize(stmt);
            return CW_ER_DB_QUERY;
          }
          if ((err = _fill_current_row(row, stmt)) != CW_ER_OK) {
            DEBUG_ERROR();
            sqlite3_finalize(stmt);
            return err;
          }
          ++(res->row_cnt);
        }
        break;
      case SQLITE_BUSY:
        delay(DB_QUERY_DELAY);
        break;
      case SQLITE_DONE:
        trying = FALSE;
        break;
      default:
        DEBUG_ERROR();
        sqlite3_finalize(stmt);
        return CW_ER_DB_QUERY;
        break;
    }
  }
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    DEBUG_ERROR();
    return CW_ER_DB_QUERY;
  }

  return CW_ER_OK;
}

void db_result_free(CW_DB_RESULT *db_res) {
  register CW_DB_RESULT_ROW *c_row = db_res->first_row, *n_row;
  register int i = 0;

  while ((db_res->row_cnt--) && (c_row != NULL)) {
    for (; i < c_row->col_cnt; i++) {
      if (c_row->values[i].type == DB_BLOB) {
        if (c_row->values[i].value.as_blob.sz > 0) {
          free(c_row->values[i].value.as_blob.blob);
        }
      }
      if (c_row->values[i].type == DB_TEXT) {
        if (c_row->values[i].value.as_text.len > 0) {
          free(c_row->values[i].value.as_text.text);
        }
      }
    }
    n_row = c_row->_next;
    if (c_row->col_cnt > 0) {
      free(c_row->values);
    }
    free(c_row);
    c_row = n_row;
  }
}
