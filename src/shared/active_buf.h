#ifndef _ACTIVE_BUF_H_
#define _ACTIVE_BUF_H_
typedef struct {
	CW_UINT32 size;
	CW_UINT8 *buf;
} CW_BUFFER;

typedef CWERROR (*AB_ON_FULL_FUNC)(CW_BUFFER *cwbuf, void *param);

typedef struct {
	CW_UINT32		sz;
	CW_UINT32		pb;
	CW_UINT8		*buf;
	AB_ON_FULL_FUNC	on_full_func;
} CW_ACTIVE_BUFFER;

#define ACTIVE_BUFFER_INITIALIZED(ab) (ab.buf != NULL)
CWERROR active_buf_init(CW_ACTIVE_BUFFER *ab, 
						const CW_UINT32 size,
						AB_ON_FULL_FUNC on_full_func);

CWERROR active_buf_put(CW_ACTIVE_BUFFER *ab, 
					   const CW_UINT8 *data, 
					   const CW_UINT32 size,
					   void *param);
CWERROR active_buf_flush(CW_ACTIVE_BUFFER *ab, void *param);

void active_buf_final(CW_ACTIVE_BUFFER *ab);

#endif
