#ifndef _FUTILS_H_
#define _FUTILS_H_

CWERROR write_file(const void *buf, const CW_UINT32 len, const char *fname);

CWERROR read_file(void *buf, const CW_UINT32 len, const char *fname);

char *get_fname(char *name, char *path);

char *get_fpath(char *res, char *path);

CWERROR rm_file(const char *file);

#endif
