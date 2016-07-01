#include "general.h"
#include "errors.h"

#include "futils.h"

CWERROR write_file(const void *buf, const CW_UINT32 len, const char *fname) {
  register FILE *f = NULL;

  if ((f = fopen(fname, "wb")) == NULL) {
    DEBUG_ERROR();
    return CW_ER_OPEN_FILE;
  }

  if (fwrite(buf, len, 1, f) != 1) {
    fclose(f);
    DEBUG_ERROR();
    return CW_ER_WRITE_FILE;
  }
  fflush(f);
  fclose(f);

  return CW_ER_OK;
}

CWERROR read_file(void *buf, const CW_UINT32 len, const char *fname) {
  register FILE *f = NULL;

  if ((f = fopen(fname, "rb")) == NULL) {
    DEBUG_ERROR();
    return CW_ER_OPEN_FILE;
  }

  if (fread(buf, len, 1, f) != 1) {
    fclose(f);
    DEBUG_ERROR();
    return CW_ER_READ_FILE;
  }
  fclose(f);

  return CW_ER_OK;
}

char *get_fname(char *name, char *path) {
  register char *p;
  int len, n;

  len = strlen(path);
  if ((len == 0) || (len > MAX_PATH))
    return NULL;

  p = &path[len];

  while ((*--p != SLASH) && (p != path)); /* move k to last SLASH character */
  if (p == path)
    return NULL;
  ++p; /* k points to the 1st characyer of the name */


  n = len - (p - path);
  if (n <= 0)
    return NULL;

  memcpy(name, p, n * sizeof(char));
  name[n] = '\0';

  return name;
}

char *get_fpath(char *name, char *path) {
  register char *p;
  int len, n;

  len = strlen(path);
  if ((len == 0) || (len > MAX_PATH))
    return NULL;

  p = &path[len];

  while ((*--p != SLASH) && (p != path)); /* move k to last SLASH character */
  if (p == path)
    return NULL;
  ++p; /* k points to the 1st characyer of the name */


  n = p - path;
  if (n <= 0)
    return NULL;

  memcpy(name, path, n * sizeof(char));
  name[n] = '\0';

  return name;
}

CWERROR rm_file(const char *file) {
  if (unlink(file) != 0) {
    DEBUG_ERROR();
    return CW_ER_RM_FILE;
  }

  return CW_ER_OK;
}
