#ifndef _LOG_H_
#define _LOG_H_

CWERROR log_open(const char *fname);

void log_write(char *fmt, ...);

void log_close(void);

#endif
