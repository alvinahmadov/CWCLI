#ifndef _DEBUG_H_
#define _DEBUG_H_
#ifdef __DEBUG__
#ifdef __CONSOLE_DEBUG__
#define DEBUG_ERROR() fprintf(stderr, "ERROR: %s line %d\n", __FILE__, __LINE__)
#endif

#ifdef __DLL_DEBUG__
#define DEBUG_ERROR() { \
            log_write("%s %s %s %d\n", "ERROR:", __FILE__, "line", __LINE__); \
        }
#endif

#ifdef __SERVICE_DEBUG__
#define DEBUG_ERROR() { \
            log_write("%s %s %s %d\n", "ERROR:", __FILE__, "line", __LINE__); \
        }
#endif
#else
#define DEBUG_ERROR()
#endif
#endif
