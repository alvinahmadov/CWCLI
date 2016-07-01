#ifndef _GENERAL_H_
#define _GENERAL_H_
#define CURRENT_VERSION            0x01    /* current project version */

#pragma pack(8)

typedef int CW_BOOL;
typedef unsigned char CW_UINT8;
typedef unsigned short CW_UINT16;
typedef unsigned long CW_UINT32;
typedef long long CW_INT64;
typedef unsigned long long CW_UINT64;

#define    MAX_UINT32_LEN            (sizeof("4294967295") - 1)
#define    MAX_INT64_LEN            (sizeof("9223372036854775807") - 1)
#define MAX_UINT64_LEN            (sizeof("18446744073709551615") - 1)
#define MAX_TIMESTAMP_LEN        (sizeof("00:00:00 01/01/2007") - 1)

#define max3(x, y, z)           max((max((x), (y))), (z))
#define EMPTY_STRING(x)         ((x)[0] == '\0')
#define MAKE_EMPTY_STRING(x)    ((x)[0] = '\0')


#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif


#define MALLOC(x)                malloc((x))
#define FREE(x)                    {free((x)); (x) = NULL;}

#define WRONG_ID                    0


/* ------------------- Microsoft Windows ------------------- */
#if defined(_WIN32) || defined(WIN32)

#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <direct.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <tlhelp32.h>
#include <lm.h>

#include "win_svc.h"
#include "win_rnd.h"

#define DLL_MALLOC(x)               VirtualAlloc(NULL, (x), MEM_COMMIT, PAGE_READWRITE)
#define DLL_FREE(x)                 {VirtualFree((x), 0, MEM_RELEASE); (x) = NULL;}

#define DLLEXPORT					__declspec(dllexport)
#define	DLLCALL						__stdcall

#define EXIT(r)						win32_service_stop()

#define	SD_BOTH	                    0x02

#define LAN_IP(ip)					(((ip).S_un.S_addr == 0x0100007FUL) || \
                                     ((ip).S_un.S_addr << 16 == 0xA8C00000UL) || \
                                     ((ip).S_un.S_addr << 16 == 0x10AC0000UL) || \
                                     ((ip).S_un.S_addr << 24 == 0x0A000000UL))

#define sock_init(dt)	\
    if (WSAStartup(MAKEWORD(1, 1), &(dt)) != 0) { \
        DEBUG_ERROR(); \
        err = CW_ER_SOCKET; \
        goto err_exit; \
    }
#define sock_final()				WSACleanup()

#define platform_get_rndbuf(buf)    win32_get_random_pool((buf))

#define mlock(p, n)					VirtualLock((p), (n))
#define munlock(p, n)               VirtualUnlock((p), (n))
#define delay(x)					Sleep((x))
#define mkdir(x)					_mkdir((x))
#define chdir(x)					_chdir((x))
#define ultoa(v, s, r)				_ultoa((v), (s), (r))

/* pthread */
#define	THREAD_RET					0
#define PTHREAD_INITIALIZER			0
#define THREAD_PROC(x)				unsigned __stdcall x(void *param) 
#define pthread_t					uintptr_t
#define pthread_mutex_t				CRITICAL_SECTION
#define pthread_mutex_init(x, y)	InitializeCriticalSection((x))
#define MUTEX_TRY_LOCK(x)			((TryEnterCriticalSection((x))) ? TRUE : FALSE)
#define pthread_mutex_lock(x)		EnterCriticalSection((x))
#define pthread_mutex_unlock(x)		LeaveCriticalSection((x))
#define pthread_mutex_destroy(x)	DeleteCriticalSection((x))

#define THREAD_SUCCESS(x)			((x) != 0)
#define CREATE_THREAD(x, y, z)		((x) = _beginthreadex(NULL, 0, (y), (z), 0, NULL))
#define pthread_cancel(x)			{TerminateThread((HANDLE)(x), 0); CloseHandle((HANDLE)(x));}
#define pthread_exit(x)				_endthreadex((x))
#define pthread_detach(x)
#define	pthread_setcanceltype(x, y)
#define MUTEX_INIT(x)

#define SLASH						'\\'

/* ------------------- Unix ------------------- */
#else

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h> 
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_PATH                1023

#define EXIT(r)                    exit((r))

#define DLL_MALLOC(x)           MALLOC((x))
#define DLL_FREE(x)             FREE((x))

#define LAN_IP(ip)                    (((ip).s_addr == 0x0100007FUL) || \
                                     ((ip).s_addr << 16 == 0xA8C00000UL) || \
                                     ((ip).s_addr << 16 == 0x10AC0000UL) || \
                                     ((ip).s_addr << 24 == 0x0A000000UL))

#define INVALID_SOCKET            (-1)
#define SOCKET_ERROR            (-1)
#define    SD_BOTH                    SHUT_RDWR

typedef int WSADATA;
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct in_addr IN_ADDR;
typedef struct sockaddr SOCKADDR;

#define delay(x)                usleep(x)
#define closesocket(s)            close(s)
#define sock_init(wsadt)
#define sock_final()

#define    THREAD_RET                NULL
#define THREAD_SUCCESS(x)        ((x) == 0)
#define MUTEX_TRY_LOCK(x)        ((pthread_mutex_trylock((x)) != EBUSY) ? TRUE : FALSE)
#define CREATE_THREAD(x, y, z)    pthread_create(&(x), NULL, (y), (z))
#define THREAD_PROC(x)            void * x(void *param)
#define MUTEX_INIT(x)           (x) = PTHREAD_MUTEX_INITIALIZER

#define SLASH                    '//'

#endif

#include "debug.h"

#endif
