#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "dns.h"
#include "log.h"
#include "crypto.h"
#include "cert_struct.h"
#include "cert_chk.h"
#include "usock.h"
#include "futils.h"
#include "utils.h"
#include "key_rw.h"
#include "cfg_read.h"
#include "packets_struct.h"
#include "packets.h"
#include "sqlite3.h"
#include "db.h"
#include "query.h"
#include "shared_list.h"
#include "active_buf.h"

#include "cwcli.h"

CW_CLIENT *cli = NULL;

CW_BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
        if ((cli = malloc(sizeof(CW_CLIENT))) == NULL) {
            return FALSE;
        }
		break;
	case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
	case DLL_PROCESS_DETACH:
        free(cli);
		break;
	default:
		break;
	}

    return TRUE;
}
