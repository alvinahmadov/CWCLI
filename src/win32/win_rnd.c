#include "general.h"
#include "errors.h"
#include "secmem.h"
#include "crypto.h"

#include "win_rnd.h"

CW_BOOL win32_get_random_pool(CW_UINT8 *buf) {
  SHA512_CTX sha512;
  HANDLE hHandle = INVALID_HANDLE_VALUE;
  PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};
  THREADENTRY32 te = {sizeof(THREADENTRY32)};
  HEAPLIST32 hl = {sizeof(HEAPLIST32)};
  HEAPENTRY32 he = {sizeof(HEAPENTRY32)};
  MEMORYSTATUS ms = {sizeof(MEMORYSTATUS)};
  POINT point;
  SYSTEMTIME dt;
  CW_UINT32 dw[3];
  FILETIME pt[8];
  LARGE_INTEGER pc[2];
  CW_UINT8 *netstat = NULL;
  CW_BOOL res = FALSE;


  sha512_init(&sha512);

  if (NetStatisticsGet(NULL, L"LanmanWorkstation", 0, 0, &netstat) == NERR_Success) {
    sha512_update(&sha512, netstat, sizeof(STAT_WORKSTATION_0));
    NetApiBufferFree(netstat);
  }
  if (NetStatisticsGet(NULL, L"LanmanServer", 0, 0, &netstat) == NERR_Success) {
    sha512_update(&sha512, netstat, sizeof(STAT_SERVER_0));
    NetApiBufferFree(netstat);
  }

  GetSystemTime(&dt);
  sha512_update(&sha512, &dt, sizeof(dt));

  sha512_final(&sha512, buf);
  buf += SHA512_DIGEST_LEN;


  sha512_init(&sha512);

  if ((hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == INVALID_HANDLE_VALUE) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if (!Thread32First(hHandle, &te)) {
    DEBUG_ERROR();
    goto err_exit;
  }
  do {
    sha512_update(&sha512, &te, sizeof(te));
  }while (Thread32Next(hHandle, &te));
  CloseHandle(hHandle);

  if ((hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if (!Process32First(hHandle, &pe)) {
    DEBUG_ERROR();
    goto err_exit;
  }
  do {
    sha512_update(&sha512, &pe, sizeof(pe));
  }while (Process32Next(hHandle, &pe));
  CloseHandle(hHandle);

  sha512_final(&sha512, buf);
  buf += SHA512_DIGEST_LEN;

  sha512_init(&sha512);

  if ((hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, 0)) == INVALID_HANDLE_VALUE) {
    DEBUG_ERROR();
    goto err_exit;
  }
  if (!Heap32ListFirst(hHandle, &hl)) {
    DEBUG_ERROR();
    goto err_exit;
  }
  do {
    sha512_update(&sha512, &hl, sizeof(hl));
    if (!Heap32First(&he, hl.th32ProcessID, hl.th32HeapID)) {
      DEBUG_ERROR();
      goto err_exit;
    }
    do {
      sha512_update(&sha512, &he, sizeof(he));
    }while (Heap32Next(&he));
  }while (Heap32ListNext(hHandle, &hl));
  CloseHandle(hHandle);

  sha512_final(&sha512, buf);
  buf += SHA512_DIGEST_LEN;

  sha512_init(&sha512);

  GetCursorPos(&point);
  sha512_update(&sha512, &point, sizeof(point));

  GlobalMemoryStatus(&ms);
  sha512_update(&sha512, &ms, sizeof(ms));

  dw[0] = GetQueueStatus(QS_ALLEVENTS);
  dw[1] = GetMessageTime();
  dw[2] = GetTickCount();
  sha512_update(&sha512, dw, sizeof(dw));

  GetProcessTimes(GetCurrentProcess(), &pt[0], &pt[1], &pt[2], &pt[3]);
  GetThreadTimes(GetCurrentThread(), &pt[4], &pt[5], &pt[6], &pt[7]);
  sha512_update(&sha512, pt, sizeof(pt));

  QueryPerformanceCounter(&pc[0]);
  QueryPerformanceFrequency(&pc[1]);
  sha512_update(&sha512, pc, sizeof(pc));

  sha512_final(&sha512, buf);

  res = TRUE;

  err_exit:

  if (res == FALSE) {
    if (hHandle != INVALID_HANDLE_VALUE) {
      CloseHandle(hHandle);
    }
  }
  return res;
}
