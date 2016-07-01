#include "general.h"
#include "errors.h"

#include "usock.h"

int send_buf(SOCKET s, char *buf, int *len) {
  register int total = 0;
  register int bytesleft = *len;
  register int n;

  while (total < *len) {
    n = send(s, buf + total, bytesleft, 0);
    if (n == -1) {
      DEBUG_ERROR();
      break;
    }
    total += n;
    bytesleft -= n;
  }

  *len = total;

  return ((n == -1) ? -1 : 0);
}

int recv_buf(SOCKET s, char *buf, int *len, const long timeout) {
  fd_set fds;
  struct timeval tv;
  register int total = 0;
  register int bytesleft = *len;
  register int n;

  FD_ZERO(&fds);
  FD_SET(s, &fds);

  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  while (total < *len) {
    n = select((int) s + 1, &fds, NULL, NULL, &tv);
    if (n == 0) {
      n = -2;
      break;
    }
    if (n == -1) {
      DEBUG_ERROR();
      break;
    }
    if ((n = recv(s, buf + total, bytesleft, 0)) <= 0) {
      DEBUG_ERROR();
      break;
    }
    total += n;
    bytesleft -= n;
  }

  *len = total;

  return n;
}
