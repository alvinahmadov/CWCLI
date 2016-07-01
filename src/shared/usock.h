#ifndef _USOCK_H_
#define _USOCK_H_

#define SOCK_ER_SEND            (-1)

#define SOCK_ER_RECV_DISCONN    0
#define SOCK_ER_RECV            (-1)
#define SOCK_ER_RECV_TIMEOUT    (-2)


int send_buf(SOCKET s, char *buf, int *len);

int recv_buf(SOCKET s, char *buf, int *len, const long timeout);

#endif
