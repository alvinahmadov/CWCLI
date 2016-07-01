#ifndef __DNS_H__
#define __DNS_H__

#define IS_DOMAIN(s) ((inet_addr((s)) == INADDR_NONE) ? 1 : 0)

int resolve_ip(char *ip, const char *domain);

#endif
