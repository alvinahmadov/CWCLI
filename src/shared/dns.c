#include "general.h"
#include "dns.h"

int resolve_ip(char *ip, const char *domain) {
  struct hostent *he;
  char *ip_str;

  if (inet_addr(domain) != INADDR_NONE) {
    strcpy(ip, domain);
    return 1;
  } else {
    if ((he = gethostbyname(domain)) == NULL) {
      return 0;
    }
    if (he->h_addr_list[0] == NULL) {
      return 0;
    }
    if ((ip_str = inet_ntoa(*(struct in_addr *) (he->h_addr_list[0]))) == NULL) {
      return 0;
    }
    strcpy(ip, ip_str);
    return 1;
  }
}
