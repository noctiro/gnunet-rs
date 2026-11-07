/* Independent layout check against FreeBSD's installed public headers. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
  printf("%zu %zu %zu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", sizeof(struct ifreq),
         sizeof(struct in6_aliasreq), offsetof(struct in6_aliasreq, ifra_lifetime),
         (unsigned long)TUNGIFNAME, (unsigned long)TUNSIFHEAD,
         (unsigned long)TUNGIFHEAD, (unsigned long)SIOCAIFADDR_IN6,
         (unsigned long)SIOCGIFMTU, (unsigned long)SIOCGIFFLAGS,
         (unsigned long)SIOCGIFNETMASK, (unsigned long)SIOCSIFMTU,
         (unsigned long)SIOCSIFFLAGS, (unsigned long)SIOCSIFADDR,
         (unsigned long)SIOCSIFNETMASK);
  return 0;
}
