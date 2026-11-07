/* Read-only IPv6 query layouts, independently compiled from installed headers. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
  struct in6_ifreq req;
  printf("%zu %zu %zu %zu %lu %lu %u %u %u\n",
         sizeof(req), _Alignof(struct in6_ifreq),
         offsetof(struct in6_ifreq, ifr_ifru), sizeof(req.ifr_ifru),
         (unsigned long)SIOCGIFNETMASK_IN6, (unsigned long)SIOCGIFAFLAG_IN6,
         (unsigned)IN6_IFF_TENTATIVE, (unsigned)IN6_IFF_DUPLICATED,
         (unsigned)IN6_IFF_DETACHED);
  return 0;
}
