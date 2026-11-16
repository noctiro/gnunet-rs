/* Native clone/rename ABI and the transient request encoding on both releases. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <stddef.h>
#include <stdio.h>

/* FreeBSD 14 does not implement these requests. Check their native ioctl
 * encoding there; runtime capability detection must still observe ENOTTY. */
#ifndef TUNSTRANSIENT
#define TUNSTRANSIENT _IOW('t', 98, int)
#define TUNGTRANSIENT _IOR('t', 99, int)
#endif
int main(void) {
  printf("%lu %lu %lu %lu %lu %zu %lu %lu\n",
    (unsigned long)SIOCIFCREATE, (unsigned long)SIOCIFDESTROY,
    (unsigned long)SIOCSIFNAME, (unsigned long)TUNSTRANSIENT,
    (unsigned long)TUNGTRANSIENT, offsetof(struct ifreq, ifr_ifru),
    (unsigned long)SIOCGIFFIB, (unsigned long)SIOCSIFFIB);
  return 0;
}
