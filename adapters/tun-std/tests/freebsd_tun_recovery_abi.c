/* Native description getter/setter and pointer-bearing buffer layout. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
  printf("%lu %lu %zu %zu %zu\n",
    (unsigned long)SIOCSIFDESCR, (unsigned long)SIOCGIFDESCR,
    sizeof(struct ifreq_buffer), offsetof(struct ifreq_buffer, length),
    offsetof(struct ifreq_buffer, buffer));
  return 0;
}
