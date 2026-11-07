/* Native ABI-only oracle; no GNUnet function extraction or production C bridge. */
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/proc_info.h>
int main(void) {
  printf("{\"options_offset\":%zu,\"socket_fdinfo_size\":%zu,\"flavor\":%d,\"acceptconn\":%d}\n",
         offsetof(struct socket_fdinfo, psi.soi_options),
         sizeof(struct socket_fdinfo), PROC_PIDFDSOCKETINFO, SO_ACCEPTCONN);
  return 0;
}
