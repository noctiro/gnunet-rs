/* Actual public API caller; normal unchanged libgnunetutil, no source shim. */
#include "gnunet_util_lib.h"
#include <stdio.h>
int main(int argc,char **argv) {
  if(argc!=3)return 2;
  struct GNUNET_CONFIGURATION_Handle *cfg=
    GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());
  GNUNET_log_setup("client-presence-observer","ERROR",NULL);
  if(GNUNET_OK!=GNUNET_CONFIGURATION_parse(cfg,argv[1])) {
    GNUNET_CONFIGURATION_destroy(cfg);return 3;
  }
  printf("%d\n",(int)GNUNET_CLIENT_test(cfg,argv[2]));
  GNUNET_CONFIGURATION_destroy(cfg);return 0;
}
