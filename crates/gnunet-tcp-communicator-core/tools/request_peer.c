/* External public-API caller only; no replacement C state machine. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_TRANSPORT_ApplicationHandle *application;
static struct GNUNET_PeerIdentity target;
static const char *address;
static void stop(void *cls){(void)cls;GNUNET_TRANSPORT_application_done(application);application=NULL;GNUNET_SCHEDULER_shutdown();}
static void run(void *cls){(void)cls;application=GNUNET_TRANSPORT_application_init(cfg);GNUNET_assert(NULL!=application);GNUNET_TRANSPORT_application_validate(application,&target,GNUNET_NT_LOOPBACK,address);puts("actual-public-application-validate-called");fflush(stdout);GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,8),&stop,NULL);}
int main(int argc,char **argv){if(argc!=4||strlen(argv[2])!=64)return 2;for(size_t i=0;i<32;i++){unsigned int b;if(1!=sscanf(argv[2]+2*i,"%2x",&b))return 2;((unsigned char*)&target)[i]=(unsigned char)b;}address=argv[3];GNUNET_log_setup("tcp-public-request","DEBUG",NULL);cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(cfg,argv[1]))return 3;GNUNET_SCHEDULER_run(&run,NULL);GNUNET_CONFIGURATION_destroy(cfg);return NULL==application?0:4;}
