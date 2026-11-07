/* Public GNUnet Resolver config selection with both original cfg owners alive. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
static struct GNUNET_CONFIGURATION_Handle *a,*b;
static struct GNUNET_RESOLVER_RequestHandle *requests[4];
static struct GNUNET_SCHEDULER_Task *watchdog;
static const char *live_path;
static int status;
static void address(void *,const struct sockaddr *,socklen_t);
static struct GNUNET_RESOLVER_RequestHandle *query(unsigned id,const char *name){return GNUNET_RESOLVER_ip_get(name,AF_UNSPEC,GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,3),&address,(void *)(uintptr_t)id);}
static void expired(void *cls){(void)cls;watchdog=NULL;status=8;GNUNET_SCHEDULER_shutdown();}
static void third(void *cls){(void)cls;puts("THIRD");fflush(stdout);requests[3]=query(3,"third");}
static void address(void *cls,const struct sockaddr *sa,socklen_t len){(void)len;unsigned id=(unsigned)(uintptr_t)cls;if(sa){status=6;return;}requests[id]=NULL;printf("END|%u\n",id);fflush(stdout);if(id==2)GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,20),&third,NULL);if(id==3&&watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}}
static void mutate(void *cls){(void)cls;GNUNET_CONFIGURATION_set_value_string(a,"resolver","UNIXPATH",live_path);puts("MUTATE");fflush(stdout);requests[2]=query(2,"second");}
static void select_new(void *cls){(void)cls;GNUNET_RESOLVER_connect(b);fprintf(stderr,"BROKER_SELECT\n");puts("SELECT");fflush(stdout);GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,20),&mutate,NULL);}
static void run(void *cls){(void)cls;watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,6),&expired,NULL);requests[1]=query(1,"first");GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,20),&select_new,NULL);}
int main(int argc,char **argv){if(argc!=4)return 2;live_path=argv[3];GNUNET_log_setup("resolver-selected-cfg","DEBUG",NULL);a=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());b=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(a,argv[1])||GNUNET_OK!=GNUNET_CONFIGURATION_load(b,argv[2]))return 3;GNUNET_RESOLVER_connect(a);GNUNET_SCHEDULER_run(&run,NULL);for(unsigned i=1;i<4;i++)if(requests[i])GNUNET_RESOLVER_request_cancel(requests[i]);GNUNET_RESOLVER_disconnect();GNUNET_CONFIGURATION_destroy(a);GNUNET_CONFIGURATION_destroy(b);return status;}
