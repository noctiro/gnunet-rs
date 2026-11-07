/* Actual public ARM + STATISTICS callers share normal libutil Resolver globals. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_arm_service.h"
#include "gnunet_statistics_service.h"
#include <dlfcn.h>
#include <mach-o/dyld.h>
static struct GNUNET_CONFIGURATION_Handle *configuration;
static struct GNUNET_ARM_Handle *arm;
static struct GNUNET_ARM_Operation *list_operation;
static struct GNUNET_STATISTICS_Handle *statistics;
static struct GNUNET_STATISTICS_GetHandle *get;
static struct GNUNET_SCHEDULER_Task *watchdog,*finish_task;
static int status,listed,got,started;
static void finish(void *cls){(void)cls;finish_task=NULL;if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}if(statistics){GNUNET_STATISTICS_destroy(statistics,GNUNET_NO);statistics=NULL;}if(arm){GNUNET_ARM_disconnect(arm);arm=NULL;}}
static void check_finish(void){if(listed&&got&&!finish_task)finish_task=GNUNET_SCHEDULER_add_now(&finish,NULL);}
static void expired(void *cls){(void)cls;watchdog=NULL;status=8;GNUNET_SCHEDULER_shutdown();}
static void list_callback(void *cls,enum GNUNET_ARM_RequestStatus result,unsigned count,const struct GNUNET_ARM_ServiceInfo *list){(void)cls;(void)list;list_operation=NULL;if(result!=GNUNET_ARM_REQUEST_SENT_OK||count!=0){status=6;GNUNET_SCHEDULER_shutdown();return;}listed=1;puts("ARM_LIST|0");fflush(stdout);check_finish();}
static int value_callback(void *cls,const char *subsystem,const char *name,uint64_t value,int persistent){(void)cls;(void)subsystem;(void)name;(void)value;(void)persistent;status=5;return GNUNET_NO;}
static void get_callback(void *cls,int success){(void)cls;get=NULL;if(success!=GNUNET_OK){status=7;GNUNET_SCHEDULER_shutdown();return;}got=1;puts("STATS_END|1");fflush(stdout);check_finish();}
static void connected(void *cls,enum GNUNET_GenericReturnValue up){(void)cls;if(up!=GNUNET_YES||started)return;started=1;puts("ARM_UP|1");fflush(stdout);list_operation=GNUNET_ARM_request_service_list(arm,&list_callback,NULL);statistics=GNUNET_STATISTICS_create("s",configuration);if(!statistics||!list_operation){status=3;GNUNET_SCHEDULER_shutdown();return;}get=GNUNET_STATISTICS_get(statistics,"s","n",&get_callback,&value_callback,NULL);if(!get){status=4;GNUNET_SCHEDULER_shutdown();}}
static void run(void *cls){(void)cls;watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,5),&expired,NULL);arm=GNUNET_ARM_connect(configuration,&connected,NULL);if(!arm){status=2;GNUNET_SCHEDULER_shutdown();}}
int main(int argc,char **argv){if(argc!=3)return 2;Dl_info info;if(!dladdr((void*)&GNUNET_RESOLVER_ip_get,&info))return 9;char loaded[PATH_MAX],expected[PATH_MAX];if(!realpath(info.dli_fname,loaded)||!realpath(argv[2],expected)||strcmp(loaded,expected))return 10;unsigned utils=0;for(uint32_t i=0;i<_dyld_image_count();i++){const char *path=_dyld_get_image_name(i);if(strstr(path,"/libgnunetutil.")){utils++;fprintf(stderr,"DYLD_UTIL|%s\n",path);}}if(utils!=1)return 11;fprintf(stderr,"BOUND_UTIL|%s\n",loaded);GNUNET_log_setup("public-shared-two-services","DEBUG",NULL);configuration=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(configuration,argv[1]))return 12;GNUNET_RESOLVER_connect(configuration);GNUNET_SCHEDULER_run(&run,NULL);if(get){GNUNET_STATISTICS_get_cancel(get);get=NULL;}if(list_operation){GNUNET_ARM_operation_cancel(list_operation);list_operation=NULL;}if(statistics){GNUNET_STATISTICS_destroy(statistics,GNUNET_NO);statistics=NULL;}if(arm){GNUNET_ARM_disconnect(arm);arm=NULL;}GNUNET_RESOLVER_disconnect();GNUNET_CONFIGURATION_destroy(configuration);return status;}
