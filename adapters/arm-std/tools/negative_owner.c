/* Only defined public ARM API calls. The peer is an owned Unix literal fixture.
 * No BINARY, local ARM start, stop-waiter, stale pointer or canceled NULL callback.
 * Handle destruction is scheduled after the MQ callback returns. */
#include "gnunet_arm_service.h"
#include "arm.h"
#include <stdio.h>
#include <string.h>
_Static_assert(sizeof(struct GNUNET_ARM_Message)==16,"profile arm prefix");
_Static_assert(sizeof(struct GNUNET_ARM_ListResultMessage)==24,"profile list prefix");
_Static_assert(sizeof(struct GNUNET_ARM_ServiceInfoMessage)==28,"profile row width");
static const char *endpoint,*profile;
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_Handle *owner;
static struct GNUNET_SCHEDULER_Task *watchdog,*ending;
static unsigned bad_callbacks,keep_callbacks,started;
static int failed;
static void finish(void *cls) {
 (void)cls;ending=NULL;
 if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}
 if(owner){GNUNET_ARM_disconnect(owner);owner=NULL;}
 printf("{\"event\":\"done\",\"bad\":%u,\"keep\":%u,\"failed\":%d}\n",bad_callbacks,keep_callbacks,failed);
 GNUNET_SCHEDULER_shutdown();
}
static void timeout(void *cls){(void)cls;watchdog=NULL;failed=1;printf("{\"event\":\"watchdog\"}\n");finish(NULL);}
static void bad_list(void *cls,enum GNUNET_ARM_RequestStatus status,unsigned count,const struct GNUNET_ARM_ServiceInfo *rows){
 (void)cls;(void)rows;bad_callbacks++;printf("{\"event\":\"bad-list\",\"status\":%u,\"count\":%u}\n",status,count);
}
static void bad_result(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){
 (void)cls;bad_callbacks++;printf("{\"event\":\"bad-result\",\"status\":%u,\"result\":%u}\n",status,result);
}
static void keep_result(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){
 (void)cls;keep_callbacks++;printf("{\"event\":\"keep\",\"status\":%u,\"result\":%u}\n",status,result);
 if(ending==NULL)ending=GNUNET_SCHEDULER_add_now(&finish,NULL);
}
static void connection(void *cls,enum GNUNET_GenericReturnValue connected){
 (void)cls;printf("{\"event\":\"connection\",\"status\":%d}\n",connected);
 if(connected==GNUNET_SYSERR){failed=1;return;}
 if(connected!=GNUNET_YES || started)return;started=1;
 if(0==strcmp(profile,"wrong-result-list")){
  if(NULL==GNUNET_ARM_request_service_start(owner,"wrong",GNUNET_OS_INHERIT_STD_NONE,&bad_result,NULL))failed=1;
 } else if(NULL==GNUNET_ARM_request_service_list(owner,&bad_list,NULL))failed=1;
 if(NULL==GNUNET_ARM_request_service_stop(owner,"keep",&keep_result,NULL))failed=1;
}
static void run(void *cls){
 (void)cls;cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());GNUNET_CONFIGURATION_set_value_string(cfg,"arm","UNIXPATH",endpoint);
 if(GNUNET_YES==GNUNET_CONFIGURATION_have_value(cfg,"arm","BINARY")){failed=1;finish(NULL);return;}
 owner=GNUNET_ARM_connect(cfg,&connection,NULL);
 if(owner==NULL){failed=1;finish(NULL);return;}
 watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,5),&timeout,NULL);
}
int main(int argc,char **argv){
 if(argc!=3)return 90;endpoint=argv[1];profile=argv[2];setvbuf(stdout,NULL,_IOLBF,0);GNUNET_log_setup("arm-negative-actor","WARNING",NULL);GNUNET_SCHEDULER_run(&run,NULL);
 if(owner)GNUNET_ARM_disconnect(owner);if(cfg)GNUNET_CONFIGURATION_destroy(cfg);return failed?1:0;
}
