/* Actual unchanged official public ARM API caller. Only the supplied owned
 * daemon endpoints/services are used; no local ARM BINARY can be spawned. */
#include "gnunet_arm_service.h"
#include <stdio.h>
#include <unistd.h>
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_Handle *arm;
static struct GNUNET_ARM_MonitorHandle *monitor;
static struct GNUNET_ARM_Operation *op;
static struct GNUNET_SCHEDULER_Task *watchdog;
static const char *config_file,*child_ready;
static struct GNUNET_SCHEDULER_Task *ready_task;
static int initial_list,initial_monitor;
static void maybe_start(void);
static int phase,failed,monitors,finishing;
static void finish(void *cls){(void)cls;if(ready_task){GNUNET_SCHEDULER_cancel(ready_task);ready_task=NULL;}if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}if(op){GNUNET_ARM_operation_cancel(op);op=NULL;}if(monitor){GNUNET_ARM_monitor_stop(monitor);monitor=NULL;}if(arm){GNUNET_ARM_disconnect(arm);arm=NULL;}if(cfg){GNUNET_CONFIGURATION_destroy(cfg);cfg=NULL;}printf("{\"event\":\"done\",\"failed\":%d,\"monitors\":%d}\n",failed,monitors);GNUNET_SCHEDULER_shutdown();}
static void complete(void){if(!finishing){finishing=1;GNUNET_SCHEDULER_add_now(&finish,NULL);}}
static void timeout(void *cls){(void)cls;watchdog=NULL;failed=1;puts("{\"event\":\"watchdog\"}");complete();}
static void canceled(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){(void)cls;(void)status;(void)result;failed=1;puts("{\"event\":\"canceled-callback\"}");}
static void stopped_arm(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){(void)cls;op=NULL;if(status==GNUNET_ARM_REQUEST_SENT_OK){if(result!=GNUNET_ARM_RESULT_STOPPED)failed=1;printf("{\"event\":\"stop-arm\",\"status\":%u,\"result\":%u}\n",status,result);}else{if(status!=GNUNET_ARM_REQUEST_DISCONNECTED)failed=1;printf("{\"event\":\"stop-arm\",\"status\":%u,\"result\":null}\n",status);}complete();}
static void listing(void *cls,enum GNUNET_ARM_RequestStatus status,unsigned count,const struct GNUNET_ARM_ServiceInfo *rows){(void)cls;op=NULL;if(status!=GNUNET_ARM_REQUEST_SENT_OK||count!=3||!rows){failed=1;complete();return;}printf("{\"event\":\"list\",\"phase\":%d,\"count\":%u}\n",phase,count);int found=0;for(unsigned i=0;i<count;i++){printf("{\"event\":\"row\",\"phase\":%d,\"name\":\"%s\",\"status\":%u,\"exit\":%d}\n",phase,rows[i].name,rows[i].status,rows[i].last_exit_status);if(!strcmp(rows[i].name,"running")){found=1;if(phase==3&&(rows[i].status!=GNUNET_ARM_SERVICE_STATUS_FAILED||rows[i].last_exit_status!=15))failed=1;}}if(!found)failed=1;if(phase==0){struct GNUNET_ARM_Operation *cancel=GNUNET_ARM_request_service_stop(arm,"missing",&canceled,NULL);if(!cancel)failed=1;else GNUNET_ARM_operation_cancel(cancel);initial_list=1;maybe_start();}else{phase=4;op=GNUNET_ARM_request_service_stop(arm,"ARM",&stopped_arm,NULL);}if(phase!=0&&!op){failed=1;complete();}}
static void stopped(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){(void)cls;op=NULL;if(status!=GNUNET_ARM_REQUEST_SENT_OK||result!=GNUNET_ARM_RESULT_STOPPED)failed=1;printf("{\"event\":\"stop\",\"status\":%u,\"result\":%u}\n",status,result);phase=3;op=GNUNET_ARM_request_service_list(arm,&listing,NULL);if(!op){failed=1;complete();}}
static void wait_child(void *cls){(void)cls;ready_task=NULL;if(0!=access(child_ready,F_OK)){ready_task=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MILLISECONDS,&wait_child,NULL);return;}op=GNUNET_ARM_request_service_stop(arm,"RuNnInG",&stopped,NULL);if(!op){failed=1;complete();}}
static void started(void *cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){(void)cls;op=NULL;if(status!=GNUNET_ARM_REQUEST_SENT_OK||result!=GNUNET_ARM_RESULT_STARTING)failed=1;printf("{\"event\":\"start\",\"status\":%u,\"result\":%u}\n",status,result);phase=2;ready_task=GNUNET_SCHEDULER_add_now(&wait_child,NULL);}
static void maybe_start(void){if(phase==0&&initial_list&&initial_monitor){phase=1;op=GNUNET_ARM_request_service_start(arm,"RuNnInG",GNUNET_OS_INHERIT_STD_OUT_AND_ERR,&started,NULL);if(!op){failed=1;complete();}}}
static void status(void *cls,const char *name,enum GNUNET_ARM_ServiceMonitorStatus value){(void)cls;if(!name){if(phase<4)failed=1;return;}monitors++;if(value==GNUNET_ARM_SERVICE_MONITORING_STARTED){initial_monitor=1;maybe_start();}printf("{\"event\":\"monitor\",\"name\":\"%s\",\"status\":%u}\n",name,value);}
static void connected(void *cls,enum GNUNET_GenericReturnValue value){(void)cls;if(value==GNUNET_SYSERR){failed=1;complete();return;}if(value==GNUNET_YES&&phase==0&&!op){monitor=GNUNET_ARM_monitor_start(cfg,&status,NULL);if(!monitor)failed=1;op=GNUNET_ARM_request_service_list(arm,&listing,NULL);if(!op){failed=1;complete();}}}
static void run(void *cls){(void)cls;cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_parse(cfg,config_file)){failed=1;complete();return;}if(GNUNET_YES==GNUNET_CONFIGURATION_have_value(cfg,"arm","BINARY")){failed=1;complete();return;}arm=GNUNET_ARM_connect(cfg,&connected,NULL);if(!arm){failed=1;complete();return;}watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,8),&timeout,NULL);}
int main(int argc,char **argv){if(argc!=3)return 90;config_file=argv[1];child_ready=argv[2];setvbuf(stdout,NULL,_IOLBF,0);GNUNET_log_setup("arm-reactor-public","WARNING",NULL);GNUNET_SCHEDULER_run(&run,NULL);return failed?1:0;}
