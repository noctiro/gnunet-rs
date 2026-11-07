/* Normal unmodified libgnunetarm caller, only an owned Unix scripted peer.
 * No ARM BINARY is configured; local start is exercised only confirmed-up.
 * All owner destruction is scheduled outside C callbacks. */
#include "gnunet_arm_service.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_Handle *owner;
static struct GNUNET_ARM_MonitorHandle *monitor;
static struct GNUNET_ARM_Operation *operation;
static int phase,failed,stopped,repeat_seen,monitor_count,finish_pending;
static const char *endpoint;
static struct GNUNET_SCHEDULER_Task *watchdog;
static void finish(void *cls);
static void maybe_finish(void) {
 if (!finish_pending && stopped && repeat_seen && monitor_count>=4) {
  finish_pending=1;GNUNET_SCHEDULER_add_now(&finish,NULL);
 }
}
static void check(int condition) {if(!condition)failed=1;}
static void clean(void) {
 if(operation){GNUNET_ARM_operation_cancel(operation);operation=NULL;}
 if(monitor){GNUNET_ARM_monitor_stop(monitor);monitor=NULL;}
 if(owner){GNUNET_ARM_disconnect(owner);owner=NULL;}
 if(cfg){GNUNET_CONFIGURATION_destroy(cfg);cfg=NULL;}
}
static void finish(void *cls) {
 (void)cls;if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}clean();printf("{\"event\":\"done\",\"failed\":%d,\"monitor_count\":%d,\"repeat\":%d,\"stopped\":%d}\n",failed,monitor_count,repeat_seen,stopped);fflush(stdout);GNUNET_SCHEDULER_shutdown();
}
static void timeout(void *cls) {(void)cls;watchdog=NULL;failed=1;printf("{\"event\":\"watchdog\"}\n");finish(NULL);}
static void unexpected(void *cls,enum GNUNET_ARM_RequestStatus rs,enum GNUNET_ARM_Result r) {(void)cls;(void)rs;(void)r;failed=1;printf("{\"event\":\"canceled_callback\"}\n");}
static void stop_arm(void *cls,enum GNUNET_ARM_RequestStatus rs,enum GNUNET_ARM_Result r) {
 (void)cls;operation=NULL;check(rs==GNUNET_ARM_REQUEST_SENT_OK&&r==GNUNET_ARM_RESULT_STOPPED);printf("{\"event\":\"stop_arm\",\"rs\":%u,\"result\":%u}\n",rs,r);stopped=1;phase=6;maybe_finish();
}
static void already(void *cls,enum GNUNET_ARM_RequestStatus rs,enum GNUNET_ARM_Result r) {
 (void)cls;operation=NULL;check(rs==GNUNET_ARM_REQUEST_SENT_OK&&r==GNUNET_ARM_RESULT_IS_STARTED_ALREADY);printf("{\"event\":\"local_arm_already\",\"rs\":%u,\"result\":%u}\n",rs,r);phase=5;operation=GNUNET_ARM_request_service_stop(owner,"arm",&stop_arm,NULL);check(operation!=NULL);
}
static void list(void *cls,enum GNUNET_ARM_RequestStatus rs,unsigned count,const struct GNUNET_ARM_ServiceInfo *rows) {
 (void)cls;operation=NULL;check(rs==GNUNET_ARM_REQUEST_SENT_OK&&count==1&&rows!=NULL);if(rows&&count){printf("{\"event\":\"list\",\"rs\":%u,\"count\":%u,\"name\":\"%s\",\"binary\":\"%s\",\"status\":%u,\"exit\":%d,\"restart\":%" PRIu64 ",\"last_start\":%" PRIu64 "}\n",rs,count,rows[0].name,rows[0].binary,rows[0].status,rows[0].last_exit_status,rows[0].restart_at.abs_value_us,rows[0].last_started_at.abs_value_us);}
 struct GNUNET_ARM_Operation *cancel=GNUNET_ARM_request_service_stop(owner,"cancel",&unexpected,NULL);check(cancel!=NULL);if(cancel)GNUNET_ARM_operation_cancel(cancel);printf("{\"event\":\"cancel_queued\"}\n");phase=4;operation=GNUNET_ARM_request_service_start(owner,"arm",GNUNET_OS_INHERIT_STD_OUT_AND_ERR,&already,NULL);check(operation!=NULL);
}
static void stop_service(void *cls,enum GNUNET_ARM_RequestStatus rs,enum GNUNET_ARM_Result r) {
 (void)cls;operation=NULL;check(rs==GNUNET_ARM_REQUEST_SENT_OK&&r==GNUNET_ARM_RESULT_STOPPED);printf("{\"event\":\"stop_service\",\"rs\":%u,\"result\":%u}\n",rs,r);phase=3;operation=GNUNET_ARM_request_service_list(owner,&list,NULL);check(operation!=NULL);
}
static void start_service(void *cls,enum GNUNET_ARM_RequestStatus rs,enum GNUNET_ARM_Result r) {
 (void)cls;operation=NULL;check(rs==GNUNET_ARM_REQUEST_SENT_OK&&r==GNUNET_ARM_RESULT_STARTING);printf("{\"event\":\"start_service\",\"rs\":%u,\"result\":%u}\n",rs,r);phase=2;operation=GNUNET_ARM_request_service_stop(owner,"svc",&stop_service,NULL);check(operation!=NULL);
}
static void status(void *cls,const char *service,enum GNUNET_ARM_ServiceMonitorStatus s) {
 (void)cls;if(!service){failed=1;printf("{\"event\":\"monitor_unavailable\"}\n");return;}monitor_count++;printf("{\"event\":\"monitor\",\"service\":\"%s\",\"status\":%u}\n",service,s);maybe_finish();
}
static void connection(void *cls,enum GNUNET_GenericReturnValue connected) {
 (void)cls;printf("{\"event\":\"connection\",\"connected\":%d}\n",connected);
 if(connected==GNUNET_SYSERR){failed=1;return;}
 if(connected==GNUNET_YES&&phase==0){phase=1;monitor=GNUNET_ARM_monitor_start(cfg,&status,NULL);check(monitor!=NULL);operation=GNUNET_ARM_request_service_start(owner,"svc",GNUNET_OS_INHERIT_STD_OUT_AND_ERR,&start_service,NULL);check(operation!=NULL);}
 else if(connected==GNUNET_YES){repeat_seen=1;maybe_finish();}
}
static void run(void *cls) {
 (void)cls;cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());GNUNET_CONFIGURATION_set_value_string(cfg,"arm","UNIXPATH",endpoint);
 /* A defensive executable guard: even an unexpected unconfirmed-up branch
    has no BINARY and therefore cannot create a managed process. */
 if(GNUNET_YES==GNUNET_CONFIGURATION_have_value(cfg,"arm","BINARY")){failed=1;finish(NULL);return;}
 owner=GNUNET_ARM_connect(cfg,&connection,NULL);check(owner!=NULL);watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,5),&timeout,NULL);
}
int main(int argc,char **argv) {if(argc!=2)return 90;endpoint=argv[1];setvbuf(stdout,NULL,_IOLBF,0);GNUNET_log_setup("arm-public-owner","WARNING",NULL);GNUNET_SCHEDULER_run(&run,NULL);clean();return failed?1:0;}
