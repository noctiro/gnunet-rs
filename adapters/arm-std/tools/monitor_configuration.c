/* Normal unchanged GNUNET_ARM monitor configuration read-site observation.
 * Only this new caller's owned configuration and private Unix endpoint change. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_MonitorHandle *monitor;
static struct GNUNET_SCHEDULER_Task *watchdog,*settle;
static unsigned statuses,unavailable;static int failed;
static void finish(void*cls){(void)cls;settle=NULL;if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}if(monitor){GNUNET_ARM_monitor_stop(monitor);monitor=NULL;}GNUNET_SCHEDULER_shutdown();}
static void late(void*cls){(void)cls;watchdog=NULL;failed=1;finish(NULL);}
static void status(void*cls,const char*service,enum GNUNET_ARM_ServiceMonitorStatus value){(void)cls;
 if(service){statuses++;printf("{\"event\":\"status\",\"status\":%u,\"service\":\"%s\"}\n",value,service);GNUNET_CONFIGURATION_set_value_string(cfg,"arm","UNIXPATH",NULL);printf("{\"event\":\"configuration-removed\"}\n");}
 else{unavailable++;printf("{\"event\":\"unavailable\",\"status\":%u}\n",value);if(!settle)settle=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,40),&finish,NULL);}}
static void run(void*cls){(void)cls;watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,3),&late,NULL);monitor=GNUNET_ARM_monitor_start(cfg,&status,NULL);if(!monitor){failed=1;finish(NULL);}}
int main(int argc,char**argv){if(argc!=2)return 90;setvbuf(stdout,NULL,_IOLBF,0);GNUNET_log_setup("owned-arm-monitor-config","ERROR",NULL);cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());GNUNET_CONFIGURATION_set_value_string(cfg,"arm","UNIXPATH",argv[1]);GNUNET_SCHEDULER_run(&run,NULL);GNUNET_CONFIGURATION_destroy(cfg);printf("{\"event\":\"done\",\"statuses\":%u,\"unavailable\":%u,\"failed\":%d}\n",statuses,unavailable,failed);return failed||statuses!=1||unavailable!=1;}
