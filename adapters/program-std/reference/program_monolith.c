/* Real normal monolith with one registered service on an owned Unix listener.
 * No UID/GID option, network client, target process or foreign path is used. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
static const char *path;
static unsigned initialized,callbacks;
static int status;
static int live(void){struct stat st;return !lstat(path,&st)&&S_ISSOCK(st.st_mode);}
static void record(void *cls,enum GNUNET_ErrorType kind,const char*component,const char*date,const char*message){(void)cls;printf("R %d ",kind);for(const unsigned char*p=(const unsigned char*)component;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)date;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)message;*p;p++)printf("%02x",*p);putchar('\n');}
static void init(void *cls,const struct GNUNET_CONFIGURATION_Handle *cfg,struct GNUNET_SERVICE_Handle *sh){(void)cls;if(!cfg||!sh||!live()){status=7;GNUNET_SCHEDULER_shutdown();return;}initialized++;printf("SERVICE_INIT %u SOCKET %d\n",initialized,live());}
static void*connected(void*cls,struct GNUNET_SERVICE_Client*c,struct GNUNET_MQ_Handle*mq){(void)cls;(void)mq;status=8;return c;}
static void disconnected(void*cls,struct GNUNET_SERVICE_Client*c,void*internal){(void)cls;(void)c;(void)internal;status=8;}
static void newest(void *cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){if(cls||args||file||!cfg||!live())status=9;printf("TASK newest CFG %d SOCKET %d\n",cfg!=NULL,live());callbacks++;}
static void first(void *cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){if(cls||args||file||!cfg||!live())status=9;printf("TASK first CFG %d SOCKET %d\n",cfg!=NULL,live());callbacks++;GNUNET_SCHEDULER_shutdown();}
int main(int argc,char**argv){argv[0]="owned-monolith";path=getenv("OWNED_MONOLITH_PATH");if(!path)return 2;printf("PID %u\n",(unsigned)getpid());GNUNET_log_setup("owned-monolith","NONE",NULL);GNUNET_logger_add(&record,NULL);const struct GNUNET_OS_ProjectData *pd=GNUNET_OS_project_data_gnunet();struct GNUNET_CONFIGURATION_Handle *cfg=GNUNET_CONFIGURATION_create(pd);GNUNET_CONFIGURATION_set_value_string(cfg,"owned-service","UNIXPATH",path);GNUNET_CONFIGURATION_set_value_string(cfg,"owned-service","PORT","0");GNUNET_CONFIGURATION_set_value_string(cfg,"owned-service","BINDTO","127.0.0.1");struct GNUNET_MQ_MessageHandler handlers[]={GNUNET_MQ_handler_end()};if(GNUNET_SERVICE_register_(pd,"owned-service",GNUNET_SERVICE_OPTION_NONE,&init,&connected,&disconnected,NULL,handlers))return 3;printf("REGISTER %d\n",GNUNET_DAEMON_register("first","unused",&first));printf("REGISTER %d\n",GNUNET_DAEMON_register("newest","unused",&newest));GNUNET_PROGRAM_monolith_main(pd,argc,argv,cfg);GNUNET_RESOLVER_disconnect();if(!getenv("OWNED_OPTIONS_STOP"))GNUNET_CONFIGURATION_destroy(cfg);printf("DONE INIT %u TASKS %u SOCKET %d\n",initialized,callbacks,live());GNUNET_logger_remove(&record,NULL);return status;}
