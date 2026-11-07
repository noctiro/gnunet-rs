/* Normal public DAEMON/PROGRAM helpers; no service/account/process is started. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct GNUNET_CONFIGURATION_Handle *configuration;
static unsigned first_count,new_count,late_count,total;
static int callback_register;
static int status;
static void row(const char*name,unsigned count,void*cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){if(cls||args||file){status=9;return;}printf("TASK %s %u CFG %d VALUE ",name,count,cfg!=NULL);char*value=NULL;if(cfg&&GNUNET_OK==GNUNET_CONFIGURATION_get_value_string(cfg,"owned","value",&value)){for(const unsigned char*p=(const unsigned char*)value;*p;p++)printf("%02x",*p);GNUNET_free(value);}else putchar('-');puts("");total++;}
static void late(void*cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){row("late",++late_count,cls,args,file,cfg);}
static void first(void*cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){row("first",++first_count,cls,args,file,cfg);}
static void newest(void*cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){row("newest",++new_count,cls,args,file,cfg);if(callback_register&&new_count==1&&GNUNET_OK!=GNUNET_DAEMON_register("late","unused",&late))status=8;}
static void log_record(void*cls,enum GNUNET_ErrorType kind,const char*component,const char*date,const char*message){(void)cls;printf("R %d ",kind);for(const unsigned char*p=(const unsigned char*)component;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)date;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)message;*p;p++)printf("%02x",*p);putchar('\n');}
static void bare(void*cls){(void)cls;GNUNET_DAEMON_main(GNUNET_OS_project_data_gnunet(),0,NULL,configuration,GNUNET_NO);}
int main(int argc,char**argv){const char *mode=getenv("OWNED_DAEMON_MODE");if(!mode)return 2;int is_bare=!strcmp(mode,"bare");int is_null=!strcmp(mode,"null");int is_repeat=!strcmp(mode,"repeat");callback_register=is_repeat;printf("PID %u\n",(unsigned)getpid());GNUNET_log_setup("owned-daemon",is_bare?"DEBUG":"NONE",NULL);GNUNET_logger_add(&log_record,NULL);if(!is_null){configuration=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());GNUNET_CONFIGURATION_set_value_string(configuration,"owned","value","provided%value");}printf("REGISTER %d\n",GNUNET_DAEMON_register("first","unused",&first));printf("REGISTER %d\n",GNUNET_DAEMON_register("newest","unused",&newest));for(unsigned i=0;i<(is_repeat?2U:1U);i++){if(is_bare)GNUNET_SCHEDULER_run(&bare,NULL);else GNUNET_DAEMON_main(GNUNET_OS_project_data_gnunet(),argc,argv,configuration,GNUNET_YES);printf("RUN %u TASKS %u\n",i,total);}if(!getenv("OWNED_OPTIONS_STOP")&&configuration)GNUNET_CONFIGURATION_destroy(configuration);GNUNET_logger_remove(&log_record,NULL);return status;}
