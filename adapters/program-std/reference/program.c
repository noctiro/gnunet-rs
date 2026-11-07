/* Unmodified PROGRAM public API, only owned configurations and no DNS requests. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int calls;
static int scheduled;
static void hex(const char*s){if(!s){putchar('-');return;}for(const unsigned char*p=(const unsigned char*)s;*p;p++)printf("%02x",*p);}
static void task(void*cls,char*const*args,const char*file,const struct GNUNET_CONFIGURATION_Handle*cfg){(void)cls;calls++;printf("TASK %d OFFSET %lld FILE ",calls,GNUNET_TIME_get_offset());hex(file);printf(" ARMCONFIG ");char*v=NULL;if(GNUNET_OK==GNUNET_CONFIGURATION_get_value_string(cfg,"arm","CONFIG",&v)){hex(v);GNUNET_free(v);}else putchar('-');printf(" ARGS");if(args)for(unsigned i=0;args[i];i++){putchar(' ');hex(args[i]);}putchar('\n');if(scheduled&&getenv("OWNED_SHUTDOWN"))GNUNET_SCHEDULER_shutdown();}
int main(int argc,char**argv){struct GNUNET_GETOPT_CommandLineOption options[]={GNUNET_GETOPT_OPTION_END};int repeat=getenv("OWNED_REPEAT")?2:1;scheduled=getenv("OWNED_DIRECT")==NULL;for(int i=0;i<repeat;i++){int result=GNUNET_PROGRAM_run2(GNUNET_OS_project_data_gnunet(),argc,argv,"owned summary","Owned PROGRAM oracle",options,task,NULL,scheduled?GNUNET_NO:GNUNET_YES);printf("RETURN %d CALLS %d OFFSET %lld\n",result,calls,GNUNET_TIME_get_offset());}return 0;}
