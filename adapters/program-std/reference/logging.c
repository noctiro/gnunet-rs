/* Normal, unchanged public libgnunetutil caller. Inputs are data, never formats. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void hex(const char*s){for(const unsigned char*p=(const unsigned char*)s;*p;p++)printf("%02x",*p);}
static void logger(void*cls,enum GNUNET_ErrorType kind,const char*comp,const char*date,const char*message){printf("R %d %d ",*(int*)cls,kind);hex(comp);putchar(' ');hex(date);putchar(' ');hex(message);putchar('\n');}
int main(int argc,char**argv){if(argc<3)return 2;const char*level=strcmp(argv[2],"-")?argv[2]:NULL;printf("PID %u\n",(unsigned)getpid());printf("PROFILE %d\n",GNUNET_EXTRA_LOGGING);
 if(GNUNET_OK!=GNUNET_log_setup("owned-program",level,(argc>3)?argv[3]:NULL))return 3;
 if(!strcmp(argv[1],"policy")){const char*components[]={NULL,"owned-program","other"};int levels[]={-1,0,1,2,4,8,16,32,64,65};int lines[]={0,9,10,11,20,21,2147483647};for(unsigned c=0;c<3;c++)for(unsigned l=0;l<10;l++)for(unsigned n=0;n<7;n++)printf("P %u %d %d %d\n",c,levels[l],lines[n],GNUNET_get_log_call_status(levels[l],components[c],"owned/unit.c","probe",lines[n]));return 0;}
 if(!strcmp(argv[1],"custom")){int one=1,two=2;GNUNET_logger_add(logger,&one);GNUNET_logger_add(logger,&two);GNUNET_log_nocheck(GNUNET_ERROR_TYPE_ERROR,"%s","alpha");struct GNUNET_AsyncScopeId id={0};struct GNUNET_AsyncScopeSave old,current;GNUNET_async_scope_enter(&id,&old);GNUNET_async_scope_get(&current);printf("SCOPE %d\n",current.have_scope);GNUNET_log_from_nocheck(GNUNET_ERROR_TYPE_WARNING,"other","%s","beta\n");GNUNET_log_nocheck(GNUNET_ERROR_TYPE_MESSAGE,"%s","ready");GNUNET_log_nocheck(GNUNET_ERROR_TYPE_ERROR,"%s","");GNUNET_logger_remove(logger,&two);GNUNET_log_from_nocheck(GNUNET_ERROR_TYPE_DEBUG,NULL,"%s","tail");GNUNET_async_scope_restore(&old);GNUNET_async_scope_get(&current);printf("SCOPE %d\n",current.have_scope);GNUNET_logger_remove(logger,&one);return 0;}
 if(!strcmp(argv[1],"file")){fprintf(stderr,"diagnostic-port\n");struct GNUNET_AsyncScopeId id={0};struct GNUNET_AsyncScopeSave old;GNUNET_async_scope_enter(&id,&old);GNUNET_log_nocheck(GNUNET_ERROR_TYPE_ERROR,"%s","alpha");GNUNET_async_scope_restore(&old);GNUNET_log_nocheck(GNUNET_ERROR_TYPE_MESSAGE,"%s","ready");for(int i=0;i<1002;i++)GNUNET_log_from_nocheck(GNUNET_ERROR_TYPE_WARNING|GNUNET_ERROR_TYPE_BULK,"other","%s","repeat\n");return 0;}
 return 4;}
