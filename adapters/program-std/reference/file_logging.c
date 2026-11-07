/* Defined-safe normal public logging calls; filesystem fixture belongs to runner. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void hex(const char *s){for(const unsigned char*p=(const unsigned char*)s;*p;p++)printf("%02x",*p);}
static void logger(void*cls,enum GNUNET_ErrorType kind,const char*comp,const char*date,const char*message){(void)cls;printf("R %d ",kind);hex(comp);putchar(' ');hex(date);putchar(' ');hex(message);putchar('\n');}
int main(int argc,char**argv){if(argc!=5)return 2;printf("PID %u\nPROFILE %d\n",(unsigned)getpid(),GNUNET_EXTRA_LOGGING);GNUNET_logger_add(logger,NULL);int first=GNUNET_log_setup("owned-errors",argv[2],argv[3]);printf("SETUP %d\n",first);
 if(!strcmp(argv[1],"cached")||!strcmp(argv[1],"recover")){if(unlink(argv[4])||mkdir(argv[4],0755))return 3;char *next=NULL;GNUNET_asprintf(&next,"%s.new",argv[3]);int second=GNUNET_log_setup("owned-errors",argv[2],!strcmp(argv[1],"cached")?argv[3]:next);printf("SETUP %d\n",second);GNUNET_free(next);}
 if(!strcmp(argv[1],"rotate")){fprintf(stderr,"DIRECT initial\n");fflush(stderr);for(unsigned i=0;i<6;i++){char*next=NULL;GNUNET_asprintf(&next,"%s.%u",argv[3],i);int ret=GNUNET_log_setup("owned-errors",argv[2],next);printf("SETUP %d\n",ret);fprintf(stderr,"DIRECT %u\n",i);fflush(stderr);GNUNET_free(next);}}
 GNUNET_logger_remove(logger,NULL);fprintf(stderr,"DIRECT after setup\n");fflush(stderr);return 0;}
