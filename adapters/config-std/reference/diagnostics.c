/* Normal public configuration API; all fixtures are owned by the runner. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void hx(const char *s){for(const unsigned char*p=(const unsigned char*)s;*p;p++)printf("%02x",*p);}
static void log_record(void *cls,enum GNUNET_ErrorType kind,const char *component,const char *date,const char *message){(void)cls;printf("R %d ",kind);hx(component);putchar(' ');hx(date);putchar(' ');hx(message);putchar('\n');}
int main(int argc,char **argv){if(argc!=4)return 2;printf("PID %u\nPROFILE %d\n",(unsigned)getpid(),GNUNET_EXTRA_LOGGING);if(GNUNET_OK!=GNUNET_log_setup("owned-config", "DEBUG",NULL))return 3;struct GNUNET_CONFIGURATION_Handle *c=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());GNUNET_logger_add(log_record,NULL);int ret=0;
 if(!strcmp(argv[1],"deserialize"))ret=GNUNET_CONFIGURATION_deserialize(c,argv[2],strlen(argv[2]),NULL);
 else if(!strcmp(argv[1],"parse"))ret=GNUNET_CONFIGURATION_parse(c,argv[2]);
 else if(!strcmp(argv[1],"load"))ret=GNUNET_CONFIGURATION_load(c,argv[2]);
 else if(!strcmp(argv[1],"load-repeat")){ret=GNUNET_CONFIGURATION_load(c,argv[2]);if(GNUNET_OK==ret)ret=GNUNET_CONFIGURATION_load(c,argv[2]);}
 else if(!strcmp(argv[1],"diff-project")){struct GNUNET_OS_ProjectData pd=*GNUNET_OS_project_data_gnunet();struct GNUNET_CONFIGURATION_Handle*n=GNUNET_CONFIGURATION_create(&pd);struct GNUNET_CONFIGURATION_Handle*d=GNUNET_CONFIGURATION_get_diff(c,n);ret=d?GNUNET_OK:GNUNET_SYSERR;GNUNET_CONFIGURATION_destroy(d);GNUNET_CONFIGURATION_destroy(n);}
 else if(!strcmp(argv[1],"from"))ret=GNUNET_CONFIGURATION_load_from(c,argv[2]);
 else if(!strcmp(argv[1],"choice")){const char *choices[]={"YES","NO",NULL};const char *value=NULL;GNUNET_CONFIGURATION_set_value_string(c,"own","key",argv[2]);ret=GNUNET_CONFIGURATION_get_value_choice(c,"own","key",choices,&value);}
 else if(!strcmp(argv[1],"filename")){char*value=NULL;ret=GNUNET_CONFIGURATION_get_value_filename(c,"own","missing",&value);GNUNET_free(value);}
 else if(!strcmp(argv[1],"dollar")){char*v=GNUNET_CONFIGURATION_expand_dollar(c,GNUNET_strdup(argv[2]));printf("VALUE ");hx(v);putchar('\n');GNUNET_free(v);ret=GNUNET_OK;}
 else if(!strcmp(argv[1],"secret-get")){GNUNET_CONFIGURATION_parse(c,argv[2]);char*v=NULL;ret=GNUNET_CONFIGURATION_get_value_string(c,"secret","missing",&v);GNUNET_free(v);}
 else if(!strcmp(argv[1],"clean")){GNUNET_CONFIGURATION_enable_diagnostics(c);if(strcmp(argv[3],"not-parsed")){GNUNET_CONFIGURATION_parse(c,argv[2]);if(!strcmp(argv[3],"unlinked")){if(unlink(argv[2]))return 4;}else{FILE*f=fopen(argv[2],"a");if(!f)return 4;fputs("# owned change\n",f);fclose(f);}}unsigned removed=99;ret=GNUNET_CONFIGURATION_clean_file(c,argv[2],NULL,NULL,&removed);}
 else if(!strcmp(argv[1],"write"))ret=GNUNET_CONFIGURATION_write(c,argv[2]);
 else return 5;
 printf("RESULT %d\n",ret);GNUNET_CONFIGURATION_destroy(c);GNUNET_logger_remove(log_record,NULL);return 0;}
