/* Normal unchanged utility-library process caller, only finite owned targets. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <signal.h>
#include <sys/wait.h>
static int ready(const char *path){for(unsigned i=0;i<3000;i++){FILE*f=fopen(path,"r");if(f){char buffer[8192];size_t n=fread(buffer,1,sizeof(buffer)-1,f);buffer[n]=0;fclose(f);if(strstr(buffer,"ready=1"))return 1;}usleep(1000);}return 0;}
int main(int argc,char**argv){
 if(argc<6)return 90;
 if(SIG_ERR==signal(SIGPIPE,!strcmp(argv[5],"default")?SIG_DFL:SIG_IGN))return 91;
 GNUNET_log_setup("process-owned-caller","ERROR",NULL);
 unsigned flags=(unsigned)strtoul(argv[4],NULL,10);
 struct GNUNET_Process *proc=GNUNET_process_create((enum GNUNET_OS_InheritStdioFlags)flags);
 GNUNET_process_set_options(proc,GNUNET_process_option_set_environment("GNUNET_PROCESS_TEST_OUTPUT",argv[3]),GNUNET_process_option_set_environment("GNUNET_PROCESS_TEST_MODE",argv[2]));
 const char *value=getenv("GNUNET_PROCESS_OWNER_VALUE");if(value)GNUNET_process_set_options(proc,GNUNET_process_option_set_environment("GNUNET_PROCESS_TEST_VALUE",value));
 const char *raw=getenv("GNUNET_PROCESS_OWNER_FDS");if(raw){char *copy=strdup(raw),*save=NULL;for(char *at=strtok_r(copy,":",&save);at;at=strtok_r(NULL,":",&save))GNUNET_process_set_options(proc,GNUNET_process_option_inherit_lsock(atoi(at)));free(copy);}
 int result=GNUNET_process_run_command_argv(proc,argv[1],(const char**)&argv[6]);
 printf("{\"event\":\"admission\",\"admitted\":%s,\"pid_positive\":%s}\n",result==GNUNET_OK?"true":"false",GNUNET_process_get_pid(proc)>0?"true":"false");fflush(stdout);
 if(result!=GNUNET_OK){GNUNET_process_destroy(proc);return 0;}
 if(!strcmp(argv[2],"control")||!strcmp(argv[2],"close-control")){
  if(!ready(argv[3]))return 92;int sent=GNUNET_process_kill(proc,15);printf("{\"event\":\"signal\",\"ok\":%s}\n",sent==GNUNET_OK?"true":"false");fflush(stdout);
 }
 enum GNUNET_OS_ProcessStatusType type;unsigned long code;
 int waited=GNUNET_process_wait(proc,true,&type,&code);
 if(waited!=GNUNET_OK)return 93;
 printf("{\"event\":\"wait\",\"exit\":");if(type==GNUNET_OS_PROCESS_EXITED)printf("%lu",code);else printf("null");printf(",\"signal\":%lu}\n",type==GNUNET_OS_PROCESS_SIGNALED?code:0UL);
 GNUNET_process_destroy(proc);return 0;
}
