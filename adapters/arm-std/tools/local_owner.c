/* Actual unchanged normal libgnunetarm public ARM-self caller.  Only the BINARY
 * explicitly supplied by an owned test config can start; all children belong to
 * this new isolated caller and are waited before it exits. No daemon inventory. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include <sys/wait.h>
#include <signal.h>
#include <inttypes.h>
static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_ARM_Handle *owner;
static struct GNUNET_ARM_Operation *operation;
static struct GNUNET_SCHEDULER_Task *deadline,*cancel_task;
static const char *mode,*profile;
static unsigned flags,callbacks,close_mask,cloexec_mask;
static FILE *record;
static int failed,canceled;
static struct timespec beginning;
static uint64_t elapsed(void){struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;return ((uint64_t)now.tv_sec-(uint64_t)beginning.tv_sec)*1000000+(now.tv_nsec-beginning.tv_nsec)/1000;}
static void connection(void*cls,enum GNUNET_GenericReturnValue value){(void)cls;fprintf(record,"{\"event\":\"connection\",\"status\":%d}\n",value);}
static void finish(void*cls){(void)cls;if(deadline){GNUNET_SCHEDULER_cancel(deadline);deadline=NULL;}if(cancel_task){GNUNET_SCHEDULER_cancel(cancel_task);cancel_task=NULL;}if(owner){struct GNUNET_ARM_Handle *old=owner;owner=NULL;GNUNET_ARM_disconnect(old);}GNUNET_SCHEDULER_shutdown();}
static void terminal(void*cls,enum GNUNET_ARM_RequestStatus status,enum GNUNET_ARM_Result result){(void)cls;operation=NULL;callbacks++;fprintf(record,"{\"event\":\"result\",\"status\":%u,\"result\":",status);if(status==GNUNET_ARM_REQUEST_DISCONNECTED)fprintf(record,"null");else fprintf(record,"%u",result);fprintf(record,",\"elapsed_us\":%" PRIu64,elapsed());const char*release=getenv("ARM_COMMAND_RELEASE");if(release)fprintf(record,",\"release_observed\":%s",0==access(release,F_OK)?"true":"false");fprintf(record,"}\n");const char*ack=getenv("ARM_COMMAND_ACK");if(ack){FILE*a=fopen(ack,"w");if(!a)failed=1;else if(fclose(a))failed=1;}GNUNET_SCHEDULER_add_now(&finish,NULL);}
static void cancel_now(void*cls){(void)cls;cancel_task=NULL;canceled=1;if(!strcmp(mode,"cancel")){if(operation){GNUNET_ARM_operation_cancel(operation);operation=NULL;}fprintf(record,"{\"event\":\"cancel\"}\n");}finish(NULL);}
static void too_late(void*cls){(void)cls;deadline=NULL;failed=1;finish(NULL);}
static void start(void*cls){(void)cls;
 if(strcmp(profile,"inherit")){struct sigaction action;memset(&action,0,sizeof(action));sigemptyset(&action.sa_mask);action.sa_handler=!strcmp(profile,"ignore")?SIG_IGN:SIG_DFL;if(sigaction(SIGPIPE,&action,NULL)){failed=1;GNUNET_SCHEDULER_shutdown();return;}sigset_t blocked;sigemptyset(&blocked);sigaddset(&blocked,SIGUSR1);if(sigprocmask(SIG_BLOCK,&blocked,NULL)){failed=1;GNUNET_SCHEDULER_shutdown();return;}}
 owner=GNUNET_ARM_connect(cfg,&connection,NULL);if(!owner){failed=1;GNUNET_SCHEDULER_shutdown();return;}clock_gettime(CLOCK_MONOTONIC,&beginning);for(int fd=0;fd<3;fd++){if(close_mask&(1u<<fd))close(fd);else if(cloexec_mask&(1u<<fd)){int f=fcntl(fd,F_GETFD);if(f<0||fcntl(fd,F_SETFD,f|FD_CLOEXEC)){failed=1;GNUNET_SCHEDULER_shutdown();return;}}}operation=GNUNET_ARM_request_service_start(owner,"arm",(enum GNUNET_OS_InheritStdioFlags)flags,&terminal,NULL);if(!operation){failed=1;GNUNET_SCHEDULER_shutdown();return;}
 deadline=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,72),&too_late,NULL);if(strcmp(mode,"start"))cancel_task=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,20),&cancel_now,NULL);
}
int main(int argc,char**argv){if(argc!=5&&argc!=7&&argc!=8)return 90;record=stdout;if(argc>=7){record=fopen(argv[5],"w");if(!record)return 92;int f=fcntl(fileno(record),F_GETFD);if(f<0||fcntl(fileno(record),F_SETFD,f|FD_CLOEXEC))return 93;close_mask=(unsigned)strtoul(argv[6],NULL,10);if(close_mask>7)return 94;if(argc==8)cloexec_mask=(unsigned)strtoul(argv[7],NULL,10);if(cloexec_mask>7)return 95;}mode=argv[2];flags=(unsigned)strtoul(argv[3],NULL,10);profile=argv[4];setvbuf(record,NULL,_IOLBF,0);GNUNET_log_setup("arm-self-owned-caller","ERROR",NULL);cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_parse(cfg,argv[1]))return 91;GNUNET_SCHEDULER_run(&start,NULL);if(deadline)GNUNET_SCHEDULER_cancel(deadline);if(cancel_task)GNUNET_SCHEDULER_cancel(cancel_task);if(operation)GNUNET_ARM_operation_cancel(operation);if(owner)GNUNET_ARM_disconnect(owner);GNUNET_CONFIGURATION_destroy(cfg);
 unsigned children=0;int status;pid_t pid;while((pid=waitpid(-1,&status,0))>0){children++;fprintf(record,"{\"event\":\"reaped\",\"pid\":%d,\"exit\":",(int)pid);if(WIFEXITED(status))fprintf(record,"%d",WEXITSTATUS(status));else fprintf(record,"null");fprintf(record,",\"signal\":%d}\n",WIFSIGNALED(status)?WTERMSIG(status):0);}if(pid<0&&errno!=ECHILD)failed=1;
 fprintf(record,"{\"event\":\"done\",\"callbacks\":%u,\"canceled\":%s,\"children\":%u,\"failed\":%d}\n",callbacks,canceled?"true":"false",children,failed);if(record!=stdout)fclose(record);return failed?1:0;}
