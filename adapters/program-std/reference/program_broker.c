/* Normal PROGRAM -> global RESOLVER_connect -> one real public request.
 * Only runner-owned Unix peers are selected; the external sandbox denies IP. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
static struct GNUNET_RESOLVER_RequestHandle *request;
static struct GNUNET_SCHEDULER_Task *watchdog;
static unsigned calls,ends;
static unsigned long long wall(void){struct timeval tv;if(gettimeofday(&tv,NULL))return 0;return (unsigned long long)tv.tv_sec*1000000ULL+(unsigned long long)tv.tv_usec;}
static void point(const char *tag){unsigned long long before=wall();unsigned long long logical=(unsigned long long)GNUNET_TIME_absolute_get().abs_value_us;unsigned long long after=wall();printf("%s WALL %llu %llu LOGICAL %llu OFFSET %lld\n",tag,before,after,logical,GNUNET_TIME_get_offset());fflush(stdout);}
static int status;
static void expired(void *cls){(void)cls;watchdog=NULL;status=8;GNUNET_SCHEDULER_shutdown();}
static void resolved(void *cls,const struct sockaddr *address,socklen_t length){(void)cls;(void)length;if(address){if(address->sa_family!=AF_INET){status=9;return;}const unsigned char *raw=(const unsigned char*)&((const struct sockaddr_in*)address)->sin_addr;printf("ADDRESS %02x%02x%02x%02x\n",raw[0],raw[1],raw[2],raw[3]);}else{request=NULL;ends++;point("END");if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}GNUNET_SCHEDULER_shutdown();}fflush(stdout);}
static void main_task(void *cls,char *const *args,const char *filename,const struct GNUNET_CONFIGURATION_Handle *config){(void)cls;(void)args;(void)filename;(void)config;calls++;point("MAIN");watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,2),&expired,NULL);request=GNUNET_RESOLVER_ip_get("owned.program.invalid",AF_UNSPEC,GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,500),&resolved,NULL);if(!request){status=7;GNUNET_SCHEDULER_shutdown();}point("QUEUED");}
int main(int argc,char **argv){const char *first=getenv("OWNED_BROKER_INITIAL");if(!first)return 2;struct GNUNET_CONFIGURATION_Handle *initial=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(initial,first))return 3;GNUNET_RESOLVER_connect(initial);struct GNUNET_GETOPT_CommandLineOption options[]={GNUNET_GETOPT_OPTION_END};int result=GNUNET_PROGRAM_run2(GNUNET_OS_project_data_gnunet(),argc,argv,"owned-program","Owned shared PROGRAM",options,&main_task,NULL,GNUNET_NO);if(request){GNUNET_RESOLVER_request_cancel(request);request=NULL;}GNUNET_RESOLVER_disconnect();GNUNET_CONFIGURATION_destroy(initial);printf("RETURN %d TASKS %u ENDS %u\n",result,calls,ends);return status;}
