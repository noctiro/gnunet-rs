/* Calls the unchanged normal public C Resolver library against the Rust host. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
static const char *operation,*value;
static int family,status;
static unsigned values,ends;
static struct GNUNET_RESOLVER_RequestHandle *request;
static struct GNUNET_SCHEDULER_Task *watchdog;
static void expiry(void *cls){(void)cls;watchdog=NULL;status=8;GNUNET_SCHEDULER_shutdown();}
static void done(void){request=NULL;ends++;printf("END|%u\n",values);if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}}
static void address(void *cls,const struct sockaddr *sa,socklen_t len){(void)cls;(void)len;if(!sa){done();return;}char b[INET6_ADDRSTRLEN];const void *p=sa->sa_family==AF_INET?(const void*)&((const struct sockaddr_in*)sa)->sin_addr:(const void*)&((const struct sockaddr_in6*)sa)->sin6_addr;if(!inet_ntop(sa->sa_family,p,b,sizeof b)){status=6;return;}values++;printf("ADDR|%d|%s\n",sa->sa_family,b);}
static void hostname(void *cls,const char *name){(void)cls;if(!name){done();return;}values++;printf("NAME|");for(const unsigned char *p=(const unsigned char*)name;*p;p++)printf("%02x",*p);puts("");}
static void canceled(void *cls){(void)cls;printf("CANCELED|%u|%u\n",values,ends);if(values||ends)status=7;if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}GNUNET_SCHEDULER_shutdown();}
static void cancel_request(void *cls){(void)cls;if(!request){status=9;GNUNET_SCHEDULER_shutdown();return;}GNUNET_RESOLVER_request_cancel(request);request=NULL;GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,60),&canceled,NULL);}
static void run(void *cls){(void)cls;struct GNUNET_TIME_Relative t=GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,2);watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,4),&expiry,NULL);
if(!strcmp(operation,"reverse")){if(family==AF_INET){struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
 a.sin_len=sizeof a;
#endif
if(inet_pton(AF_INET,value,&a.sin_addr)!=1){status=3;return;}request=GNUNET_RESOLVER_hostname_get((const void*)&a,sizeof a,GNUNET_YES,t,&hostname,NULL);
}else{struct sockaddr_in6 a;memset(&a,0,sizeof a);a.sin6_family=AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
 a.sin6_len=sizeof a;
#endif
if(inet_pton(AF_INET6,value,&a.sin6_addr)!=1){status=3;return;}request=GNUNET_RESOLVER_hostname_get((const void*)&a,sizeof a,GNUNET_YES,t,&hostname,NULL);}}
else request=GNUNET_RESOLVER_ip_get(value,family,t,&address,NULL);
printf("HANDLE|%s\n",request?"some":"none");if(!request){status=4;GNUNET_SCHEDULER_shutdown();return;}
if(!strcmp(operation,"cancel"))GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,20),&cancel_request,NULL);
}
int main(int argc,char **argv){if(argc!=5)return 2;operation=argv[2];value=argv[3];family=!strcmp(argv[4],"4")?AF_INET:(!strcmp(argv[4],"6")?AF_INET6:AF_UNSPEC);GNUNET_log_setup("resolver-rust-host-client","ERROR",NULL);struct GNUNET_CONFIGURATION_Handle *c=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(c,argv[1]))return 3;GNUNET_RESOLVER_connect(c);GNUNET_SCHEDULER_run(&run,NULL);GNUNET_RESOLVER_disconnect();GNUNET_CONFIGURATION_destroy(c);return status;}
