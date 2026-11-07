/* Actual unmodified public GNUnet Resolver API caller; no service implementation. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
static struct GNUNET_RESOLVER_RequestHandle *requests[4];
static struct GNUNET_SCHEDULER_Task *watchdog;
static const char *mode;
static int status;
static unsigned complete;
static struct GNUNET_MQ_Handle *client_mq;
static unsigned service_replies;
static const struct GNUNET_CONFIGURATION_Handle *configuration;
static void address(void *,const struct sockaddr *,socklen_t);
static void failure(void *cls){(void)cls;watchdog=NULL;status=8;GNUNET_SCHEDULER_shutdown();}
static void stop(void){if(watchdog){GNUNET_SCHEDULER_cancel(watchdog);watchdog=NULL;}}
static struct GNUNET_RESOLVER_RequestHandle *query(unsigned id,const char *name,unsigned millis){return GNUNET_RESOLVER_ip_get(name,AF_UNSPEC,GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,millis),&address,(void *)(uintptr_t)id);}
static void canceled(void *cls){(void)cls;GNUNET_RESOLVER_request_cancel(requests[2]);requests[2]=NULL;puts("CANCEL|2");fflush(stdout);}
static void after_warm(void *cls){(void)cls;requests[2]=query(2,"instant-cancel",2000);if(!requests[2]){status=9;return;}GNUNET_RESOLVER_request_cancel(requests[2]);requests[2]=NULL;puts("CANCEL|2");requests[3]=query(3,"kept",2000);fflush(stdout);}
static void address(void *cls,const struct sockaddr *sa,socklen_t len){(void)len;unsigned id=(unsigned)(uintptr_t)cls;
 if(sa){char text[INET6_ADDRSTRLEN];const void *a=sa->sa_family==AF_INET?(const void *)&((const struct sockaddr_in*)sa)->sin_addr:(const void *)&((const struct sockaddr_in6*)sa)->sin6_addr;if(!inet_ntop(sa->sa_family,a,text,sizeof text)){status=5;return;}printf("ADDR|%u|%s\n",id,text);
 if(!strcmp(mode,"stack")&&id==1&&sa->sa_family==AF_INET6){requests[2]=query(2,"due",0);GNUNET_TIME_set_offset(-3000000);}
 }else{requests[id]=NULL;printf("END|%u\n",id);complete++;
 if(!strcmp(mode,"stack")&&id==1)GNUNET_TIME_set_offset(0);
 if(!strcmp(mode,"instant")&&id==1)GNUNET_SCHEDULER_add_now(&after_warm,NULL);
 if(!strcmp(mode,"orphan")&&id==1){requests[3]=query(3,"kept",2000);GNUNET_SCHEDULER_add_now(&canceled,NULL);}
 if((!strcmp(mode,"stack")&&complete==2)||(!strcmp(mode,"instant")&&id==3)||(!strcmp(mode,"orphan")&&id==3)||(!strcmp(mode,"retry")&&id==1)||(!strcmp(mode,"hosts")&&complete==2))stop();
 }fflush(stdout);
}
static void handle_service(void *cls,const struct GNUNET_MessageHeader *msg){(void)cls;(void)msg;printf("SERVICE|%u\n",++service_replies);fflush(stdout);if(service_replies==2){GNUNET_MQ_destroy(client_mq);client_mq=NULL;stop();}}
static void client_error(void *cls,enum GNUNET_MQ_Error error){(void)cls;(void)error;status=7;if(client_mq){GNUNET_MQ_destroy(client_mq);client_mq=NULL;}GNUNET_SCHEDULER_shutdown();}
static void hostname(void *cls,const char *name){unsigned id=(unsigned)(uintptr_t)cls;if(name){printf("NAME|%u|",id);for(const unsigned char *p=(const unsigned char*)name;*p;p++)printf("%02x",*p);puts("");}else{requests[id]=NULL;printf("END|%u\n",id);stop();}fflush(stdout);}
static void run(void *cls){(void)cls;watchdog=GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,5),&failure,NULL);
 if(!strcmp(mode,"client")){struct GNUNET_MQ_MessageHandler handlers[]={GNUNET_MQ_hd_fixed_size(service,GNUNET_MESSAGE_TYPE_TEST,struct GNUNET_MessageHeader,NULL),GNUNET_MQ_handler_end()};client_mq=GNUNET_CLIENT_connect(configuration,"owned",handlers,&client_error,NULL);if(!client_mq){status=4;GNUNET_SCHEDULER_shutdown();return;}struct GNUNET_MessageHeader *msg;struct GNUNET_MQ_Envelope *env=GNUNET_MQ_msg(msg,GNUNET_MESSAGE_TYPE_TEST);GNUNET_MQ_send(client_mq,env);return;}
 if(!strcmp(mode,"stack"))requests[1]=query(1,"localhost",0);
 else if(!strcmp(mode,"instant"))requests[1]=query(1,"warm",2000);
 else if(!strcmp(mode,"orphan")){requests[1]=query(1,"expired",50);requests[2]=query(2,"canceled",2000);}
 else if(!strcmp(mode,"reverse")){struct sockaddr_in address;memset(&address,0,sizeof address);address.sin_family=AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
address.sin_len=sizeof address;
#endif
inet_pton(AF_INET,"192.0.2.9",&address.sin_addr);requests[1]=GNUNET_RESOLVER_hostname_get((const void*)&address,sizeof address,GNUNET_YES,GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,2),&hostname,(void*)(uintptr_t)1);}
 else if(!strcmp(mode,"retry"))requests[1]=query(1,"retry",2000);
 else if(!strcmp(mode,"hosts")){requests[1]=query(1,"broadcasthost",2000);requests[2]=query(2,"broadcasthost",2000);}
 else {status=2;GNUNET_SCHEDULER_shutdown();}
 if(!requests[1]){status=3;GNUNET_SCHEDULER_shutdown();}
}
int main(int argc,char **argv){if(argc!=3)return 2;mode=argv[2];GNUNET_log_setup("shared-resolver-public","DEBUG",NULL);struct GNUNET_CONFIGURATION_Handle *cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(GNUNET_OK!=GNUNET_CONFIGURATION_load(cfg,argv[1]))return 3;configuration=cfg;GNUNET_RESOLVER_connect(cfg);GNUNET_SCHEDULER_run(&run,NULL);if(client_mq){GNUNET_MQ_destroy(client_mq);client_mq=NULL;}for(unsigned i=1;i<4;i++)if(requests[i]){GNUNET_RESOLVER_request_cancel(requests[i]);requests[i]=NULL;}GNUNET_RESOLVER_disconnect();GNUNET_CONFIGURATION_destroy(cfg);return status;}
