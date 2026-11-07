/* These are recording external capabilities, not a statistics/client state machine. */
static void do_destroy(void*);
static void reconnect_task(void*);
static void reconnect_later(struct GNUNET_STATISTICS_Handle*);
static void transmit_ready(void*);
static void impl_send_continue(void*);
static void connection_client_send_impl(struct GNUNET_MQ_Handle*,const struct GNUNET_MessageHeader*,void*);
static void mq_error_handler(void*,enum GNUNET_MQ_Error);
struct GNUNET_SCHEDULER_Task{unsigned id;uint64_t at,delay;GNUNET_SCHEDULER_TaskCallback cb;void*cls;int active;int write;};
static struct GNUNET_SCHEDULER_Task tasks[1024];
static unsigned task_count,action_calls,mq_destroy_calls,sent_calls,inflight_calls,continue_calls,error_calls,completion_calls;
static uint64_t clock_now;
static int completion_result;
static const char*scenario;
static int connector_available;
static struct ClientState*connector_client;
static unsigned connector_calls;
static ssize_t send_results[16];static int send_errors[16];static unsigned send_count,send_index;
struct GNUNET_TIME_Absolute GNUNET_TIME_absolute_get(void){return (struct GNUNET_TIME_Absolute){clock_now};}
static struct GNUNET_SCHEDULER_Task*add_task(struct GNUNET_TIME_Relative delay,GNUNET_SCHEDULER_TaskCallback cb,void*cls,int write){assert(task_count<1024);struct GNUNET_SCHEDULER_Task*t=&tasks[task_count++];*t=(struct GNUNET_SCHEDULER_Task){task_count,GNUNET_TIME_relative_to_absolute(delay).abs_value_us,delay.rel_value_us,cb,cls,1,write};return t;}
struct GNUNET_SCHEDULER_Task*GNUNET_SCHEDULER_add_delayed(struct GNUNET_TIME_Relative delay,GNUNET_SCHEDULER_TaskCallback cb,void*cls){return add_task(delay,cb,cls,0);}
struct GNUNET_SCHEDULER_Task*GNUNET_SCHEDULER_add_now(GNUNET_SCHEDULER_TaskCallback cb,void*cls){return add_task(GNUNET_TIME_UNIT_ZERO,cb,cls,0);}
struct GNUNET_SCHEDULER_Task*GNUNET_SCHEDULER_add_write_net(struct GNUNET_TIME_Relative delay,struct GNUNET_NETWORK_Handle*sock,GNUNET_SCHEDULER_TaskCallback cb,void*cls){assert(sock);return add_task(delay,cb,cls,1);}
void*GNUNET_SCHEDULER_cancel(struct GNUNET_SCHEDULER_Task*t){assert(t&&t->active);t->active=0;return t->cls;}
static void deliver(struct GNUNET_SCHEDULER_Task*t,int ready){assert(t&&t->active);if(!ready){assert(t->at!=UINT64_MAX);clock_now=t->at;}t->active=0;t->cb(t->cls);}
static void hold_send(struct GNUNET_MQ_Handle*mq,const struct GNUNET_MessageHeader*msg,void*cls){(void)mq;(void)msg;(void)cls;}
static void record_destroy(struct GNUNET_MQ_Handle*mq,void*cls){(void)mq;(void)cls;mq_destroy_calls++;}
static void record_sent(void*cls){(void)cls;sent_calls++;}
static void record_error(void*cls,enum GNUNET_MQ_Error error){(void)cls;assert(error==GNUNET_MQ_ERROR_WRITE);error_calls++;}
static void record_completion(void*cls,int result){(void)cls;completion_calls++;completion_result=result;}
ssize_t GNUNET_NETWORK_socket_send(const struct GNUNET_NETWORK_Handle*sock,const void*bytes,size_t len){assert(sock&&bytes&&len);assert(send_index<send_count);ssize_t n=send_results[send_index];errno=send_errors[send_index++];assert(n<0||(size_t)n<=len);return n;}
static void reset(const char*name){assert(task_count<1024);scenario=name;action_calls=mq_destroy_calls=sent_calls=inflight_calls=continue_calls=error_calls=completion_calls=0;completion_result=0;send_count=send_index=0;connector_client=NULL;connector_available=1;connector_calls=0;}
static struct GNUNET_MQ_Handle*queue(void){struct GNUNET_MQ_Handle*mq=GNUNET_new(struct GNUNET_MQ_Handle);mq->send_impl=&hold_send;mq->destroy_impl=&record_destroy;mq->error_handler=&record_error;return mq;}
static struct GNUNET_MQ_Envelope*envelope(uint16_t type){struct GNUNET_MessageHeader*msg;struct GNUNET_MQ_Envelope*env=GNUNET_MQ_msg_(&msg,20,type);memset(&msg[1],0,16);GNUNET_MQ_notify_sent(env,&record_sent,NULL);return env;}

struct GNUNET_MQ_Handle* GNUNET_CLIENT_connect(const struct GNUNET_CONFIGURATION_Handle*cfg,const char*service,const struct GNUNET_MQ_MessageHandler*handlers,GNUNET_MQ_ErrorHandler error_handler,void*error_cls){assert(cfg&&0==strcmp(service,"statistics"));connector_calls++;if(!connector_available)return NULL;struct GNUNET_MQ_Handle*mq=GNUNET_MQ_queue_for_callbacks(connector_client?&connection_client_send_impl:&hold_send,&record_destroy,NULL,connector_client,handlers,error_handler,error_cls);if(connector_client)connector_client->mq=mq;return mq;}
