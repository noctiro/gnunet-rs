/* Normal public GNUnet STATISTICS API observer. No library/source substitutions. */
#include "gnunet_statistics_service.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_STATISTICS_Handle *owner;
struct Context {
  unsigned id;
  int watch;
  int mode;
  unsigned rows;
  struct GNUNET_STATISTICS_GetHandle *get;
  char *sub;
  char *name;
};
static struct Context contexts[64];
static char input[262144];
static size_t used;
static int stopped;
static const char *socket_path, *disable, *transport;

static void emit_hex(const char *s) {
  if (s) for (const unsigned char *p=(const unsigned char *)s; *p; p++)
    printf("%02x", *p);
}
static char *decode(const char *s) {
  if (!s || !strcmp(s,"-")) return NULL;
  if (!strcmp(s,"_")) return GNUNET_strdup("");
  size_t n=strlen(s);
  if (n%2) { fprintf(stderr,"bad hex\n"); _exit(90); }
  char *r=GNUNET_malloc(n/2+1);
  for(size_t i=0;i<n/2;i++) {
    unsigned x;
    if (1!=sscanf(s+2*i,"%2x",&x) || !x) _exit(91);
    r[i]=(char)x;
  }
  r[n/2]=0;
  return r;
}
static struct Context *context(char *s) {
  unsigned i=(unsigned)strtoul(s,NULL,10);
  if(i>=64) _exit(92);
  contexts[i].id=i;
  return &contexts[i];
}
static int row(void *cls,const char *sub,const char *name,uint64_t value,int persistent) {
  struct Context *c=cls;
  c->rows++;
  printf("{\"event\":\"row\",\"kind\":\"%s\",\"id\":%u,\"row\":%u,\"sub_hex\":\"",c->watch?"watch":"get",c->id,c->rows);
  emit_hex(sub);printf("\",\"name_hex\":\"");emit_hex(name);
  printf("\",\"value\":\"%" PRIu64 "\",\"persistent\":%d}\n",value,persistent);
  if(c->mode==2 && c->get) {
    GNUNET_STATISTICS_get_cancel(c->get);c->get=NULL;
    printf("{\"event\":\"callback_cancel\",\"id\":%u}\n",c->id);
  }
  return c->mode==1?GNUNET_SYSERR:GNUNET_OK;
}
static void complete(void *cls,int success) {
  struct Context *c=cls;
  c->get=NULL;
  printf("{\"event\":\"cont\",\"id\":%u,\"success\":%d}\n",c->id,success);
  /* Public header prohibits destroying the owner from this continuation. */
}
static void command(char *line) {
  char *save=NULL,*op=strtok_r(line," ",&save);
  if(!op)return;
#define ARG() strtok_r(NULL," ",&save)
  if(!strcmp(op,"CREATE")) {
    char *sub=decode(ARG());
    owner=GNUNET_STATISTICS_create(sub,cfg);
    GNUNET_free(sub);
    printf("{\"event\":\"create\",\"present\":%s}\n",owner?"true":"false");
  } else if(!strcmp(op,"SET") || !strcmp(op,"UPDATE")) {
    char *name=decode(ARG());char *number=ARG();int persistent=atoi(ARG());
    if(!strcmp(op,"SET")) GNUNET_STATISTICS_set(owner,name,strtoull(number,NULL,10),persistent);
    else GNUNET_STATISTICS_update(owner,name,strtoll(number,NULL,10),persistent);
    GNUNET_free(name);
    printf("{\"event\":\"call\",\"api\":\"%s\"}\n",op);
  } else if(!strcmp(op,"GET")) {
    struct Context *c=context(ARG());
    c->watch=0;c->rows=0;
    char *sub=decode(ARG()),*name=decode(ARG());c->mode=atoi(ARG());
    c->get=GNUNET_STATISTICS_get(owner,sub,name,c->mode==3?NULL:&complete,&row,c);
    GNUNET_free(sub);GNUNET_free(name);
    printf("{\"event\":\"get\",\"id\":%u,\"present\":%s}\n",c->id,c->get?"true":"false");
  } else if(!strcmp(op,"GCANCEL")) {
    struct Context *c=context(ARG());
    if(c->get){GNUNET_STATISTICS_get_cancel(c->get);c->get=NULL;}
    printf("{\"event\":\"get_cancel\",\"id\":%u}\n",c->id);
  } else if(!strcmp(op,"WATCH")) {
    struct Context *c=context(ARG());c->watch=1;
    char *s=decode(ARG()),*n=decode(ARG());c->mode=atoi(ARG());
    if(!c->sub){c->sub=GNUNET_strdup(s);c->name=GNUNET_strdup(n);}
    int result=GNUNET_STATISTICS_watch(owner,s,n,&row,c);
    GNUNET_free(s);GNUNET_free(n);
    printf("{\"event\":\"watch\",\"id\":%u,\"result\":%d}\n",c->id,result);
  } else if(!strcmp(op,"WCANCEL")) {
    struct Context *c=context(ARG());
    int result=GNUNET_STATISTICS_watch_cancel(owner,c->sub,c->name,&row,c);
    printf("{\"event\":\"watch_cancel\",\"id\":%u,\"result\":%d}\n",c->id,result);
  } else if(!strcmp(op,"DESTROY")) {
    int sync=atoi(ARG());
    printf("{\"event\":\"destroy_begin\",\"sync\":%d}\n",sync);
    struct GNUNET_STATISTICS_Handle *h=owner;owner=NULL;
    GNUNET_STATISTICS_destroy(h,sync);
    printf("{\"event\":\"destroy_return\",\"sync\":%d}\n",sync);
  } else if(!strcmp(op,"STOP")) {
    if(owner){struct GNUNET_STATISTICS_Handle *h=owner;owner=NULL;GNUNET_STATISTICS_destroy(h,GNUNET_NO);}
    stopped=1;GNUNET_SCHEDULER_shutdown();
  } else {fprintf(stderr,"unknown command %s\n",op);_exit(93);}
#undef ARG
}
static void poll_control(void *cls) {
  (void)cls;
  for(;;) {
    ssize_t n=read(STDIN_FILENO,input+used,sizeof(input)-1-used);
    if(n>0) used+=(size_t)n;
    else if(n<0 && errno==EINTR) continue;
    else if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
    else {if(n==0) stopped=1;else perror("control read");break;}
    if(used==sizeof(input)-1) _exit(94);
  }
  input[used]=0;
  char *end;
  while((end=strstr(input,"COMMIT\n"))) {
    size_t consumed=(size_t)(end-input)+7;
    *end=0;
    char *save=NULL;
    for(char *line=strtok_r(input,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) command(line);
    printf("{\"event\":\"commit\"}\n");
    memmove(input,input+consumed,used-consumed);used-=consumed;input[used]=0;
  }
  if(stopped){GNUNET_SCHEDULER_shutdown();return;}
  GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MILLISECONDS,&poll_control,NULL);
}
static void run(void *cls) {
  (void)cls;
  cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());
  if(strcmp(transport,"missing") && strncmp(transport,"tcp",3))GNUNET_CONFIGURATION_set_value_string(cfg,"statistics","UNIXPATH",socket_path);
  if(strcmp(disable,"missing"))GNUNET_CONFIGURATION_set_value_string(cfg,"statistics","DISABLE",disable);
  GNUNET_CONFIGURATION_set_value_string(cfg,"statistics","PORT",!strncmp(transport,"tcp",3)?socket_path:"0");
  if(strcmp(transport,"missing-hostname"))GNUNET_CONFIGURATION_set_value_string(cfg,"statistics","HOSTNAME",!strcmp(transport,"tcp4")?"127.0.0.1":!strcmp(transport,"tcp6")?"::1":"localhost");
  printf("{\"event\":\"ready\",\"version\":%u,\"ok\":%d,\"syserr\":%d}\n",GNUNET_STATISTICS_VERSION,GNUNET_OK,GNUNET_SYSERR);
  GNUNET_SCHEDULER_add_now(&poll_control,NULL);
}
int main(int argc,char **argv) {
  if(argc!=4)return 89;
  socket_path=argv[1];disable=argv[2];transport=argv[3];
  setvbuf(stdout,NULL,_IONBF,0);
  if(fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK)<0)return 88;
  GNUNET_log_setup("public-statistics-owner","WARNING",NULL);
  GNUNET_SCHEDULER_run(&run,NULL);
  if(owner)GNUNET_STATISTICS_destroy(owner,GNUNET_NO);
  GNUNET_CONFIGURATION_destroy(cfg);
  for(unsigned i=0;i<64;i++){GNUNET_free(contexts[i].sub);GNUNET_free(contexts[i].name);}
  printf("{\"event\":\"exit\"}\n");return 0;
}
