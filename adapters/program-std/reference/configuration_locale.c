#include "platform.h"
#include "gnunet_util_lib.h"
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#if defined(__APPLE__)
#include <xlocale.h>
#endif
static const char us[]={'o','w','n',(char)0xc9,0},ls[]={'o','w','n',(char)0xe9,0},uk[]={'k',(char)0xd6,0},lk[]={'k',(char)0xf6,0};
static void value(const char *label,struct GNUNET_CONFIGURATION_Handle *cfg,const char *s,const char *k){char *v=NULL;int r=GNUNET_CONFIGURATION_get_value_string(cfg,s,k,&v);printf("%s %d ",label,r);if(v)for(size_t i=0;i<strlen(v);++i)printf("%02x",(unsigned char)v[i]);printf("\n");GNUNET_free(v);}
struct Worker { struct GNUNET_CONFIGURATION_Handle *cfg; int fail; size_t consumed; locale_t copied; };
static void *worker(void *raw){struct Worker *w=raw;if(w->fail){float f=0;int r=GNUNET_CONFIGURATION_get_value_float(w->cfg,"s","v",&f);if(r!=GNUNET_SYSERR)return (void*)1;}w->copied=duplocale(uselocale(NULL));if(!w->copied)return (void*)2;char *end=NULL;const char *in="1,5";(void)strtof(in,&end);w->consumed=(size_t)(end-in);return NULL;}
int main(int argc,char **argv){
 if(argc<3)return 2;
 if(!setlocale(LC_ALL,"C"))return 3;
 if(GNUNET_OK!=GNUNET_log_setup("owned-locale","NONE",NULL))return 4;
 struct GNUNET_CONFIGURATION_Handle *cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());
 GNUNET_CONFIGURATION_remove_section(cfg,"PATHS");
 GNUNET_CONFIGURATION_set_value_string(cfg,us,uk,"value");
 struct GNUNET_CONFIGURATION_Handle *copy=GNUNET_CONFIGURATION_dup(cfg);
 if(!setlocale(LC_ALL,argv[2]))return 5;
 if(0==strcmp(argv[1],"switch")){
  value("ORIGINAL",cfg,ls,lk);value("DUPLICATE",copy,ls,lk);
  GNUNET_CONFIGURATION_set_value_string(cfg,ls,lk,"replacement");value("UPDATED-UPPER",cfg,us,uk);value("UPDATED-LOWER",cfg,ls,lk);
  GNUNET_CONFIGURATION_remove_section(cfg,ls);value("REMOVED-UPPER",cfg,us,uk);
  if(!setlocale(LC_ALL,"C"))return 6;
  value("RESET-C-UPPER",copy,us,uk);value("RESET-C-LOWER",copy,ls,lk);
 }else if(0==strcmp(argv[1],"float")||0==strcmp(argv[1],"float-reset")){
  if(argc!=4)return 7;GNUNET_CONFIGURATION_set_value_string(cfg,"s","v",argv[3]);float f=0;int r=GNUNET_CONFIGURATION_get_value_float(cfg,"s","v",&f);uint32_t bits=0;memcpy(&bits,&f,4);printf("FLOAT %d %08x\n",r,r==GNUNET_OK?bits:0);if(0==strcmp(argv[1],"float-reset")&&!setlocale(LC_ALL,"C"))return 9;value("AFTER-FLOAT",cfg,ls,lk);
 }else if(0==strcmp(argv[1],"choice-paths")){
  GNUNET_CONFIGURATION_set_value_string(cfg,"s","v","i");const char *choice=NULL;const char *const choices[]={"I",NULL};int r=GNUNET_CONFIGURATION_get_value_choice(cfg,"s","v",choices,&choice);printf("CHOICE %d %d\n",r,choice!=NULL);
  GNUNET_CONFIGURATION_set_value_string(cfg,"paths","bindir","owned");size_t size=0;char *s=GNUNET_CONFIGURATION_serialize(cfg,&size);printf("SERIALIZED ");for(size_t i=0;i<size;++i)printf("%02x",(unsigned char)s[i]);printf("\n");GNUNET_free(s);
 }else if(0==strcmp(argv[1],"include")||0==strcmp(argv[1],"include-secret")||0==strcmp(argv[1],"include-matching")){
  if(argc!=4)return 15;char *text=NULL;const char *directive=0==strcmp(argv[1],"include-secret")?"iNlInE-sEcReT":0==strcmp(argv[1],"include-matching")?"iNlInE-mAtChInG":"iNlInE";
  if(0==strcmp(argv[1],"include-secret"))GNUNET_asprintf(&text,"@%s@ %s %s\n",directive,us,argv[3]);else GNUNET_asprintf(&text,"@%s@ %s\n",directive,argv[3]);int r=GNUNET_CONFIGURATION_deserialize(cfg,text,strlen(text),NULL);printf("INCLUDE %d\n",r);value("INCLUDED-UPPER",cfg,us,uk);value("INCLUDED-LOWER",cfg,ls,lk);GNUNET_free(text);
 }else if(0==strcmp(argv[1],"dollar")){
  const char key[]={'O','W','N','E','D','_','L','O','C','A','L','E','_','V','A','R',(char)0xc9,0};const char term[]={'$','{','o','w','n','e','d','_','l','o','c','a','l','e','_','v','a','r',(char)0xe9,':','-','f','a','l','l','b','a','c','k','}','/','l','e','a','f',0};GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS",key,"value");char *v=GNUNET_CONFIGURATION_expand_dollar(cfg,GNUNET_strdup(term));printf("EXPANDED ");for(size_t i=0;i<strlen(v);++i)printf("%02x",(unsigned char)v[i]);printf("\n");GNUNET_free(v);
 }else if(0==strcmp(argv[1],"byte-table")){
  printf("SPACES ");for(int i=0;i<256;++i)putchar(isspace(i)?'1':'0');printf("\nCASE ");
  for(int i=0;i<256;++i)for(int j=0;j<256;++j){char a[2]={(char)i,0},b[2]={(char)j,0};putchar(0==strcasecmp(a,b)?'1':'0');}printf("\n");
 }else if(0==strcmp(argv[1],"parse-number")){
  const char text[]="\v[own\xc9]\f\n\tk\xd6\v=\vvalue\f\t\n";
  printf("PARSE %d\n",GNUNET_CONFIGURATION_deserialize(cfg,text,sizeof(text)-1,NULL));value("PARSED",cfg,ls,lk);
  GNUNET_CONFIGURATION_set_value_string(cfg,"s","n"," \v+12\f");unsigned long long n=0;int r=GNUNET_CONFIGURATION_get_value_number(cfg,"s","n",&n);printf("NUMBER %d %llu\n",r,n);
 }else if(0==strcmp(argv[1],"thread-numeric")){
  GNUNET_CONFIGURATION_set_value_string(cfg,"s","v","x");struct Worker a={cfg,1,0,0},b={cfg,0,0,0};pthread_t ta,tb;void *ra=NULL,*rb=NULL;if(pthread_create(&ta,NULL,worker,&a)||pthread_create(&tb,NULL,worker,&b))return 10;if(pthread_join(ta,&ra)||pthread_join(tb,&rb)||ra||rb)return 11;
  char *end=NULL;const char *in="1,5";(void)strtof_l(in,&end,a.copied);printf("THREAD %zu %zu RETAINED %zu\n",a.consumed,b.consumed,(size_t)(end-in));freelocale(a.copied);freelocale(b.copied);
 }else if(0==strcmp(argv[1],"set-float")){
  if(argc!=4)return 12;float values[]={0.0f,-0.0f,1.25f,INFINITY,-INFINITY,NAN,-NAN,FLT_MAX,FLT_MIN,0.123456789f};int i=atoi(argv[3]);if(i<0||i>9)return 13;GNUNET_CONFIGURATION_set_value_float(cfg,"s","v",values[i]);value("FORMATTED",cfg,"s","v");
 }else return 8;
 GNUNET_CONFIGURATION_destroy(copy);GNUNET_CONFIGURATION_destroy(cfg);return 0;
}
