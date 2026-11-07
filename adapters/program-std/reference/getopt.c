/* Unmodified normal GNUNET_GETOPT_run public API, safe owned descriptors. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int cleaned;
static void hex(const char*s){if(!s){putchar('-');return;}for(const unsigned char*p=(const unsigned char*)s;*p;p++)printf("%02x",*p);}
static void cleaner(void*cls){(void)cls;cleaned++;}
static int process(struct GNUNET_GETOPT_CommandLineProcessorContext*ctx,void*cls,const char*name,const char*value){(void)cls;printf("C ");hex(name);putchar(' ');hex(value);printf(" %u",ctx->currentArgument);for(unsigned i=0;i<ctx->argc;i++){putchar(' ');hex(ctx->argv[i]);}putchar('\n');if(!strcmp(name,"exclusive"))return 0;if(value&&!strcmp(value,"fail"))return -1;return 1;}
#define S(c,n,a,m,e,k) {.shortName=c,.name=n,.description="test",.require_argument=a,.option_mandatory=m,.option_exclusive=e,.processor=process,.cleaner=k}
int main(int argc,char**argv){const char*p=getenv("OWNED_GETOPT_PROFILE");if(!p)p="base";
 struct GNUNET_GETOPT_CommandLineOption base[]={S('a',"alpha",0,0,0,cleaner),S('b',"beta",1,0,0,cleaner),S('x',"exclusive",0,0,1,NULL),S('m',"must",0,0,0,NULL),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption mandatory[]={S('a',"alpha",0,0,0,cleaner),S('b',"beta",1,0,0,cleaner),S('x',"exclusive",0,0,1,NULL),S('m',"must",0,1,0,NULL),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption optional[]={S('o',"optional",2,0,0,cleaner),S('a',"alpha",0,0,0,cleaner),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption longonly[]={S(0,"first",0,0,0,cleaner),S(0,"second",1,0,0,cleaner),S('a',"alpha",0,0,0,NULL),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption question[]={S('?',"question",0,0,0,cleaner),S('a',"alpha",0,0,0,cleaner),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption require[]={S('+',"plus",0,0,0,cleaner),S('a',"alpha",0,0,0,cleaner),S('b',"beta",1,0,0,NULL),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption order[]={S('-',"minus",0,0,0,cleaner),S(1,"position",0,0,0,cleaner),S('a',"alpha",0,0,0,NULL),GNUNET_GETOPT_OPTION_END};
 struct GNUNET_GETOPT_CommandLineOption w[]={S('W',"world",0,0,0,cleaner),S(';',"semicolon",0,0,0,cleaner),S('a',"alpha",0,0,0,NULL),S('b',"beta",1,0,0,NULL),S('c',"betamax",0,0,0,NULL),GNUNET_GETOPT_OPTION_END};
 const struct GNUNET_GETOPT_CommandLineOption*spec=base;if(!strcmp(p,"mandatory"))spec=mandatory;else if(!strcmp(p,"optional"))spec=optional;else if(!strcmp(p,"longonly"))spec=longonly;else if(!strcmp(p,"question"))spec=question;else if(!strcmp(p,"require"))spec=require;else if(!strcmp(p,"return"))spec=order;else if(!strcmp(p,"W"))spec=w;
 int result=GNUNET_GETOPT_run("owned summary",spec,(unsigned)argc,argv);printf("RET %d CLEAN %d\nARGV",result,cleaned);for(int i=0;i<argc;i++){putchar(' ');hex(argv[i]);}putchar('\n');return 0;}
