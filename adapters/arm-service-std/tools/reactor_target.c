/* Owned managed child; no GNUnet protocol or successful-service substitute. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
int main(int argc,char**argv){printf("{\"event\":\"actual-managed-child\",\"pid\":%d,\"argc\":%d,\"argvhex\":[",(int)getpid(),argc);for(int i=0;i<argc;i++){if(i)putchar(',');putchar('"');for(const unsigned char*p=(const unsigned char*)argv[i];*p;p++)printf("%02x",*p);putchar('"');}puts("]}");fflush(stdout);const char *ready=getenv("GNUNET_ARM_PAIR_CHILD_READY");if(ready){FILE *f=fopen(ready,"a");if(!f)return 4;fputs("actual-target-exec\n",f);fclose(f);}long ms=argc>1?strtol(argv[1],NULL,10):0;if(ms<0||ms>5000)return 2;struct timespec t={ms/1000,(ms%1000)*1000000};while(nanosleep(&t,&t)){if(errno!=EINTR)return 3;}return 0;}
