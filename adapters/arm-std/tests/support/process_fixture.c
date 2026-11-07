/* Finite owned-target observation fixture; no GNUnet implementation/backend. */
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static void hex(FILE *f,const unsigned char *s,size_t n){for(size_t i=0;i<n;i++)fprintf(f,"%02x",s[i]);}
static int exact(int fd,void *buffer,size_t n){size_t pos=0;while(pos<n){struct pollfd p={fd,POLLIN,0};int ready=poll(&p,1,3000);if(ready<=0)return -1;ssize_t got=read(fd,(char*)buffer+pos,n-pos);if(got<0&&(errno==EINTR||errno==EAGAIN))continue;if(got<=0)return -1;pos+=(size_t)got;}return 0;}
int main(int argc,char **argv){
 const char *output=getenv("GNUNET_PROCESS_TEST_OUTPUT"),*mode=getenv("GNUNET_PROCESS_TEST_MODE");if(!output||!mode)return 2;
 FILE *f=fopen(output,"a");if(!f)return 3;
 fprintf(f,"argc=%d\n",argc);for(int i=0;i<argc;i++){fprintf(f,"arg%d=",i);hex(f,(const unsigned char*)argv[i],strlen(argv[i]));fputc('\n',f);}
 char cwd[4096];if(getcwd(cwd,sizeof(cwd))){fputs("cwd=",f);hex(f,(unsigned char*)cwd,strlen(cwd));fputc('\n',f);}
 const char *value=getenv("GNUNET_PROCESS_TEST_VALUE");fputs("value=",f);if(value)hex(f,(const unsigned char*)value,strlen(value));else fputs("unset",f);fputc('\n',f);
 if(!strcmp(mode,"accept")){
  const char *names=getenv("LISTEN_FDNAMES"),*count=getenv("LISTEN_FDS");if(!names||!count)return 4;char *copy=strdup(names),*save=NULL;int seen=0;
  for(char *name=strtok_r(copy,":",&save);name;name=strtok_r(NULL,":",&save)){
   int fd=atoi(name);struct pollfd p={fd,POLLIN,0};if(poll(&p,1,3000)<=0)return 5;int accepted=accept(fd,NULL,NULL);if(accepted<0)return 6;
   char bytes[5];if(exact(accepted,bytes,5)||memcmp(bytes,"queue",5))return 7;if(write(accepted,"child:queue",11)!=11)return 8;close(accepted);seen++;
  }free(copy);fprintf(f,"accepted=%d\n",seen);if(seen!=atoi(count))return 9;
 }else if(!strcmp(mode,"map")){
  const char *a=getenv("GNUNET_PROCESS_TEST_FD_A"),*b=getenv("GNUNET_PROCESS_TEST_FD_B");if(!a||!b)return 10;unsigned char pair[2];if(exact(atoi(a),pair,1)||exact(atoi(b),pair+1,1))return 11;fputs("map=",f);hex(f,pair,2);fputc('\n',f);
 }else if(!strcmp(mode,"stdin")){
  unsigned char bytes[3];if(exact(0,bytes,3))return 12;fputs("stdin=",f);hex(f,bytes,3);fputc('\n',f);
 }else if(!strcmp(mode,"control")||!strcmp(mode,"close-control")||!strcmp(mode,"hold-control")||!strcmp(mode,"drain-control")){
  const char *raw=getenv("GNUNET_OS_CONTROL_PIPE");if(!raw)return 13;int fd=(int)strtol(raw,NULL,16);
  if(!strcmp(mode,"close-control"))close(fd);
  fputs("ready=1\n",f);fflush(f);
  if(!strcmp(mode,"control")){unsigned char byte;if(exact(fd,&byte,1))return 14;fprintf(f,"control=%u\n",byte);fflush(f);raise((int)byte);return 15;}
  if(!strcmp(mode,"drain-control")){
   const char *release=getenv("GNUNET_PROCESS_TEST_RELEASE");if(!release)return 17;
   unsigned attempts=0;while(access(release,F_OK)){if(++attempts>3000)return 18;usleep(1000);}
   unsigned char buffer[4096];ssize_t n;do{n=read(fd,buffer,sizeof(buffer));}while(n>0||(n<0&&errno==EINTR));
   if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK){return 19;}
   fputs("drained=1\n",f);
   fflush(f);
   for(unsigned i=0;i<2;i++){unsigned char byte;if(exact(fd,&byte,1))return 20;fprintf(f,"control=%u\n",byte);fflush(f);if(byte)raise((int)byte);}
   return 21;
  }
  const char *hold=getenv("GNUNET_PROCESS_TEST_HOLD_MS");long ms=hold?strtol(hold,NULL,10):5000;if(ms<1||ms>30000)return 16;
  struct timespec delay={ms/1000,(ms%1000)*1000000};while(nanosleep(&delay,&delay)&&errno==EINTR){};
 }
 fclose(f);return 0;
}
