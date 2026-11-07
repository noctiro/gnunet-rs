/* Actual exec target for native argv/readiness observations only. */
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef OWNED_TAG
#define OWNED_TAG "target"
#endif
int main(int argc,char**argv){const char*outpath=getenv("ARM_COMMAND_OUTPUT"),*release=getenv("ARM_COMMAND_RELEASE"),*names=getenv("LISTEN_FDNAMES");if(!outpath||!release||!names)return 2;char*end;long fd=strtol(names,&end,10);if(*end||fd<0||fd>=1024)return 3;struct stat st;int type=fstat((int)fd,&st)?-1:(int)(st.st_mode&S_IFMT);int flags=fcntl((int)fd,F_GETFL),clo=fcntl((int)fd,F_GETFD);
 FILE*out=fopen(outpath,"w");if(!out)return 4;fprintf(out,"{\"event\":\"actual-target\",\"tag\":\"%s\",\"pid\":%d,\"argv\":[",OWNED_TAG,(int)getpid());for(int i=0;i<argc;i++){fprintf(out,"%s\"",i?",":"");for(const unsigned char*p=(const unsigned char*)argv[i];*p;p++)fprintf(out,"%02x",*p);fputc('"',out);}fprintf(out,"],\"readiness_type\":%d,\"readiness_nonblock\":%s,\"readiness_cloexec\":%s}\n",type,(flags&O_NONBLOCK)?"true":"false",(clo&FD_CLOEXEC)?"true":"false");if(fclose(out))return 5;
 const char*byte=getenv("ARM_COMMAND_READY_BYTE");if(byte&&strcmp(byte,"0")){unsigned char b=42;if(1!=write((int)fd,&b,1))return 6;}
 const char*ack=getenv("ARM_COMMAND_ACK");if(ack){unsigned tries=0;while(access(ack,F_OK)){if(++tries>500)return 12;struct timespec pause={0,10000000};while(nanosleep(&pause,&pause)){if(errno!=EINTR)return 13;}}}
 const char*hold=getenv("ARM_COMMAND_HOLD_MS");long ms=hold?strtol(hold,NULL,10):0;if(ms<0||ms>2000)return 7;struct timespec t={ms/1000,(ms%1000)*1000000};while(nanosleep(&t,&t)){if(errno!=EINTR)return 8;}FILE*done=fopen(release,"w");if(!done)return 9;if(fclose(done))return 10;if(close((int)fd))return 11;const char*code=getenv("ARM_COMMAND_EXIT");return code?atoi(code):0;}
