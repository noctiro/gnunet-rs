#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
int main(int argc,char**argv){const char*outpath=NULL;for(int i=1;i+1<argc;i++)if(!strcmp(argv[i],"--output"))outpath=argv[i+1];if(!outpath)return 2;
 int types[3],access[3],fdflags[3];struct stat st;for(int i=0;i<3;i++){types[i]=fstat(i,&st)?-1:(int)(st.st_mode&S_IFMT);int f=fcntl(i,F_GETFL);access[i]=f<0?-1:(f&O_ACCMODE);fdflags[i]=fcntl(i,F_GETFD);}
 struct sigaction pipe;sigset_t mask;if(sigaction(SIGPIPE,NULL,&pipe)||sigprocmask(SIG_SETMASK,NULL,&mask))return 3;
 const char*names=getenv("LISTEN_FDNAMES");if(!names)return 4;char*end;long fd=strtol(names,&end,10);if(*end||fd<0||fd>=1024)return 5;int readyflags=fcntl((int)fd,F_GETFD),fl=fcntl((int)fd,F_GETFL);int readytype=fstat((int)fd,&st)?-1:(int)(st.st_mode&S_IFMT);
 int close_error=close((int)fd)?errno:0;
 FILE*out=fopen(outpath,"w");if(!out)return 6;fprintf(out,"{\"event\":\"target-stdio\",\"types\":[%d,%d,%d],\"access\":[%d,%d,%d],\"flags\":[%d,%d,%d],\"readiness_fd\":%ld,\"readiness_type\":%d,\"readiness_cloexec\":%s,\"readiness_nonblock\":%s,\"pipe\":\"%s\",\"mask\":[",types[0],types[1],types[2],access[0],access[1],access[2],fdflags[0],fdflags[1],fdflags[2],fd,readytype,(readyflags&FD_CLOEXEC)?"true":"false",(fl&O_NONBLOCK)?"true":"false",pipe.sa_handler==SIG_IGN?"ignore":pipe.sa_handler==SIG_DFL?"default":"caught");int first=1;for(int i=1;i<64;i++)if(sigismember(&mask,i)==1){fprintf(out,"%s%d",first?"":",",i);first=0;}fprintf(out,"],\"readiness_close_errno\":%d}\n",close_error);return fclose(out)?8:0;}
