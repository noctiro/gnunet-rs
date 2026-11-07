/* Harmless test child only, not a production service or GNUnet implementation.
 * The isolated Rust launcher exclusively supplies exactly one readiness WRITE
 * descriptor to this newly exec'd process. Only that original owner is closed.
 */
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
static void hex(FILE *out,const char *s){for(const unsigned char*p=(const unsigned char*)s;*p;p++)fprintf(out,"%02x",*p);}
int main(int argc,char **argv){const char *output=NULL;long hold=0;int markers=0,early=0;
 for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--output")&&i+1<argc)output=argv[++i];else if(!strcmp(argv[i],"--hold-ms")&&i+1<argc)hold=strtol(argv[++i],NULL,10);else if(!strcmp(argv[i],"--markers"))markers=1;else if(!strcmp(argv[i],"--release-before-wait"))early=1;}
 const char*count=getenv("LISTEN_FDS"),*names=getenv("LISTEN_FDNAMES"),*control=getenv("GNUNET_OS_CONTROL_PIPE");if(!output||!count||strcmp(count,"1")||!names)return 2;
 char*end;long fd=strtol(names,&end,10);if(*end||fd<3||fd>=1024||fcntl((int)fd,F_GETFD)<0)return 3;
 struct stat st[3];for(int i=0;i<3;i++)if(fstat(i,&st[i]))return 4;
 FILE*out=fopen(output,"w");if(!out)return 5;
 fprintf(out,"{\"event\":\"started\",\"pid\":%d,\"argv\":[",(int)getpid());for(int i=0;i<argc;i++){fprintf(out,"%s\"",i?",":"");hex(out,argv[i]);fputc('"',out);}fprintf(out,"],\"stdio_types\":[%u,%u,%u],\"listen\":\"",(unsigned)(st[0].st_mode&S_IFMT),(unsigned)(st[1].st_mode&S_IFMT),(unsigned)(st[2].st_mode&S_IFMT));hex(out,names);fprintf(out,"\",\"control\":\"");hex(out,control?control:"");fprintf(out,"\"}\n");fflush(out);
 if(markers){char b[4]={0};ssize_t n=read(0,b,3);if(n<0)return 6;fprintf(out,"{\"stdin\":\"");hex(out,b);fprintf(out,"\"}\n");write(1,"CHILD_STDOUT\n",13);write(2,"CHILD_STDERR\n",13);}
 if(early){if(close((int)fd))return 7;fprintf(out,"{\"event\":\"released\"}\n");fflush(out);}
 struct timespec t={hold/1000,(hold%1000)*1000000};while(nanosleep(&t,&t)){if(errno!=EINTR)return 9;}
 if(!early&&close((int)fd))return 7;fprintf(out,"{\"event\":\"released\"}\n");return fclose(out)?8:0;
}
