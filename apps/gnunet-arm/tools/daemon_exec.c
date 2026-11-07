/* Owned prefix: records only its own PID, arms a private failure watchdog, then
 * execs the unchanged normal ARM daemon. No system/service configuration edits. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc,char **argv){const char *path=getenv("OWNED_ARM_CLI_EXEC_TRACE");if(argc<2||!path)return 2;int fd=open(path,O_WRONLY|O_CREAT|O_APPEND,0600);if(fd<0)return 3;char line[64];int n=snprintf(line,sizeof line,"%ld\n",(long)getpid());if(n<0||write(fd,line,(size_t)n)!=n||close(fd))return 4;alarm(8);execvp(argv[1],argv+1);return 5;}
