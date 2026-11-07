/* Owned finite target: actual TERM handler plus delayed exit, no daemon emulation. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
static volatile sig_atomic_t term;
static void handle(int value){(void)value;term=1;}
int main(void){const char *path=getenv("GNUNET_ARM_DRAIN_TRACE");if(!path)return 2;struct sigaction action={0};action.sa_handler=handle;sigemptyset(&action.sa_mask);if(sigaction(SIGTERM,&action,NULL))return 3;FILE *f=fopen(path,"a");if(!f)return 4;fputs("READY\n",f);fflush(f);unsigned ticks=0;while(!term&&ticks++<3000){struct timespec delay={0,1000000};nanosleep(&delay,NULL);}if(!term)return 5;fputs("TERM\n",f);fflush(f);struct timespec delay={0,500000000};while(nanosleep(&delay,&delay)&&errno==EINTR){}fputs("EXIT\n",f);fclose(f);return 0;}
