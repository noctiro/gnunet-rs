#include "platform.h"
#include "gnunet_util_lib.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned nibble(char c){assert((c>='0'&&c<='9')||(c>='a'&&c<='f'));return c<='9'?c-'0':c-'a'+10;}
static void hex(const void *p,size_t n){const unsigned char*b=p;for(size_t i=0;i<n;i++)printf("%02x",b[i]);}
int main(int argc,char**argv){assert(argc==3);unsigned max=(unsigned)strtoul(argv[2],NULL,10);assert(max>=12&&max<=512);GNUNET_log_setup("parse-pack-audit","ERROR",NULL);size_t n=strlen(argv[1]);assert(!(n%2)&&n<8192);n/=2;unsigned char input[4096]={0};for(size_t i=0;i<n;i++)input[i]=16*nibble(argv[1][2*i])+nibble(argv[1][2*i+1]);struct GNUNET_DNSPARSER_Packet *p=GNUNET_DNSPARSER_parse((char*)input,n);if(!p){puts("{\"parsed\":false}");return 0;}char*wire=NULL;size_t length=0;int rc=GNUNET_DNSPARSER_pack(p,max,&wire,&length);printf("{\"native_name\":\"");if(p->num_queries)hex(p->queries[0].name,strlen(p->queries[0].name));printf("\",\"rc\":%d,\"wire\":\"",rc);hex(wire,length);puts("\"}");GNUNET_free(wire);GNUNET_DNSPARSER_free_packet(p);return 0;}
