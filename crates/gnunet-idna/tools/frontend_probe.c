/* Calls the actual normal C GNUnet public name APIs; no extracted functions. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned nibble(char c) {
  assert((c>='0'&&c<='9')||(c>='a'&&c<='f'));
  return c<='9'?(unsigned)(c-'0'):(unsigned)(c-'a'+10);
}
int main(int argc,char **argv) {
  assert(argc==3);GNUNET_log_setup("idna-frontend-oracle","ERROR",NULL);
  size_t n=strlen(argv[1]);assert(!(n%2)&&n<=8192);n/=2;
  char input[4097];for(size_t i=0;i<n;i++)input[i]=(char)(16*nibble(argv[1][2*i])+nibble(argv[1][2*i+1]));input[n]=0;
  char *end=NULL;unsigned long cap=strtoul(argv[2],&end,10);assert(end&&!*end&&cap<=4096);
  char output[4096];memset(output,0xa5,sizeof(output));size_t off=0;
  int label=GNUNET_DNSPARSER_check_label(input),name=GNUNET_DNSPARSER_check_name(input);
  int added=GNUNET_DNSPARSER_builder_add_name(output,(size_t)cap,&off,input);assert(off<=sizeof(output));
  printf("{\"label_rc\":%d,\"name_rc\":%d,\"builder_rc\":%d,\"off\":%zu,\"wire\":\"",label,name,added,off);
  for(size_t i=0;i<off;i++)printf("%02x",(unsigned char)output[i]);puts("\"}");return 0;
}
