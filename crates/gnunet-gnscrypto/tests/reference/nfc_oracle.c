#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include <unistring/version.h>
int main(void) {
 fprintf(stderr,"libunistring=%x Unicode=%x\n",_libunistring_version,_libunistring_unicode_version);
 char *line=NULL;size_t cap=0;ssize_t n;
 while((n=getline(&line,&cap,stdin))>0) {
  if(n>0&&line[n-1]=='\n')line[--n]=0;
  if(n%2)return 2;char input[n/2+1];
  for(ssize_t i=0;i<n/2;i++){unsigned v;if(sscanf(line+2*i,"%2x",&v)!=1)return 3;input[i]=(char)v;}
  input[n/2]=0;char *out=GNUNET_GNSRECORD_string_normalize(input);if(!out)return 4;
  for(size_t i=0;i<strlen(out);i++)printf("%02x",(unsigned char)out[i]);puts("");GNUNET_free(out);
 }free(line);return 0;
}
