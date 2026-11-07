#include "platform.h"
#include "gnunet_util_lib.h"
#include <locale.h>
#include <assert.h>
int main(void){assert(setlocale(LC_ALL,"C"));for(unsigned a=0;a<256;a++)for(unsigned b=0;b<256;b++){char in[3]={(char)a,(char)b,0};unsigned char out=0xa5;size_t n=GNUNET_DNSPARSER_hex_to_bin(in,&out);assert(n<=1);if(n)printf("%02x%02x\t%02x\n",a,b,out);}return 0;}
