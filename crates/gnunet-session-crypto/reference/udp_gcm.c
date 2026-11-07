/* Known fixture keys, exact original communicator functions and normal libraries.
 * No scheduler, service, socket, source rewriting or runtime RNG interposition. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include <gcrypt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gnunet_udp_gcm_profile.h"

static int unhex(const char *s,unsigned char *out,size_t cap){
 if(!strcmp(s,"-"))return 0;size_t n=strlen(s);if(n%2||n/2>cap)return -1;
 for(size_t i=0;i<n/2;i++){char part[3]={s[2*i],s[2*i+1],0};char *end=NULL;unsigned long value=strtoul(part,&end,16);if(end!=part+2)return -1;out[i]=(unsigned char)value;}return (int)(n/2);
}
static void field(const void *data,size_t n){const unsigned char*p=data;putchar(' ');if(!n){putchar('-');return;}for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
static int chunks(gcry_cipher_hd_t cipher,unsigned char *out,const unsigned char *data,size_t n,size_t a,size_t b){
 if(a>n||b>n-a)return -1;
 if(gcry_cipher_encrypt(cipher,out,a,data,a))return -1;
 if(gcry_cipher_encrypt(cipher,out+a,b,data+a,b))return -1;
 return gcry_cipher_encrypt(cipher,out+a+b,n-a-b,data+a+b,n-a-b)?-1:0;
}
int main(void){
 char *line=NULL;size_t capacity=0;GNUNET_log_setup("udp-gcm-component","ERROR",NULL);if(NULL==gcry_check_version(NULL))return 2;
 if(AES_KEY_SIZE!=32||AES_IV_SIZE!=12||GCM_TAG_SIZE!=16)return 2;
 while(getline(&line,&capacity,stdin)>0){char*v[10],*save=NULL;int argc=0;for(char*t=strtok_r(line," \t\r\n",&save);t;t=strtok_r(NULL," \t\r\n",&save)){if(argc==10)return 3;v[argc++]=t;}if(!argc)continue;
 unsigned char master[32],key[AES_KEY_SIZE],iv[AES_IV_SIZE],aad[4096],data[65536],out[65584],tag[GCM_TAG_SIZE],packet[65584];int n=0,an=0;gcry_cipher_hd_t cipher=NULL;
 if(!strcmp(v[0],"META")&&argc==1){printf("META %u %u %u %zu %zu %zu %zu %zu %zu %zu %zu %s\n",AES_KEY_SIZE,AES_IV_SIZE,GCM_TAG_SIZE,sizeof(struct InitialKX),sizeof(struct UDPConfirmation),sizeof(struct UDPAck),sizeof(struct UDPBox),offsetof(struct UDPBox,gcm_tag),offsetof(struct UDPConfirmation,monotonic_time),offsetof(struct UDPAck,cmac),sizeof(struct GNUNET_ShortHashCode),gcry_check_version(NULL));continue;}
 if(!strcmp(v[0],"GCM")&&argc==7){if(unhex(v[1],key,32)!=32||unhex(v[2],iv,12)!=12||(an=unhex(v[3],aad,sizeof aad))<0||(n=unhex(v[4],data,sizeof data))<0||n>65535)return 3;size_t a=strtoul(v[5],NULL,10),b=strtoul(v[6],NULL,10);
 if(gcry_cipher_open(&cipher,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_GCM,0)||gcry_cipher_setkey(cipher,key,32)||gcry_cipher_setiv(cipher,iv,12)||gcry_cipher_authenticate(cipher,aad,an)||chunks(cipher,out,data,n,a,b)||gcry_cipher_gettag(cipher,tag,16))return 4;
 printf("GCM 1");field(out,n);field(tag,16);puts("");gcry_cipher_close(cipher);continue;}
 if(!strcmp(v[0],"GCM_OPEN")&&argc==6){if(unhex(v[1],key,32)!=32||unhex(v[2],iv,12)!=12||(an=unhex(v[3],aad,sizeof aad))<0||(n=unhex(v[4],data,sizeof data))<0||n>65535||unhex(v[5],tag,16)!=16)return 3;
 if(gcry_cipher_open(&cipher,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_GCM,0)||gcry_cipher_setkey(cipher,key,32)||gcry_cipher_setiv(cipher,iv,12)||gcry_cipher_authenticate(cipher,aad,an)||gcry_cipher_decrypt(cipher,out,n,data,n))return 4;
 int ok=0==gcry_cipher_checktag(cipher,tag,16);printf("GCM_OPEN %d",ok);if(ok)field(out,n);puts("");gcry_cipher_close(cipher);continue;}
 if(argc<5||unhex(v[1],master,32)!=32||(n=unhex(v[3],data,sizeof data))<0||n>65535)return 3;
 unsigned long long parsed=strtoull(v[2],NULL,10);if(parsed>UINT32_MAX)return 3;uint32_t serial=(uint32_t)parsed;struct SharedSecret secret;memset(&secret,0,sizeof secret);memcpy(&secret.master,master,32);
 if(!strcmp(v[0],"UDP_OPEN")&&argc==5){if(unhex(v[4],tag,16)!=16)return 3;int ok=GNUNET_OK==try_decrypt(&secret,tag,serial,(const char*)data,n,(char*)out);printf("UDP_OPEN %d",ok);if(ok)field(out,n);puts("");continue;}
 if(strcmp(v[0],"UDP")||argc!=8)return 3;size_t a=strtoul(v[4],NULL,10),b=strtoul(v[5],NULL,10);int box=0==strcmp(v[6],"BOX"),kx=0==strcmp(v[6],"KX");
 if((box&&(!serial||!n))||(kx&&(serial||n<sizeof(struct UDPConfirmation)))||(!box&&!kx))return 3;
 get_iv_key(&secret.master,serial,(char*)key,(char*)iv);struct GNUNET_ShortHashCode kid;get_kid(&secret.master,serial,&kid);calculate_cmac(&secret);setup_cipher(&secret.master,serial,&cipher);
 if(chunks(cipher,out,data,n,a,b)||gcry_cipher_gettag(cipher,tag,sizeof tag))return 4;gcry_cipher_close(cipher);
 size_t prefix;if(box){struct UDPBox header;header.kid=kid;memcpy(header.gcm_tag,tag,sizeof tag);prefix=sizeof header;memcpy(packet,&header,prefix);}else{struct InitialKX header;if(unhex(v[7],(unsigned char*)&header.enc,32)!=32)return 3;memcpy(header.gcm_tag,tag,sizeof tag);prefix=sizeof header;memcpy(packet,&header,prefix);}
 memcpy(packet+prefix,out,n);unsigned char decoded[65536];if(GNUNET_OK!=try_decrypt(&secret,tag,serial,(const char*)out,n,(char*)decoded))return 4;
 printf("UDP 1");field(key,sizeof key);field(iv,sizeof iv);field(&kid,sizeof kid);field(&secret.cmac,sizeof secret.cmac);field(out,n);field(tag,sizeof tag);field(packet,prefix+n);field(decoded,n);puts("");
 }
 free(line);return 0;
}
