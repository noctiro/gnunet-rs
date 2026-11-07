/* Normal defined-safe public common_logging helpers. GNUNET_hex2b is omitted:
 * its sscanf %x destination is signed int*, a separate source-only audit. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <stddef.h>
static void row(const char*name,const char*value){printf("S %s ",name);for(const unsigned char*p=(const unsigned char*)value;*p;p++)printf("%02x",*p);putchar('\n');}
static void record(void *cls,enum GNUNET_ErrorType kind,const char *component,const char *date,const char *message){(void)cls;printf("R %d ",kind);for(const unsigned char*p=(const unsigned char*)component;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)date;*p;p++)printf("%02x",*p);putchar(' ');for(const unsigned char*p=(const unsigned char*)message;*p;p++)printf("%02x",*p);putchar('\n');}
int main(void){printf("PID %u\n",(unsigned)getpid());struct GNUNET_HashCode hash;struct GNUNET_ShortHashCode short_hash;struct GNUNET_Uuid uuid;struct GNUNET_CRYPTO_EddsaPublicKey ed;struct GNUNET_CRYPTO_EcdhePublicKey ec;struct GNUNET_PeerIdentity peer;memset(&hash,0,sizeof hash);memset(&short_hash,0xff,sizeof short_hash);memset(&uuid,0x25,sizeof uuid);for(unsigned i=0;i<sizeof ed;i++)((unsigned char*)&ed)[i]=(unsigned char)i;memcpy(&ec,&ed,sizeof ec);memcpy(&peer.public_key,&ed,sizeof ed);
 row("B2S",GNUNET_b2s("some data",9));row("H2S",GNUNET_h2s(&hash));row("H2S2",GNUNET_h2s2(&hash));row("HFULL",GNUNET_h2s_full(&hash));row("SHORT",GNUNET_sh2s(&short_hash));row("UUID",GNUNET_uuid2s(&uuid));row("P2S",GNUNET_p2s(&ed));row("P2S2",GNUNET_p2s2(&ed));row("E2S",GNUNET_e2s(&ec));row("E2S2",GNUNET_e2s2(&ec));row("I2S",GNUNET_i2s(&peer));row("I2S2",GNUNET_i2s2(&peer));row("IFULL",GNUNET_i2s_full(&peer));row("INULL",GNUNET_i2s(NULL));row("INULL2",GNUNET_i2s2(NULL));row("ANULL",GNUNET_a2s(NULL,0));
 struct sockaddr unknown={0};unknown.sa_family=127;row("UNSUPPORTED",GNUNET_a2s(&unknown,sizeof unknown));struct sockaddr_in a4={0};a4.sin_family=AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
 a4.sin_len=sizeof a4;
#endif
 inet_pton(AF_INET,"127.0.0.42",&a4.sin_addr);row("V4",GNUNET_a2s((void*)&a4,sizeof a4));a4.sin_port=htons(65535);row("V4PORT",GNUNET_a2s((void*)&a4,sizeof a4));row("V4BAD",GNUNET_a2s((void*)&a4,sizeof a4-1));
 const char *names[]={"::","::1","::192.0.2.1","::ffff:192.0.2.1","2001:db8:0:1:0:0:0:1","1:0:0:2:0:0:3:4"};for(unsigned i=0;i<sizeof names/sizeof names[0];i++){struct sockaddr_in6 a6={0};a6.sin6_family=AF_INET6;
#if HAVE_SOCKADDR_IN6_SIN6_LEN
 a6.sin6_len=sizeof a6;
#endif
 if(inet_pton(AF_INET6,names[i],&a6.sin6_addr)!=1)return 2;row("V6",GNUNET_a2s((void*)&a6,sizeof a6));a6.sin6_port=htons(53);row("V6PORT",GNUNET_a2s((void*)&a6,sizeof a6));row("V6BAD",GNUNET_a2s((void*)&a6,sizeof a6-1));}
 struct sockaddr_un un={0};un.sun_family=AF_UNIX;memcpy(un.sun_path,"/owned/file",12);row("UNIX",GNUNET_a2s((void*)&un,sizeof un));memset(un.sun_path,0,sizeof un.sun_path);memcpy(un.sun_path+1,"abstract",9);row("ABSTRACT",GNUNET_a2s((void*)&un,sizeof un));row("UNBOUND",GNUNET_a2s((void*)&un,sizeof(sa_family_t)));
 struct GNUNET_AsyncScopeId scope,fresh;struct GNUNET_AsyncScopeSave old,now;memset(&scope,0x33,sizeof scope);GNUNET_async_scope_get(&now);printf("SCOPE_ROOT %d\n",now.have_scope==GNUNET_NO);GNUNET_async_scope_enter(&scope,&old);GNUNET_async_scope_get(&now);printf("SCOPE_ENTER %d\n",now.have_scope==GNUNET_YES&&!memcmp(&now.scope_id,&scope,sizeof scope));GNUNET_async_scope_fresh(&fresh);struct GNUNET_AsyncScopeSave saved;GNUNET_async_scope_enter(&fresh,&saved);GNUNET_async_scope_get(&now);printf("SCOPE_FRESH %d\n",now.have_scope==GNUNET_YES&&!memcmp(&now.scope_id,&fresh,sizeof fresh));GNUNET_async_scope_restore(&saved);GNUNET_async_scope_restore(&old);GNUNET_async_scope_get(&now);printf("SCOPE_RESTORE %d\n",now.have_scope==GNUNET_NO);
 unsigned char bytes[]={0,1,2,127,128,254,255};int folds[]={0,3,-3,INT_MIN};for(unsigned i=0;i<4;i++)for(int inverse=0;inverse<2;inverse++){printf("PRINT %d %d\n",folds[i],inverse);GNUNET_print_bytes(bytes,sizeof bytes,folds[i],inverse);puts("PRINT_END");}
 GNUNET_log_setup("owned-helper","DEBUG",NULL);GNUNET_logger_add(&record,NULL);GNUNET_log_config_missing(GNUNET_ERROR_TYPE_ERROR,"own%section","missing%key");GNUNET_log_config_invalid(GNUNET_ERROR_TYPE_WARNING,"own%section","key","required%data");GNUNET_log_skip(3,GNUNET_NO);printf("SKIP %d\n",GNUNET_get_log_skip());GNUNET_log_skip(0,GNUNET_YES);printf("SKIP %d\n",GNUNET_get_log_skip());GNUNET_logger_remove(&record,NULL);return 0;}
