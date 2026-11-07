#include <platform.h>
#include <gnunet_util_lib.h>
#include <idn2.h>
#include <uninorm.h>
#include <unistr.h>
#include <unictype.h>
#include <unimetadata.h>
#include <unistring/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int nibble(int c) {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static void print(int rc,const unsigned char *p,size_t n) {
 printf("%d\t",rc);if(!rc)for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');
}
int main(int argc,char **argv) {
 if(argc==2 && !strcmp(argv[1],"--metadata")) {
  printf("libidn2=%s\nlibunistring=%x\nunicode=%x\n",idn2_check_version(NULL),_libunistring_version,_libunistring_unicode_version);return 0;
 }
 char line[131084];unsigned char bytes[65538];
 while(fgets(line,sizeof(line),stdin)) {
  size_t n=strcspn(line+2,"\r\n");if(n%2)return 2;
  n/=2;if(n>=sizeof(bytes))return 2;
  for(size_t i=0;i<n;i++) {int a=nibble(line[2+2*i]),b=nibble(line[3+2*i]);if(a<0||b<0)return 3;bytes[i]=(unsigned char)(a*16+b);}
  bytes[n]=0;char *out=NULL;int rc;
  if(line[0]=='A') {rc=idn2_to_ascii_8z((const char*)bytes,&out,25);print(rc,(unsigned char*)out,rc?0:strlen(out));idn2_free(out);}
  else if(line[0]=='U') {rc=idn2_to_unicode_8z8z((const char*)bytes,&out,16);print(rc,(unsigned char*)out,rc?0:strlen(out));idn2_free(out);}
  else if(line[0]=='N'||line[0]=='M') {size_t len=0;unsigned char *normalized=u8_normalize(UNINORM_NFC,bytes,n,NULL,&len);print(normalized?0:-200,normalized,normalized?len:0);free(normalized);}
  else if(line[0]=='P') {size_t count=0;uint32_t *cps=u8_to_u32(bytes,n,NULL,&count);if(!cps||count!=1)return 6;uint32_t cp=cps[0];const uc_script_t *sc=uc_script(cp);int script=0;if(sc){if(!strcmp(sc->name,"Greek"))script=1;else if(!strcmp(sc->name,"Hebrew"))script=2;else if(!strcmp(sc->name,"Hiragana"))script=3;else if(!strcmp(sc->name,"Katakana"))script=4;else if(!strcmp(sc->name,"Han"))script=5;}char props[128];snprintf(props,sizeof(props),"%d|%d|%s|%s|%d",uc_combining_class(cp),uc_is_general_category(cp,UC_CATEGORY_M),uc_bidi_category_name(uc_bidi_category(cp)),uc_joining_type_name(uc_joining_type(cp)),script);print(0,(unsigned char*)props,strlen(props));free(cps);}
  else if(line[0]=='W'||line[0]=='X') {size_t off=0,length=n;const unsigned char *payload=bytes;if(line[0]=='X'){if(n<2)return 2;off=((size_t)bytes[0]<<8)|bytes[1];payload+=2;length-=2;}char *name=GNUNET_DNSPARSER_parse_name((const char*)payload,length,&off);if(!name)print(-1,NULL,0);else {char prefix[32];int k=snprintf(prefix,sizeof(prefix),"%zu:",off);if(k<0||(size_t)k>=sizeof(prefix))return 7;printf("0\t");for(int j=0;j<k;j++)printf("%02x",(unsigned char)prefix[j]);for(size_t j=0;j<strlen(name);j++)printf("%02x",(unsigned char)name[j]);putchar('\n');GNUNET_free(name);}}
  else if(line[0]=='Y') {size_t off=0;struct GNUNET_DNSPARSER_Record record={0};int status=GNUNET_DNSPARSER_parse_record((const char*)bytes,n,&off,&record);if(status!=GNUNET_OK)print(-1,NULL,0);else {if(record.type!=5)return 7;char prefix[32];int k=snprintf(prefix,sizeof(prefix),"%zu:",off);if(k<0||(size_t)k>=sizeof(prefix))return 7;printf("0\t");for(int j=0;j<k;j++)printf("%02x",(unsigned char)prefix[j]);for(size_t j=0;j<strlen(record.data.hostname);j++)printf("%02x",(unsigned char)record.data.hostname[j]);putchar('\n');GNUNET_DNSPARSER_free_record(&record);}}
  else if(line[0]=='F') {if(n!=2||sizeof(struct GNUNET_TUN_DnsFlags)!=2)return 8;struct GNUNET_TUN_DnsFlags flags;memcpy(&flags,bytes,2);char text[160];int k=snprintf(text,sizeof(text),"%u|%u|%u|%u|%u|%u|%u|%u|%u|%u",flags.recursion_desired,flags.message_truncated,flags.authoritative_answer,flags.opcode,flags.query_or_response,flags.return_code,flags.checking_disabled,flags.authenticated_data,flags.zero,flags.recursion_available);if(k<0||(size_t)k>=sizeof(text))return 8;print(0,(unsigned char*)text,(size_t)k);}
  else if(line[0]=='G') {const unsigned values[]={GNUNET_TUN_DNS_CLASS_INTERNET,GNUNET_TUN_DNS_CLASS_CHAOS,GNUNET_TUN_DNS_CLASS_HESIOD,GNUNET_TUN_DNS_OPCODE_QUERY,GNUNET_TUN_DNS_OPCODE_INVERSE_QUERY,GNUNET_TUN_DNS_OPCODE_STATUS,GNUNET_TUN_DNS_RETURN_CODE_NO_ERROR,GNUNET_TUN_DNS_RETURN_CODE_FORMAT_ERROR,GNUNET_TUN_DNS_RETURN_CODE_SERVER_FAILURE,GNUNET_TUN_DNS_RETURN_CODE_NAME_ERROR,GNUNET_TUN_DNS_RETURN_CODE_NOT_IMPLEMENTED,GNUNET_TUN_DNS_RETURN_CODE_REFUSED,GNUNET_TUN_DNS_RETURN_CODE_YXDOMAIN,GNUNET_TUN_DNS_RETURN_CODE_YXRRSET,GNUNET_TUN_DNS_RETURN_CODE_NXRRSET,GNUNET_TUN_DNS_RETURN_CODE_NOT_AUTH,GNUNET_TUN_DNS_RETURN_CODE_NOT_ZONE};char text[128];size_t used=0;for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++){int k=snprintf(text+used,sizeof(text)-used,"%s%u",i?"|":"",values[i]);if(k<0||(size_t)k>=sizeof(text)-used)return 8;used+=(size_t)k;}print(0,(unsigned char*)text,used);}
  else if(line[0]=='H') {if(n!=12||sizeof(struct GNUNET_TUN_DnsHeader)!=12)return 8;struct GNUNET_TUN_DnsHeader header;memcpy(&header,bytes,12);unsigned char flags[2];memcpy(flags,&header.flags,2);char text[160];int k=snprintf(text,sizeof(text),"%u|%u|%u|%u|%u|%u",(unsigned)ntohs(header.id),((unsigned)flags[0]<<8)|flags[1],(unsigned)ntohs(header.query_count),(unsigned)ntohs(header.answer_rcount),(unsigned)ntohs(header.authority_rcount),(unsigned)ntohs(header.additional_rcount));if(k<0||(size_t)k>=sizeof(text))return 8;print(0,(unsigned char*)text,(size_t)k);}
  else if(line[0]=='L') {rc=GNUNET_DNSPARSER_check_label((const char*)bytes);printf("%d\t\n",rc);}
  else if(line[0]=='D') {rc=GNUNET_DNSPARSER_check_name((const char*)bytes);printf("%d\t\n",rc);}
  else return 4;
 }
 return ferror(stdin)?5:0;
}
