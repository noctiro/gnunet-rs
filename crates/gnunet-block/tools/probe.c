/* Test-only control stream. Calls unchanged normal C block/group/crypto APIs. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_block_group_lib.h"
#include "gnunet_block_plugin.h"
#include "gnunet_hello_uri_lib.h"
static void hex(const void *data,size_t n){const unsigned char *p=data;for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
static unsigned char *unhex(const char *s,size_t *n){if(!s||!strcmp(s,"-")){*n=0;return NULL;}*n=strlen(s)/2;GNUNET_assert(strlen(s)%2==0);unsigned char *out=calloc(*n+1,1);for(size_t i=0;i<*n;i++){unsigned v;GNUNET_assert(sscanf(s+i*2,"%2x",&v)==1);out[i]=v;}return out;}
static unsigned destroyed;
static enum GNUNET_GenericReturnValue merge_no(struct GNUNET_BLOCK_Group *a,const struct GNUNET_BLOCK_Group *b){(void)a;(void)b;return GNUNET_NO;}
static void destroy_dummy(struct GNUNET_BLOCK_Group *g){destroyed++;GNUNET_free(g);}
int main(void){
 GNUNET_log_setup("block-oracle","ERROR",NULL);
 struct GNUNET_CONFIGURATION_Handle *cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());
 GNUNET_CONFIGURATION_set_value_number(cfg,"REVOCATION","WORKBITS",0);
 GNUNET_CONFIGURATION_set_value_string(cfg,"REVOCATION","EPOCH_DURATION","1 d");
 struct GNUNET_BLOCK_Context *ctx=GNUNET_BLOCK_context_create(cfg);GNUNET_assert(ctx);
 char *line=NULL;size_t allocated=0;ssize_t len;
 while((len=getline(&line,&allocated,stdin))>0){
  char *save=NULL,*op=strtok_r(line," \n",&save);if(!op)continue;
  if(!strcmp(op,"S")){unsigned count=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),k=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);printf("S %zu\n",GNUNET_BLOCK_GROUP_compute_bloomfilter_size(count,k));}
  else if(!strcmp(op,"M")){uint32_t nonce=(uint32_t)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t n;unsigned char *in=unhex(strtok_r(NULL," \n",&save),&n);GNUNET_assert(n==64);struct GNUNET_HashCode out;GNUNET_BLOCK_mingle_hash((const void*)in,nonce,&out);printf("M ");hex(&out,sizeof out);puts("");free(in);}
  else if(!strcmp(op,"P")){size_t sn,n;unsigned char *salt=unhex(strtok_r(NULL," \n",&save),&sn),*in=unhex(strtok_r(NULL," \n",&save),&n);GNUNET_assert(sn==16);struct GNUNET_HashCode out;GNUNET_CRYPTO_pow_hash((const void*)salt,in?in:(const unsigned char*)"",n,&out);printf("P ");hex(&out,sizeof out);puts("");free(salt);free(in);}
  else if(!strcmp(op,"T")){
   char *bits=strtok_r(NULL," \n",&save),*epoch=strtok_r(NULL," \n",&save);GNUNET_BLOCK_context_destroy(ctx);GNUNET_CONFIGURATION_destroy(cfg);cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());if(strcmp(bits,"-"))GNUNET_CONFIGURATION_set_value_number(cfg,"REVOCATION","WORKBITS",strtoull(bits,NULL,10));if(strcmp(epoch,"-")){char buffer[80];snprintf(buffer,sizeof buffer,"%s us",epoch);GNUNET_CONFIGURATION_set_value_string(cfg,"REVOCATION","EPOCH_DURATION",buffer);}ctx=GNUNET_BLOCK_context_create(cfg);GNUNET_assert(ctx);puts("T");
  }
  else if(!strcmp(op,"E")){
   unsigned kind=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t sn,n;unsigned char *seed=unhex(strtok_r(NULL," \n",&save),&sn),*region=unhex(strtok_r(NULL," \n",&save),&n);GNUNET_assert(sn==32&&n>=8&&ntohl(((const struct GNUNET_CRYPTO_SignaturePurpose*)region)->size)==n);unsigned char public[32],sig[64];
   if(kind==65536){GNUNET_CRYPTO_ecdsa_key_get_public((const void*)seed,(void*)public);GNUNET_assert(GNUNET_OK==GNUNET_CRYPTO_ecdsa_sign_((const void*)seed,(const void*)region,(void*)sig));}
   else{GNUNET_assert(kind==65556);GNUNET_CRYPTO_eddsa_key_get_public((const void*)seed,(void*)public);GNUNET_assert(GNUNET_OK==GNUNET_CRYPTO_eddsa_sign_((const void*)seed,(const void*)region,(void*)sig));}printf("E ");hex(public,32);printf(" ");hex(sig,64);puts("");free(seed);free(region);
  }
  else if(!strcmp(op,"H")){
   size_t sn;unsigned char *seed=unhex(strtok_r(NULL," \n",&save),&sn);GNUNET_assert(sn==32);struct GNUNET_TIME_Absolute expiration={strtoull(strtok_r(NULL," \n",&save),NULL,10)};struct GNUNET_HELLO_Builder *builder=GNUNET_HELLO_builder_new();GNUNET_HELLO_builder_add_address(builder,"tcp://127.0.0.1:1234");GNUNET_HELLO_builder_add_address(builder,"udp://[::1]:9876");struct {struct GNUNET_CRYPTO_SignaturePurpose purpose;struct GNUNET_TIME_AbsoluteNBO expiration;struct GNUNET_HashCode hash;} signed_region;signed_region.purpose.size=htonl(sizeof signed_region);signed_region.purpose.purpose=htonl(7);signed_region.expiration=GNUNET_TIME_absolute_hton(expiration);GNUNET_HELLO_builder_hash_addresses(builder,&signed_region.hash);struct GNUNET_PeerIdentity pid;struct GNUNET_CRYPTO_EddsaSignature sig;GNUNET_CRYPTO_eddsa_key_get_public((const void*)seed,&pid.public_key);GNUNET_assert(GNUNET_OK==GNUNET_CRYPTO_eddsa_sign_((const void*)seed,&signed_region.purpose,&sig));size_t n=GNUNET_HELLO_get_builder_to_block_size(builder);char *block=GNUNET_malloc(n);GNUNET_HELLO_builder_to_block(builder,&pid,&sig,expiration,block);printf("H ");hex(block,n);puts("");GNUNET_free(block);GNUNET_HELLO_builder_free(builder);free(seed);
  }
  else if(!strcmp(op,"B")){
   unsigned size=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),k=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t rn,hn;unsigned char *raw=unhex(strtok_r(NULL," \n",&save),&rn),*hash=unhex(strtok_r(NULL," \n",&save),&hn);GNUNET_assert(hn==64&&raw);
   struct GNUNET_BLOCK_Group *g=GNUNET_BLOCK_GROUP_bf_create(NULL,size,k,GNUNET_BLOCK_TYPE_TEST,raw,rn);printf("B %d",g!=NULL);
   if(g){int a=GNUNET_BLOCK_GROUP_bf_test_and_set(g,(const void*)hash),b=GNUNET_BLOCK_GROUP_bf_test_and_set(g,(const void*)hash);void *output=(void*)1;size_t n=123;int code=GNUNET_BLOCK_group_serialize(g,&output,&n);printf(" %d %d %d %zu ",a,b,code,n);if(output){hex(output,n);GNUNET_free(output);}else printf("-");GNUNET_BLOCK_group_destroy(g);}puts("");free(raw);free(hash);
  }
  else if(!strcmp(op,"L")){
   destroyed=0;struct GNUNET_BLOCK_Group *a=GNUNET_new(struct GNUNET_BLOCK_Group),*b=GNUNET_new(struct GNUNET_BLOCK_Group);a->destroy_cb=destroy_dummy;b->destroy_cb=destroy_dummy;a->merge_cb=merge_no;b->merge_cb=merge_no;int result=GNUNET_BLOCK_group_merge(a,b);unsigned consumed=destroyed;GNUNET_BLOCK_group_destroy(a);printf("L %d %u %u\n",result,consumed,destroyed);
  }
  else if(!strcmp(op,"J")){
   unsigned size1=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),k1=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t n1,n2,hn;unsigned char *raw1=unhex(strtok_r(NULL," \n",&save),&n1);unsigned size2=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),k2=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);unsigned char *raw2=unhex(strtok_r(NULL," \n",&save),&n2),*hash=unhex(strtok_r(NULL," \n",&save),&hn);GNUNET_assert(hn==64);struct GNUNET_BLOCK_Group *a=GNUNET_BLOCK_GROUP_bf_create(NULL,size1,k1,GNUNET_BLOCK_TYPE_TEST,raw1,n1),*b=GNUNET_BLOCK_GROUP_bf_create(NULL,size2,k2,GNUNET_BLOCK_TYPE_DNS,raw2,n2);GNUNET_assert(a&&b);GNUNET_BLOCK_GROUP_bf_test_and_set(b,(const void*)hash);int result=GNUNET_BLOCK_group_merge(a,b);int duplicate=GNUNET_BLOCK_GROUP_bf_test_and_set(a,(const void*)hash);void *out=NULL;size_t n=0;int serial=GNUNET_BLOCK_group_serialize(a,&out,&n);printf("J %d %d %d %zu ",result,duplicate,serial,n);if(out){hex(out,n);GNUNET_free(out);}else printf("-");puts("");GNUNET_BLOCK_group_destroy(a);free(raw1);free(raw2);free(hash);
  }
  else if(!strcmp(op,"G")){
   unsigned type=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),mode=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10),size=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t rn,sn,qn,xn,bn;unsigned char *raw=unhex(strtok_r(NULL," \n",&save),&rn),*seen=unhex(strtok_r(NULL," \n",&save),&sn),*q=unhex(strtok_r(NULL," \n",&save),&qn),*x=unhex(strtok_r(NULL," \n",&save),&xn),*b=unhex(strtok_r(NULL," \n",&save),&bn);GNUNET_assert(qn==64&&(sn==0||sn==64));struct GNUNET_BLOCK_Group *g;
   if(mode==0)g=GNUNET_BLOCK_group_create(ctx,type,raw,rn,"seen-set-size",size,NULL);else if(mode==1)g=GNUNET_BLOCK_group_create(ctx,type,raw,rn,"filter-size",size,NULL);else g=GNUNET_BLOCK_group_create(ctx,type,raw,rn,"unknown",NULL);
   int marked=GNUNET_BLOCK_group_set_seen(g,(const void*)seen,sn?1:0);int first=GNUNET_BLOCK_check_reply(ctx,type,g,(const void*)q,x,xn,b,bn),second=GNUNET_BLOCK_check_reply(ctx,type,g,(const void*)q,x,xn,b,bn);void *out=NULL;size_t n=0;int code=GNUNET_BLOCK_group_serialize(g,&out,&n);printf("G %d %d %d %d %d %zu ",g!=NULL,marked,first,second,code,n);if(out){hex(out,n);GNUNET_free(out);}else printf("-");puts("");GNUNET_BLOCK_group_destroy(g);free(raw);free(seen);free(q);free(x);free(b);
  }
  else if(!strcmp(op,"D")){
   char *which=strtok_r(NULL," \n",&save);unsigned type=(unsigned)strtoull(strtok_r(NULL," \n",&save),NULL,10);size_t qn,xn,bn;unsigned char *q=unhex(strtok_r(NULL," \n",&save),&qn),*x=unhex(strtok_r(NULL," \n",&save),&xn),*b=unhex(strtok_r(NULL," \n",&save),&bn);GNUNET_assert(qn==64);int code;struct GNUNET_HashCode key;memset(&key,0xa5,sizeof key);
   if(!strcmp(which,"Q"))code=GNUNET_BLOCK_check_query(ctx,type,(const void*)q,x,xn);
   else if(!strcmp(which,"V"))code=GNUNET_BLOCK_check_block(ctx,type,b,bn);
   else if(!strcmp(which,"K"))code=GNUNET_BLOCK_get_key(ctx,type,b,bn,&key);
   else {GNUNET_assert(!strcmp(which,"R"));code=GNUNET_BLOCK_check_reply(ctx,type,NULL,(const void*)q,x,xn,b,bn);}
   printf("D %s %u %d ",which,type,code);if(!strcmp(which,"K"))hex(&key,sizeof key);else printf("-");puts("");free(q);free(x);free(b);
  }
  else if(!strcmp(op,"N")){
   unsigned char output=0xa5;void *out=&output;size_t size=9;destroyed=0;int serial=GNUNET_BLOCK_group_serialize(NULL,&out,&size);int seen=GNUNET_BLOCK_group_set_seen(NULL,NULL,0);int test=GNUNET_BLOCK_GROUP_bf_test_and_set(NULL,NULL);int merge=GNUNET_BLOCK_group_merge(NULL,NULL);GNUNET_BLOCK_group_destroy(NULL);struct GNUNET_BLOCK_Group *a=GNUNET_new(struct GNUNET_BLOCK_Group),*b=GNUNET_new(struct GNUNET_BLOCK_Group);a->destroy_cb=destroy_dummy;b->destroy_cb=destroy_dummy;int no=GNUNET_BLOCK_group_merge(a,b);unsigned retained=destroyed;GNUNET_BLOCK_group_destroy(b);GNUNET_BLOCK_group_destroy(a);printf("N %d %zu %d %d %d %d %u %u\n",serial,size,seen,test,merge,no,retained,destroyed);
  }else abort();fflush(stdout);
 }
 free(line);GNUNET_BLOCK_context_destroy(ctx);GNUNET_CONFIGURATION_destroy(cfg);return 0;
}
