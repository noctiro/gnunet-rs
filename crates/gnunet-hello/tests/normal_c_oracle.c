#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include <assert.h>

struct SignedRegion {
  struct GNUNET_CRYPTO_SignaturePurpose purpose;
  struct GNUNET_TIME_AbsoluteNBO expiry;
  struct GNUNET_HashCode hash;
};
_Static_assert(sizeof(struct SignedRegion)==80,"official HELLO purpose length");

static void write_file(const char *prefix,const char *suffix,const void *data,size_t n) {
  char path[4096]; assert(snprintf(path,sizeof(path),"%s.%s",prefix,suffix)<sizeof(path));
  FILE *f=fopen(path,"wb");assert(f);assert(n==fwrite(data,1,n,f));assert(0==fclose(f));
}
static unsigned char *read_file(const char *path,size_t *n) {
  FILE *f=fopen(path,"rb");assert(f);assert(0==fseek(f,0,SEEK_END));long z=ftell(f);assert(z>=0 && z<8*1024*1024);rewind(f);
  unsigned char *b=calloc((size_t)z+1,1);assert(b);assert((size_t)z==fread(b,1,(size_t)z,f));assert(0==fclose(f));*n=(size_t)z;return b;
}
static void counter(void *cls,const struct GNUNET_PeerIdentity *pid,const char *uri) { (void)pid;(void)uri;(*(unsigned*)cls)++; }
static void write_parser(struct GNUNET_HELLO_Parser *p,const char *prefix) {
  size_t n=0;assert(GNUNET_NO==GNUNET_HELLO_parser_to_block(p,NULL,&n));void *b=malloc(n);assert(b);
  assert(GNUNET_OK==GNUNET_HELLO_parser_to_block(p,b,&n));write_file(prefix,"block",b,n);free(b);
  char *url=GNUNET_HELLO_parser_to_url(p);assert(url);write_file(prefix,"url",url,strlen(url));GNUNET_free(url);
  const struct GNUNET_PeerIdentity *pid=GNUNET_HELLO_parser_get_id(p);write_file(prefix,"peer",pid,sizeof(*pid));
  struct GNUNET_MQ_Envelope *env=GNUNET_HELLO_parser_to_env(p);assert(env);const struct GNUNET_MessageHeader *m=GNUNET_MQ_env_get_msg(env);write_file(prefix,"message",m,ntohs(m->size));GNUNET_MQ_discard(env);
  struct GNUNET_MessageHeader *d=GNUNET_HELLO_parser_to_dht_hello_msg(p);assert(d);write_file(prefix,"dht",d,ntohs(d->size));GNUNET_free(d);
  unsigned count=0;GNUNET_HELLO_parser_iterate(p,counter,&count);printf("{\"accepted\":true,\"address_count\":%u,\"block_size\":%zu}\n",count,n);
}
static void json_hex(FILE *out,const void *data,size_t n) {
  const unsigned char *bytes=data;fputc('"',out);for(size_t i=0;i<n;i++)fprintf(out,"%02x",bytes[i]);fputc('"',out);
}
struct CallbackTrace { FILE *out; unsigned count; };
static void trace_uri(void *cls,const struct GNUNET_PeerIdentity *pid,const char *uri) {
  struct CallbackTrace *trace=cls;if(trace->count++)fputc(',',trace->out);
  fputs("{\"peer\":",trace->out);if(pid)json_hex(trace->out,pid,sizeof(*pid));else fputs("null",trace->out);
  fputs(",\"uri\":",trace->out);json_hex(trace->out,uri,strlen(uri));fputc('}',trace->out);
}
static struct GNUNET_TIME_Absolute expiry_at(const void *bytes,size_t offset) {
  struct GNUNET_TIME_AbsoluteNBO expiry;memcpy(&expiry,(const char*)bytes+offset,sizeof(expiry));return GNUNET_TIME_absolute_ntoh(expiry);
}
static void expiry_window(struct GNUNET_TIME_Absolute expiry,struct GNUNET_TIME_Absolute before,struct GNUNET_TIME_Absolute after) {
  uint64_t duration=GNUNET_HELLO_ADDRESS_EXPIRATION.rel_value_us;
  assert(expiry.abs_value_us>=before.abs_value_us+duration && expiry.abs_value_us<=after.abs_value_us+duration);
}
static void write_expiry(const char *prefix,const char *suffix,struct GNUNET_TIME_Absolute expiry) {
  struct GNUNET_TIME_AbsoluteNBO wire=GNUNET_TIME_absolute_hton(expiry);write_file(prefix,suffix,&wire,sizeof(wire));
}
static void contract(const char *prefix) {
  char path[4096];assert(snprintf(path,sizeof(path),"%s.block",prefix)<sizeof(path));size_t n;unsigned char *block=read_file(path,&n);
  struct GNUNET_HELLO_Parser *parser=GNUNET_HELLO_parser_from_block(block,n);assert(parser);
  struct GNUNET_PeerIdentity peer;struct GNUNET_HELLO_Builder *builder=GNUNET_HELLO_builder_from_parser(parser,&peer);assert(builder);
  struct GNUNET_CRYPTO_EddsaSignature sig;memcpy(&sig,block+32,sizeof(sig));
  assert(snprintf(path,sizeof(path),"%s.contract.json",prefix)<sizeof(path));FILE *out=fopen(path,"wb");assert(out);
  fputs("{\"builder_callbacks\":[",out);struct CallbackTrace trace={.out=out};GNUNET_HELLO_builder_iterate(builder,trace_uri,&trace);
  fputs("],\"parser_callbacks\":[",out);trace.count=0;GNUNET_HELLO_parser_iterate(parser,trace_uri,&trace);
  fputs("],\"parser_null_peer\":",out);const struct GNUNET_PeerIdentity *pid=GNUNET_HELLO_parser_iterate(parser,NULL,NULL);assert(pid);json_hex(out,pid,sizeof(*pid));
  fputs(",\"copied_peer\":",out);json_hex(out,&peer,sizeof(peer));
  struct GNUNET_HELLO_Builder *a=GNUNET_HELLO_builder_new(),*b=GNUNET_HELLO_builder_new(),*empty=GNUNET_HELLO_builder_new();
  assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(a,"a://x"));assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(b,"a://x"));assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(b,"b://y"));
  fprintf(out,",\"subsets\":[%d,%d,%d,%d,%d]",GNUNET_HELLO_builder_address_list_cmp(a,b),GNUNET_HELLO_builder_address_list_cmp(b,a),GNUNET_HELLO_builder_address_list_cmp(a,a),GNUNET_HELLO_builder_address_list_cmp(empty,a),GNUNET_HELLO_builder_address_list_cmp(a,empty));
  int missing=GNUNET_HELLO_builder_del_address(b,"missing://x"),present=GNUNET_HELLO_builder_del_address(b,"b://y"),again=GNUNET_HELLO_builder_del_address(b,"b://y");
  fprintf(out,",\"deletions\":[%d,%d,%d]",missing,present,again);
  fprintf(out,",\"builder_sizes\":[%zu,%zu,%zu]",GNUNET_HELLO_get_builder_to_block_size(empty),GNUNET_HELLO_get_builder_to_block_size(builder),GNUNET_HELLO_get_builder_to_block_size(b));
  fputs(",\"prefixes\":[",out);const char *prefix_inputs[]={"udp://host-name","udp://localhost","-x","a-b-c",NULL};
  for(unsigned i=0;prefix_inputs[i];i++){if(i)fputc(',',out);char *p=GNUNET_HELLO_address_to_prefix(prefix_inputs[i]);if(p){json_hex(out,p,strlen(p));GNUNET_free(p);}else fputs("null",out);}fputc(']',out);
  size_t needed=0;assert(GNUNET_NO==GNUNET_HELLO_parser_to_block(parser,NULL,&needed));assert(needed==n);
  unsigned char *small=malloc(n+4);assert(small);memset(small,0xa5,n+4);size_t available=n-1;assert(GNUNET_NO==GNUNET_HELLO_parser_to_block(parser,small,&available));assert(available==n);for(size_t i=0;i<n+4;i++)assert(small[i]==0xa5);
  available=n;assert(GNUNET_OK==GNUNET_HELLO_parser_to_block(parser,small,&available));assert(available==n && 0==memcmp(small,block,n));for(size_t i=n;i<n+4;i++)assert(small[i]==0xa5);free(small);
  fprintf(out,",\"block_size_query\":%zu,\"short_refused_unchanged\":true,\"exact_fit_tail_unchanged\":true,\"duration_us\":%" PRIu64,needed,GNUNET_HELLO_ADDRESS_EXPIRATION.rel_value_us);
  struct GNUNET_TIME_RelativeNBO duration=GNUNET_TIME_relative_hton(GNUNET_HELLO_ADDRESS_EXPIRATION);write_file(prefix,"duration",&duration,sizeof(duration));
  unsigned char *encoded=malloc(n);assert(encoded);struct GNUNET_TIME_Absolute before=GNUNET_TIME_absolute_get();GNUNET_HELLO_builder_to_block(builder,&peer,&sig,GNUNET_TIME_UNIT_ZERO_ABS,(char*)encoded);struct GNUNET_TIME_Absolute after=GNUNET_TIME_absolute_get();struct GNUNET_TIME_Absolute expiry=expiry_at(encoded,96);expiry_window(expiry,before,after);write_file(prefix,"default.block",encoded,n);write_expiry(prefix,"default.block.expiry",expiry);free(encoded);
  before=GNUNET_TIME_absolute_get();struct GNUNET_MQ_Envelope *env=GNUNET_HELLO_builder_to_env(builder,&peer,&sig,GNUNET_TIME_UNIT_ZERO_ABS);after=GNUNET_TIME_absolute_get();assert(env);const struct GNUNET_MessageHeader *message=GNUNET_MQ_env_get_msg(env);expiry=expiry_at(message,104);expiry_window(expiry,before,after);write_file(prefix,"default.message",message,ntohs(message->size));write_expiry(prefix,"default.message.expiry",expiry);GNUNET_MQ_discard(env);
  before=GNUNET_TIME_absolute_get();struct GNUNET_MessageHeader *dht=GNUNET_HELLO_builder_to_dht_hello_msg(builder,&peer,&sig,GNUNET_TIME_UNIT_ZERO_ABS);after=GNUNET_TIME_absolute_get();assert(dht);expiry=expiry_at(dht,72);expiry_window(expiry,before,after);write_file(prefix,"default.dht",dht,ntohs(dht->size));write_expiry(prefix,"default.dht.expiry",expiry);GNUNET_free(dht);
  char *url=NULL;before=GNUNET_TIME_absolute_get();assert(GNUNET_OK==GNUNET_HELLO_builder_to_url(builder,&peer,&sig,&url));after=GNUNET_TIME_absolute_get();const char *number=strrchr(url,'/');assert(number && 1==sscanf(number+1,"%" SCNu64,&expiry.abs_value_us));expiry_window(expiry,before,after);write_file(prefix,"default.url",url,strlen(url));write_expiry(prefix,"default.url.expiry",expiry);GNUNET_free(url);
  fputs("}",out);assert(0==fclose(out));free(block);GNUNET_HELLO_builder_free(a);GNUNET_HELLO_builder_free(b);GNUNET_HELLO_builder_free(empty);GNUNET_HELLO_builder_free(builder);GNUNET_HELLO_parser_free(parser);
}

int main(int argc,char **argv) {
  GNUNET_log_setup("hello-normal-oracle","ERROR",NULL);
  assert(argc>=2);
  if(0==strcmp(argv[1],"build")) {
    assert(argc==4 || argc==5);size_t n;unsigned char *addrs=read_file(argv[2],&n);struct GNUNET_HELLO_Builder *builder=GNUNET_HELLO_builder_new();
    unsigned added=0,duplicate=0;size_t offset=0;
    while(offset<n) { unsigned char *end=memchr(addrs+offset,0,n-offset);assert(end);int r=GNUNET_HELLO_builder_add_address(builder,(char*)addrs+offset);if(r==GNUNET_OK)added++;else if(r==GNUNET_NO)duplicate++;else return 4;offset=(size_t)(end-addrs)+1; }
    struct GNUNET_CRYPTO_EddsaPrivateKey key;for(size_t i=0;i<sizeof(key);i++)((unsigned char*)&key)[i]=(unsigned char)i;
    struct GNUNET_PeerIdentity pid;GNUNET_CRYPTO_eddsa_key_get_public(&key,&pid.public_key);
    struct GNUNET_TIME_Absolute expiry={.abs_value_us=(argc==5?strtoull(argv[4],NULL,10):UINT64_MAX)};struct SignedRegion region={.purpose={.size=htonl(sizeof(region)),.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_HELLO)},.expiry=GNUNET_TIME_absolute_hton(expiry)};
    GNUNET_HELLO_builder_hash_addresses(builder,&region.hash);struct GNUNET_CRYPTO_EddsaSignature signature;GNUNET_CRYPTO_eddsa_sign(&key,&region,&signature);
    write_file(argv[3],"region",&region,sizeof(region));write_file(argv[3],"hash",&region.hash,sizeof(region.hash));write_file(argv[3],"signature",&signature,sizeof(signature));
    n=GNUNET_HELLO_get_builder_to_block_size(builder);void *block=malloc(n);assert(block);GNUNET_HELLO_builder_to_block(builder,&pid,&signature,expiry,block);
    struct GNUNET_HELLO_Parser *parser=GNUNET_HELLO_parser_from_block_(block,n,GNUNET_YES);assert(parser);write_parser(parser,argv[3]);
    fprintf(stderr,"added=%u duplicate=%u\n",added,duplicate);
    GNUNET_HELLO_parser_free(parser);free(block);free(addrs);GNUNET_HELLO_builder_free(builder);return 0;
  }
  if(0==strcmp(argv[1],"inspect") || 0==strcmp(argv[1],"unchecked")) {
    assert(argc==6);size_t n;unsigned char *input=read_file(argv[3],&n);struct GNUNET_HELLO_Parser *parser=NULL;
    int unchecked=0==strcmp(argv[1],"unchecked");
    if(0==strcmp(argv[2],"block")) parser=GNUNET_HELLO_parser_from_block_(input,n,unchecked?GNUNET_YES:GNUNET_NO);
    else if(0==strcmp(argv[2],"url")) parser=GNUNET_HELLO_parser_from_url((char*)input);
    else {
      size_t pn;unsigned char *p=read_file(argv[4],&pn);assert(pn==sizeof(struct GNUNET_PeerIdentity));
      if(n>=4 && ntohs(((struct GNUNET_MessageHeader*)input)->size)<=n) parser=GNUNET_HELLO_parser_from_msg_((void*)input,(void*)p,unchecked?GNUNET_YES:GNUNET_NO);
      free(p);
    }
    if(!parser) {printf("{\"accepted\":false}\n");free(input);return 3;}
    write_parser(parser,argv[5]);GNUNET_HELLO_parser_free(parser);free(input);return 0;
  }
  if(0==strcmp(argv[1],"relations")) {
    struct GNUNET_HELLO_Builder *a=GNUNET_HELLO_builder_new(),*b=GNUNET_HELLO_builder_new();
    assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(a,"a://x"));assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(b,"a://x"));assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(b,"b://y"));
    char *prefix=GNUNET_HELLO_address_to_prefix("udp://host-name"),*none=GNUNET_HELLO_address_to_prefix("udp://localhost");
    printf("{\"subset_ab\":%d,\"subset_ba\":%d,\"hyphen_prefix\":\"%s\",\"no_hyphen_is_null\":%s}\n",GNUNET_HELLO_builder_address_list_cmp(a,b),GNUNET_HELLO_builder_address_list_cmp(b,a),prefix,none?"false":"true");
    GNUNET_free(prefix);GNUNET_free(none);GNUNET_HELLO_builder_free(a);GNUNET_HELLO_builder_free(b);return 0;
  }
  if(0==strcmp(argv[1],"api")) {
    assert(argc==3);char path[4096];assert(snprintf(path,sizeof(path),"%s.block",argv[2])<sizeof(path));size_t n;unsigned char *block=read_file(path,&n);
    struct GNUNET_HELLO_Parser *parser=GNUNET_HELLO_parser_from_block(block,n);assert(parser);
    struct GNUNET_PeerIdentity copied;struct GNUNET_HELLO_Builder *builder=GNUNET_HELLO_builder_from_parser(parser,&copied);assert(builder);assert(0==memcmp(&copied,block,sizeof(copied)));
    unsigned count=0;GNUNET_HELLO_builder_iterate(builder,counter,&count);assert(count==3);assert(GNUNET_NO==GNUNET_HELLO_builder_add_address(builder,"z://Z"));assert(GNUNET_NO==GNUNET_HELLO_builder_del_address(builder,"missing://none"));assert(GNUNET_OK==GNUNET_HELLO_builder_del_address(builder,"z://Z"));assert(GNUNET_OK==GNUNET_HELLO_builder_add_address(builder,"z://Z"));
    struct GNUNET_CRYPTO_EddsaSignature sig;memcpy(&sig,block+32,sizeof(sig));struct GNUNET_TIME_Absolute expiry={.abs_value_us=UINT64_MAX};
    size_t out_size=GNUNET_HELLO_get_builder_to_block_size(builder);assert(out_size==n);unsigned char *out=malloc(out_size);assert(out);GNUNET_HELLO_builder_to_block(builder,&copied,&sig,expiry,(char*)out);assert(0==memcmp(out,block,n));
    struct GNUNET_MQ_Envelope *env=GNUNET_HELLO_builder_to_env(builder,&copied,&sig,expiry);assert(env);const struct GNUNET_MessageHeader *msg=GNUNET_MQ_env_get_msg(env);struct GNUNET_HELLO_Parser *q=GNUNET_HELLO_parser_from_msg(msg,NULL);assert(q);GNUNET_HELLO_parser_free(q);assert(GNUNET_HELLO_get_expiration_time_from_msg(msg).abs_value_us==UINT64_MAX);GNUNET_MQ_discard(env);
    struct GNUNET_MessageHeader *dht=GNUNET_HELLO_builder_to_dht_hello_msg(builder,&copied,&sig,expiry);assert(dht);void *raw=NULL;size_t raw_size=0;struct GNUNET_TIME_Absolute et;assert(GNUNET_OK==GNUNET_HELLO_dht_msg_to_block(dht,&copied,&raw,&raw_size,&et));assert(raw_size==n && et.abs_value_us==UINT64_MAX && 0==memcmp(raw,block,n));GNUNET_free(raw);GNUNET_free(dht);
    char *a=NULL,*b=NULL,*c=GNUNET_HELLO_parser_to_url(parser);assert(GNUNET_OK==GNUNET_HELLO_build_url(builder,&copied,&sig,expiry,&a));assert(GNUNET_OK==GNUNET_HELLO_builder_to_url2(builder,&copied,&sig,expiry,&b));assert(0==strcmp(a,b) && 0==strcmp(a,c));GNUNET_free(a);GNUNET_free(b);GNUNET_free(c);
    struct GNUNET_TIME_Absolute before=GNUNET_TIME_absolute_get();assert(GNUNET_OK==GNUNET_HELLO_builder_to_url(builder,&copied,&sig,&a));struct GNUNET_TIME_Absolute after=GNUNET_TIME_absolute_get();const char *ep=strrchr(a,'/');assert(ep);uint64_t default_expiry=strtoull(ep+1,NULL,10);uint64_t duration=GNUNET_HELLO_ADDRESS_EXPIRATION.rel_value_us;assert(default_expiry>=before.abs_value_us+duration && default_expiry<=after.abs_value_us+duration);GNUNET_free(a);
    before=GNUNET_TIME_absolute_get();GNUNET_HELLO_builder_to_block(builder,&copied,&sig,GNUNET_TIME_UNIT_ZERO_ABS,(char*)out);after=GNUNET_TIME_absolute_get();struct GNUNET_TIME_AbsoluteNBO nbo;memcpy(&nbo,out+96,sizeof(nbo));uint64_t zero_expiry=GNUNET_TIME_absolute_ntoh(nbo).abs_value_us;assert(zero_expiry>=before.abs_value_us+duration && zero_expiry<=after.abs_value_us+duration);
    struct GNUNET_HELLO_Builder *empty=GNUNET_HELLO_builder_new();env=GNUNET_HELLO_builder_to_env(empty,&copied,&sig,expiry);assert(GNUNET_HELLO_get_expiration_time_from_msg(GNUNET_MQ_env_get_msg(env)).abs_value_us==0);GNUNET_MQ_discard(env);dht=GNUNET_HELLO_builder_to_dht_hello_msg(empty,&copied,&sig,expiry);assert(GNUNET_HELLO_get_expiration_time_from_msg(dht).abs_value_us==UINT64_MAX);GNUNET_free(dht);GNUNET_HELLO_builder_free(empty);
    GNUNET_HELLO_parser_free(parser);GNUNET_HELLO_builder_free(builder);free(out);free(block);printf("{\"builder_copy_delete_and_all_formats\":true,\"zero_expiry_uses_two_days\":true,\"default_url_uses_two_days\":true,\"empty_hello_expiry_zero\":true,\"empty_dht_expiry_max\":true}\n");return 0;
  }
  if(0==strcmp(argv[1],"contract")) { assert(argc==3);contract(argv[2]);return 0; }
  return 2;
}
