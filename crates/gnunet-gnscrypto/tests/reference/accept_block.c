/* Verify and decrypt a Rust-emitted block using normal unmodified GNUnet APIs. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
static int failed=1;
static void *load(const char *name,size_t *n) {
 FILE *f=fopen(name,"rb");if(!f)return NULL;
 if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}long size=ftell(f);
 if(size<0||size>65536||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}
 void *out=GNUNET_malloc((size_t)size+1);*n=(size_t)size;
 if(*n!=fread(out,1,*n,f)){GNUNET_free(out);fclose(f);return NULL;}
 fclose(f);return out;
}
static void received(void *cls,unsigned int count,const struct GNUNET_GNSRECORD_Data *rd) {
 const char *expected=cls;size_t n;void *bytes=load(expected,&n);
 ssize_t need=GNUNET_GNSRECORD_records_get_size(count,rd);if(!bytes||need<0||(size_t)need!=n){GNUNET_free(bytes);return;}
 unsigned char serialized[n?n:1];if(need!=GNUNET_GNSRECORD_records_serialize(count,rd,n,(char*)serialized)){GNUNET_free(bytes);return;}
 failed=memcmp(bytes,serialized,n)!=0;GNUNET_free(bytes);printf("records=%u exact_plaintext=%d\n",count,!failed);
}
int main(int argc,char **argv) {
 if(argc!=5)return 2; if(GNUNET_OK!=GNUNET_log_setup("gns-rust-block-oracle","ERROR",NULL))return 3;
 size_t zn,ln,bn;void *z=load(argv[1],&zn);char *label=load(argv[2],&ln);void *raw=load(argv[3],&bn);
 if(!z||!label||!raw||zn!=36||bn<sizeof(struct GNUNET_GNSRECORD_Block)||memchr(label,0,ln))return 4;
 char *terminated=GNUNET_malloc(ln+1);memcpy(terminated,label,ln);terminated[ln]=0;
 struct GNUNET_GNSRECORD_Block *block=raw;struct GNUNET_CRYPTO_BlindablePublicKey *zone=z;
 if(ntohl(block->size)!=bn||GNUNET_OK!=GNUNET_GNSRECORD_block_verify(block))return 5;
 struct GNUNET_HashCode expected,carried;GNUNET_GNSRECORD_query_from_public_key(zone,terminated,&expected);GNUNET_GNSRECORD_query_from_block(block,&carried);
 if(memcmp(&expected,&carried,sizeof expected))return 6;
 if(GNUNET_OK!=GNUNET_GNSRECORD_block_decrypt(block,zone,terminated,&received,argv[4]))return 7;
 GNUNET_free(z);GNUNET_free(label);GNUNET_free(raw);GNUNET_free(terminated);return failed;
}
