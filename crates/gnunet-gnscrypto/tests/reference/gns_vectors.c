/* Independent vector driver using normal unmodified GNUnet shared libraries.
 * Inputs are fixed published/synthetic test keys, never a user's secret. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnsrecord_crypto.h"
#include <sodium.h>
#include <inttypes.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static void row(const char *prefix,const char *name,const void *buf,size_t n) {
  printf("%s.%s ",prefix,name);
  for(size_t i=0;i<n;i++)printf("%02x",((const unsigned char*)buf)[i]);
  puts("");
}
static void status(const char *prefix,const char *name,int x) { printf("%s.%s %d\n",prefix,name,x); }
static int hex(const char *s,unsigned char *out,size_t n,int reverse) {
  for(size_t i=0;i<n;i++){ unsigned v;if(1!=sscanf(s+2*i,"%2x",&v))return 1;out[reverse?n-1-i:i]=(unsigned char)v; } return 0;
}
struct opened { const char *name; unsigned count; };
static void on_records(void *cls,unsigned int count,const struct GNUNET_GNSRECORD_Data *rd) {
 struct opened *o=cls;o->count=count;
 unsigned char raw[4096];ssize_t size=GNUNET_GNSRECORD_records_get_size(count,rd);
 if(size<0||size>(ssize_t)sizeof raw)return;
 if(size!=GNUNET_GNSRECORD_records_serialize(count,rd,(size_t)size,(char*)raw))return;
 row(o->name,"opened_rdata",raw,(size_t)size);
}
static int one(uint32_t type,const char *name,const char *label,uint64_t exp) {
 struct GNUNET_CRYPTO_BlindablePrivateKey key={0};struct GNUNET_CRYPTO_BlindablePublicKey pub;
 key.type=htonl(type);
 const char *private_hex= type==GNUNET_GNSRECORD_TYPE_PKEY?"50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98":"5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65";
 if(hex(private_hex,(unsigned char*)&key.ecdsa_key,32,type==GNUNET_GNSRECORD_TYPE_PKEY))return 2;
 GNUNET_CRYPTO_blindable_key_get_public(&key,&pub);
 char *normalized=GNUNET_GNSRECORD_string_normalize(label); if(!normalized)return 3;
 row(name,"private_input",&key.ecdsa_key,32);row(name,"zone",&pub,36);row(name,"label_input",label,strlen(label));row(name,"label_nfc",normalized,strlen(normalized));
 struct GNUNET_HashCode h; unsigned char reversed[64],reduced[32];
 GNUNET_CRYPTO_hkdf_gnunet(&h,sizeof h,"key-derivation",strlen("key-derivation"),&pub.ecdsa_key,32,GNUNET_CRYPTO_kdf_arg_string(normalized),GNUNET_CRYPTO_kdf_arg_string("gns"));
 row(name,"h64",&h,64);for(size_t i=0;i<64;i++)reversed[i]=((unsigned char*)&h)[63-i];crypto_core_ed25519_scalar_reduce(reduced,reversed);row(name,"h_mod_l",reduced,32);
 if(type==GNUNET_GNSRECORD_TYPE_PKEY) {
  struct GNUNET_CRYPTO_EcdsaPrivateKey *d=GNUNET_CRYPTO_ecdsa_private_key_derive(&key.ecdsa_key,normalized,"gns");
  struct GNUNET_CRYPTO_EcdsaPublicKey q;GNUNET_CRYPTO_ecdsa_public_key_derive(&pub.ecdsa_key,normalized,"gns",&q);
  row(name,"derived_private",d,32);row(name,"derived_public",&q,32);GNUNET_free(d);
 } else {
  struct GNUNET_CRYPTO_EddsaPrivateScalar d;struct GNUNET_CRYPTO_EddsaPublicKey q,q2;
  GNUNET_CRYPTO_eddsa_private_key_derive(&key.eddsa_key,normalized,"gns",&d);GNUNET_CRYPTO_eddsa_public_key_derive(&pub.eddsa_key,normalized,"gns",&q);GNUNET_CRYPTO_eddsa_key_get_public_from_scalar(&d,&q2);
  row(name,"derived_private",&d,64);row(name,"derived_public",&q,32);status(name,"derived_public_equal",memcmp(&q,&q2,32)==0);
 }
 struct GNUNET_TIME_Absolute expiry={.abs_value_us=exp};struct GNUNET_TIME_AbsoluteNBO en=GNUNET_TIME_absolute_hton(expiry);
 row(name,"expiration_be",&en,8);
 if(type==GNUNET_GNSRECORD_TYPE_PKEY){unsigned char iv[16],k[32];GNR_derive_block_aes_key(iv,k,normalized,en.abs_value_us__,&pub.ecdsa_key);row(name,"symmetric_key",k,32);row(name,"nonce",iv,16);}
 else {struct GNUNET_CRYPTO_XSalsa20Nonce iv;struct GNUNET_CRYPTO_XSalsa20SecretKey k;GNR_derive_block_xsalsa_key(&iv,&k,normalized,en.abs_value_us__,&pub.eddsa_key);row(name,"symmetric_key",&k,32);row(name,"nonce",&iv,24);}
 const unsigned char address[]={192,0,2,1};const char text[]="interop";
 struct GNUNET_GNSRECORD_Data records[2]={{.data=address,.data_size=4,.record_type=1,.flags=0,.expiration_time=exp},{.data=text,.data_size=sizeof(text)-1,.record_type=16,.flags=GNUNET_GNSRECORD_RF_SUPPLEMENTAL,.expiration_time=exp}};
 ssize_t size=GNUNET_GNSRECORD_records_get_size(2,records);unsigned char plaintext[4096];if(size<0||size>(ssize_t)sizeof plaintext)return 4;
 if(size!=GNUNET_GNSRECORD_records_serialize(2,records,size,(char*)plaintext))return 5;row(name,"rdata",plaintext,size);
 struct GNUNET_GNSRECORD_EncryptionContext *owner=GNUNET_GNSRECORD_encryption_context_setup_owner(&key);struct GNUNET_GNSRECORD_Block *block=NULL;
 int result=owner->seal(owner->cls,label,expiry,plaintext,size,&block);status(name,"seal_result",result);if(result!=GNUNET_OK||!block)return 6;
 size_t total=ntohl(block->size);row(name,"block",block,total);status(name,"block_verify",GNUNET_GNSRECORD_block_verify(block));
 unsigned char preimage[4096];struct GNRBlockPS *ps=(struct GNRBlockPS*)preimage;ps->purpose.size=htonl(16+total-sizeof(*block));ps->purpose.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);ps->expiration_time=block->ecdsa_block.expiration_time;memcpy(preimage+16,&block[1],total-sizeof(*block));row(name,"signed_preimage",preimage,16+total-sizeof(*block));
 struct GNUNET_HashCode q1,q2,q3;GNUNET_GNSRECORD_query_from_private_key(&key,label,&q1);GNUNET_GNSRECORD_query_from_public_key(&pub,label,&q2);GNUNET_GNSRECORD_query_from_block(block,&q3);row(name,"query",&q1,64);status(name,"three_queries_equal",memcmp(&q1,&q2,64)==0&&memcmp(&q2,&q3,64)==0);
 struct opened opened={.name=name,.count=0};struct GNUNET_GNSRECORD_EncryptionContext *resolver=GNUNET_GNSRECORD_encryption_context_setup_resolver(&pub);
 result=resolver->open(resolver->cls,label,block,&on_records,&opened);status(name,"open_result",result);status(name,"open_record_count",opened.count);
 ((unsigned char*)block)[total-1]^=1;status(name,"tampered_signature_verify",GNUNET_GNSRECORD_block_verify(block));((unsigned char*)block)[total-1]^=1;
 GNUNET_GNSRECORD_encryption_context_destroy(resolver);GNUNET_GNSRECORD_encryption_context_destroy(owner);GNUNET_free(block);GNUNET_free(normalized);
 return result==GNUNET_OK&&opened.count==2?0:7;
}
int main(void) {
 if(GNUNET_OK!=GNUNET_log_setup("gns-vector-driver","ERROR",NULL))return 8;
 int r=0;r|=one(GNUNET_GNSRECORD_TYPE_PKEY,"pkey_ascii","testdelegation",UINT64_C(0x003ff2aa5408db40));
 r|=one(GNUNET_GNSRECORD_TYPE_EDKEY,"edkey_ascii","testdelegation",UINT64_C(0x003ff2aa5408db40));
 r|=one(GNUNET_GNSRECORD_TYPE_PKEY,"pkey_nfc","e\xcc\x81xample",UINT64_C(0x003ff2aa5408db41));
 r|=one(GNUNET_GNSRECORD_TYPE_EDKEY,"edkey_nfc","e\xcc\x81xample",UINT64_C(0x003ff2aa5408db41));
 return r;
}
