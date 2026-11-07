/* Test-only public calls to the unchanged GNUnet v0.29.1 library.
 * Known fixture keys and bounded owned buffers only; no production FFI.
 * Invalid KEM selectors and underflowing short one-shot inputs are excluded. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bytes(const char *s, unsigned char *out, size_t cap) {
  size_t n = strlen(s);
  if (0 == strcmp(s, "-")) return 0;
  if (n % 2 || n / 2 > cap) return -1;
  for (size_t i = 0; i < n / 2; i++) {
    char token[3] = {s[2*i], s[2*i+1], 0};
    char *end = NULL;
    unsigned long value = strtoul(token, &end, 16);
    if (end != token + 2) return -1;
    out[i] = (unsigned char) value;
  }
  return (int) (n / 2);
}
static void field(const void *value, size_t n) {
  const unsigned char *p = value;
  putchar(' ');
  if (!n) { putchar('-'); return; }
  for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}
static void sk(struct GNUNET_CRYPTO_HpkePrivateKey *key, const unsigned char *raw) {
  memset(key, 0, sizeof *key);
  key->type = htonl(GNUNET_CRYPTO_HPKE_KEY_TYPE_X25519);
  memcpy(&key->ecdhe_key, raw, 32);
}
static void state(const struct GNUNET_CRYPTO_HpkeContext *ctx) {
  printf(" %d", ctx->role);
  field(ctx->key, 32); field(ctx->base_nonce, 12);
  field(&ctx->seq, 8); field(&ctx->exporter_secret, 32);
}
static void nonce(const struct GNUNET_CRYPTO_HpkeContext *ctx, unsigned char out[12]) {
  memcpy(out, ctx->base_nonce, 12);
  for (int i=0; i<8; i++) out[4+i] ^= ((const unsigned char *)&ctx->seq)[i];
}
int main(void) {
  char *line=NULL; size_t capacity=0;
  if (sodium_init()<0) return 2;
  GNUNET_log_setup("hpke-context-reference", "ERROR", NULL);
  while (getline(&line,&capacity,stdin)>0) {
    char *v[12], *save=NULL; int argc=0;
    for(char *t=strtok_r(line," \t\r\n",&save); t; t=strtok_r(NULL," \t\r\n",&save)) {
      if(argc==12) return 3; v[argc++]=t;
    }
    if(!argc) continue;
    unsigned char eraw[32], rraw[32], info[4096], psk[4096], id[4096], aad[4096], data[65584], output[65584];
    int ni=0,np=0,nd=0,na=0,n=0;
    struct GNUNET_CRYPTO_HpkePrivateKey e,r;
    struct GNUNET_CRYPTO_HpkePublicKey recipient;
    struct GNUNET_CRYPTO_HpkeEncapsulation enc;
    struct GNUNET_CRYPTO_HpkeContext sender,receiver;
    memset(&sender,0xa5,sizeof sender); memset(&receiver,0xa5,sizeof receiver); memset(&enc,0xa5,sizeof enc);
    memset(output,0xa5,sizeof output);
    if(!strcmp(v[0],"META") && argc==1) {
      printf("META %zu %zu %zu %zu %zu %zu %zu\n",sizeof sender,offsetof(struct GNUNET_CRYPTO_HpkeContext,role),offsetof(struct GNUNET_CRYPTO_HpkeContext,key),offsetof(struct GNUNET_CRYPTO_HpkeContext,base_nonce),offsetof(struct GNUNET_CRYPTO_HpkeContext,seq),offsetof(struct GNUNET_CRYPTO_HpkeContext,exporter_secret),sizeof sender.seq);
      continue;
    }
    if(!strcmp(v[0],"KEY") && argc==2) {
      if(bytes(v[1],rraw,32)!=32) return 3; sk(&r,rraw);
      struct GNUNET_CRYPTO_HpkePrivateKey parsed;
      struct GNUNET_CRYPTO_HpkePublicKey parsed_public;
      size_t consumed=0;
      ssize_t plen=GNUNET_CRYPTO_hpke_sk_get_length(&r);
      ssize_t written=GNUNET_CRYPTO_write_hpke_sk_to_buffer(&r,output,sizeof output);
      int read=GNUNET_CRYPTO_read_hpke_sk_from_buffer(output,written,&parsed,&consumed);
      if(plen!=36 || written!=36 || read!=GNUNET_OK || consumed!=36) return 4;
      if(GNUNET_OK!=GNUNET_CRYPTO_hpke_sk_get_public(&parsed,&recipient)) return 4;
      unsigned char public_wire[36]; size_t public_read=0;
      if(GNUNET_CRYPTO_hpke_pk_get_length(&recipient)!=36 || GNUNET_CRYPTO_write_hpke_pk_to_buffer(&recipient,public_wire,36)!=36 || GNUNET_OK!=GNUNET_CRYPTO_read_hpke_pk_from_buffer(public_wire,36,&parsed_public,&public_read) || public_read!=36) return 4;
      printf("KEY %zd %zu",written,consumed); field(output,36); field(public_wire,36);
      GNUNET_CRYPTO_hpke_sk_clear(&parsed); field(&parsed.ecdhe_key,32); puts(""); continue;
    }
    if((!strcmp(v[0],"ONESHOT") || !strcmp(v[0],"OPEN_ONESHOT") || !strcmp(v[0],"DEFAULT")) && argc==5) {
      if(bytes(v[1],rraw,32)!=32 || (ni=bytes(v[2],info,sizeof info))<0 || (na=bytes(v[3],aad,sizeof aad))<0 || (n=bytes(v[4],data,sizeof data))<0) return 3;
      if((!strcmp(v[0],"OPEN_ONESHOT") && n>65583) || (strcmp(v[0],"OPEN_ONESHOT") && n>65535)) return 3;
      sk(&r,rraw); if(GNUNET_OK!=GNUNET_CRYPTO_hpke_sk_get_public(&r,&recipient)) return 4;
      unsigned long long length=0;
      if(!strcmp(v[0],"OPEN_ONESHOT")) {
        if(n<48) return 3; /* Never exercise the known C unsigned-underflow path. */
        int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_open_oneshot(&r,info,ni,aad,na,data,n,output,&length);
        printf("OPEN_ONESHOT %d",ok); if(ok) field(output,length); puts(""); continue;
      }
      if(!strcmp(v[0],"DEFAULT")) {
        if(GNUNET_OK!=GNUNET_CRYPTO_hpke_sender_setup(&recipient,info,ni,&enc,&sender) || GNUNET_OK!=GNUNET_CRYPTO_hpke_receiver_setup(&enc,&r,info,ni,&receiver)) return 4;
        int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_seal(&sender,aad,na,data,n,output,&length);
        if(!ok) return 4; unsigned char plain[65536]; unsigned long long pn=0;
        if(GNUNET_OK!=GNUNET_CRYPTO_hpke_open(&receiver,aad,na,output,length,plain,&pn)) return 4;
        printf("DEFAULT 1");field(&enc,32);state(&sender);state(&receiver);field(output,length);field(plain,pn);puts("");continue;
      }
      int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_seal_oneshot(&recipient,info,ni,aad,na,data,n,output,&length);
      printf("ONESHOT %d %llu",ok,length);
      if(ok) { unsigned char plain[65536]; unsigned long long pn=0; if(GNUNET_OK!=GNUNET_CRYPTO_hpke_open_oneshot(&r,info,ni,aad,na,output,length+32,plain,&pn)) return 4;field(output,length+32);field(plain,pn); }
      puts("");continue;
    }
    if(argc<8 || bytes(v[2],eraw,32)!=32 || bytes(v[3],rraw,32)!=32 || (ni=bytes(v[4],info,sizeof info))<0 || (np=bytes(v[5],psk,sizeof psk))<0 || (nd=bytes(v[6],id,sizeof id))<0) return 3;
    unsigned mode=(unsigned)strtoul(v[1],NULL,10); if(mode>3) return 3;
    sk(&e,eraw);sk(&r,rraw);if(GNUNET_OK!=GNUNET_CRYPTO_hpke_sk_get_public(&r,&recipient)) return 4;
    int s_ok=GNUNET_OK==GNUNET_CRYPTO_hpke_sender_setup2(GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,mode,&e,&r,&recipient,info,ni,psk,np,id,nd,&enc,&sender);
    /* Enc is a valid public key even after a PSK scheduling refusal; Auth skips
       KEM entirely, so use e's public key for independent receiver setup. */
    struct GNUNET_CRYPTO_HpkePublicKey ephemeral_public;
    if(GNUNET_OK!=GNUNET_CRYPTO_hpke_sk_get_public(&e,&ephemeral_public)) return 4;
    memcpy(&enc,&ephemeral_public.ecdhe_key,32);
    int r_ok=GNUNET_OK==GNUNET_CRYPTO_hpke_receiver_setup2(GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,mode,&enc,&r,&recipient,info,ni,psk,np,id,nd,&receiver);
    if(!strcmp(v[0],"SETUP") && argc==8 && !strcmp(v[7],"-")) {
      printf("SETUP %d %d",s_ok,r_ok);if(s_ok){field(&enc,32);state(&sender);}if(r_ok)state(&receiver);puts("");continue;
    }
    if(!s_ok || !r_ok || argc!=10 || (na=bytes(v[8],aad,sizeof aad))<0 || (n=bytes(v[9],data,sizeof data))<0) return 3;
    if((!strcmp(v[0],"OPEN") && n>65551) || (strcmp(v[0],"OPEN") && n>65535)) return 3;
    uint64_t sequence=strtoull(v[7],NULL,10);sender.seq=receiver.seq=GNUNET_htonll(sequence);
    if(!strcmp(v[0],"WRONG")) {
      unsigned long long length=0x1234;int bad_seal=GNUNET_OK==GNUNET_CRYPTO_hpke_seal(&receiver,aad,na,data,n,output,&length);
      unsigned char before[8];memcpy(before,output,8);int bad_open=GNUNET_OK==GNUNET_CRYPTO_hpke_open(&sender,aad,na,data,n,output,&length);
      printf("WRONG %d %d %llu",bad_seal,bad_open,length);field(before,8);field(output,8);field(&sender.seq,8);field(&receiver.seq,8);puts("");continue;
    }
    unsigned long long length=0;
    if(!strcmp(v[0],"OPEN")) {
      int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_open(&receiver,aad,na,data,n,output,&length);
      printf("OPEN %d",ok);field(&receiver.seq,8);if(ok)field(output,length);puts("");continue;
    }
    if(!strcmp(v[0],"LIMIT_OPEN")) {
      unsigned char comp_nonce[12],cipher[65552];unsigned long long cn=0;nonce(&receiver,comp_nonce);
      if(0!=crypto_aead_chacha20poly1305_ietf_encrypt(cipher,&cn,data,n,aad,na,NULL,comp_nonce,receiver.key)) return 4;
      int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_open(&receiver,aad,na,cipher,cn,output,&length);
      printf("LIMIT_OPEN %d",ok);field(&receiver.seq,8);puts("");continue;
    }
    if(!strcmp(v[0],"ROUND")) {
      int ok=GNUNET_OK==GNUNET_CRYPTO_hpke_seal(&sender,aad,na,data,n,output,&length);
      printf("ROUND %d",ok);field(&sender.seq,8);
      if(ok) {unsigned char plain[65536];unsigned long long pn=0;int ro=GNUNET_OK==GNUNET_CRYPTO_hpke_open(&receiver,aad,na,output,length,plain,&pn);printf(" %d",ro);field(&receiver.seq,8);field(output,length);if(ro)field(plain,pn);}
      puts("");continue;
    }
    return 3;
  }
  free(line);return 0;
}
