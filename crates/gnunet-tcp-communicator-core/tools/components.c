/* Test-only source component and normal public utility-library observer.
 * The generated header retains the original AGPL source notice/profile.
 * This is not an executed communicator/TRANSPORT/CORE daemon or handshake. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "tcp_source.inc"
static void hex(const char *name,const void *data,size_t n,int comma) {
 const unsigned char *p=data;printf("%s\"%s\":\"",comma?",":"",name);for(size_t i=0;i<n;i++)printf("%02x",p[i]);printf("\"");
}
static void block(gcry_cipher_hd_t cipher,struct GNUNET_CRYPTO_AuthKey *mac,unsigned char out[44]) {
 const unsigned char payload[8]={0,8,0,17,1,2,3,4};struct TCPBox box;box.header.type=htons(GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX);box.header.size=htons(sizeof payload);calculate_hmac(mac,payload,sizeof payload,&box.hmac);memcpy(out,&box,sizeof box);memcpy(out+sizeof box,payload,sizeof payload);GNUNET_assert(0==gcry_cipher_encrypt(cipher,out,44,NULL,0));
}
int main(void) {
 struct GNUNET_CRYPTO_EddsaPrivateKey a,b;memset(&a,1,sizeof a);memset(&b,2,sizeof b);struct GNUNET_PeerIdentity ap,bp;GNUNET_CRYPTO_eddsa_key_get_public(&a,&ap.public_key);GNUNET_CRYPTO_eddsa_key_get_public(&b,&bp.public_key);
 struct TCPConfirmation c;struct TcpHandshakeSignature hs;memset(&c,0,sizeof c);hs.purpose.size=htonl(sizeof hs);hs.purpose.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_HANDSHAKE);hs.sender=ap;hs.receiver=bp;memset(&hs.ephemeral,3,sizeof hs.ephemeral);hs.monotonic_time.abs_value_us__=GNUNET_htonll(123);memset(&hs.challenge,4,sizeof hs.challenge);c.sender=ap;c.monotonic_time=hs.monotonic_time;c.challenge=hs.challenge;GNUNET_CRYPTO_eddsa_sign(&a,&hs,&c.sender_sig);
 struct TCPConfirmationAck ack;struct TcpHandshakeAckSignature as;memset(&ack,0,sizeof ack);ack.header.size=htons(sizeof ack);ack.header.type=htons(GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_CONFIRMATION_ACK);ack.sender=ap;ack.monotonic_time.abs_value_us__=GNUNET_htonll(1);ack.challenge=hs.challenge;as.purpose.size=htonl(sizeof as);as.purpose.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_HANDSHAKE_ACK);as.sender=ap;as.receiver=bp;as.monotonic_time=ack.monotonic_time;as.challenge=ack.challenge;GNUNET_CRYPTO_eddsa_sign(&a,&as,&ack.sender_sig);
 struct TCPRekey rk;struct TcpRekeySignature rs;memset(&rk,0,sizeof rk);rk.header.size=htons(sizeof rk);rk.header.type=htons(GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY);memset(&rk.ephemeral,5,sizeof rk.ephemeral);rk.monotonic_time.abs_value_us__=GNUNET_htonll(7);rs.purpose.size=htonl(sizeof rs);rs.purpose.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_REKEY);rs.sender=ap;rs.receiver=bp;rs.ephemeral=rk.ephemeral;rs.monotonic_time=rk.monotonic_time;GNUNET_CRYPTO_eddsa_sign(&a,&rs,&rk.sender_sig);
 struct GNUNET_ShortHashCode p,new;memset(&p,42,sizeof p);memset(&new,19,sizeof new);struct GNUNET_CRYPTO_AuthKey mac;gcry_cipher_hd_t cipher;unsigned char one[44],two[44],fin[36],eack[sizeof ack],afterack[44],erk[sizeof rk],afterrk[44];
 setup_cipher(&p,&bp,&cipher,&mac);block(cipher,&mac,one);block(cipher,&mac,two);struct TCPFinish f;memset(&f,0,sizeof f);f.header.size=htons(sizeof f);f.header.type=htons(GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH);calculate_hmac(&mac,&f,sizeof f,&f.hmac);memcpy(fin,&f,sizeof f);GNUNET_assert(0==gcry_cipher_encrypt(cipher,fin,sizeof fin,NULL,0));gcry_cipher_close(cipher);
 setup_cipher(&p,&bp,&cipher,&mac);memcpy(eack,&ack,sizeof ack);GNUNET_assert(0==gcry_cipher_encrypt(cipher,eack,sizeof eack,NULL,0));block(cipher,&mac,afterack);gcry_cipher_close(cipher);
 setup_cipher(&p,&bp,&cipher,&mac);struct TCPRekey rkm=rk;calculate_hmac(&mac,&rkm,sizeof rkm,&rkm.hmac);memcpy(erk,&rkm,sizeof rkm);GNUNET_assert(0==gcry_cipher_encrypt(cipher,erk,sizeof erk,NULL,0));gcry_cipher_close(cipher);setup_cipher(&new,&bp,&cipher,&mac);block(cipher,&mac,afterrk);gcry_cipher_close(cipher);
 struct GNUNET_CRYPTO_BlindablePublicKey peer;peer.type=htonl(GNUNET_PUBLIC_KEY_TYPE_EDDSA);peer.eddsa_key=bp.public_key;struct GNUNET_CRYPTO_HpkePublicKey target;GNUNET_assert(GNUNET_OK==GNUNET_CRYPTO_hpke_pk_to_x25519(&peer,&target));
 struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey special;memset(&special,3,sizeof special);struct GNUNET_CRYPTO_HpkeEncapsulation enc;struct GNUNET_ShortHashCode initial_prk;GNUNET_assert(GNUNET_OK==GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand(6,&target,&enc,&special,&initial_prk));
 struct TCPConfirmation actual_c=c;struct TcpHandshakeSignature actual_hs=hs;actual_hs.ephemeral=enc;GNUNET_CRYPTO_eddsa_sign(&a,&actual_hs,&actual_c.sender_sig);unsigned char initial[32+sizeof actual_c],following_ack[sizeof ack];memcpy(initial,&enc,32);memcpy(initial+32,&actual_c,sizeof actual_c);setup_cipher(&initial_prk,&bp,&cipher,&mac);GNUNET_assert(0==gcry_cipher_encrypt(cipher,initial+32,sizeof actual_c,NULL,0));memcpy(following_ack,&ack,sizeof ack);GNUNET_assert(0==gcry_cipher_encrypt(cipher,following_ack,sizeof ack,NULL,0));gcry_cipher_close(cipher);
 printf("{\"kind\":\"exact-source-components-with-normal-util\"");hex("initial_kx",initial,sizeof initial,1);hex("initial_following_ack",following_ack,sizeof following_ack,1);hex("confirmation",&c,sizeof c,1);hex("ack",&ack,sizeof ack,1);hex("rekey",&rk,sizeof rk,1);hex("box1",one,sizeof one,1);hex("box2",two,sizeof two,1);hex("finish",fin,sizeof fin,1);hex("encrypted_ack",eack,sizeof eack,1);hex("after_ack",afterack,sizeof afterack,1);hex("encrypted_rekey",erk,sizeof erk,1);hex("after_rekey",afterrk,sizeof afterrk,1);printf(",\"sizes\":[%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu]}\n",sizeof hs,sizeof as,sizeof rs,sizeof c,32+sizeof c,sizeof ack,sizeof(struct TCPBox),sizeof rk,sizeof f,sizeof(struct TCPNATProbeMessage));return 0;
}
