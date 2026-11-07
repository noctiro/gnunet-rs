/* External finite normal-library/layout observer, NOT a C service substitute. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pils_service.h"
#include "peerstore_common.h"
#include "peerstore.h"
#include "transport.h"
#include "pils.h"
#include "nat.h"
static void hex(const void *data,size_t n){const unsigned char *p=data;putchar('"');for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('"');}
int main(void){
 struct GNUNET_CRYPTO_EddsaPrivateKey initial,derived;struct GNUNET_CRYPTO_EddsaPublicKey pub;struct GNUNET_HashCode hash;struct GNUNET_PeerIdentity peer;struct GNUNET_MQ_Envelope *env;
 memset(&initial,22,sizeof(initial));GNUNET_CRYPTO_hash("",0,&hash);GNUNET_PILS_derive_pid(sizeof(initial),(const uint8_t*)&initial,&hash,&derived);GNUNET_CRYPTO_eddsa_key_get_public(&derived,&pub);peer.public_key=pub;
 printf("{\"sizes\":[%zu,%zu,%zu,%zu,%zu,%zu],\"pils_public\":",sizeof(struct PeerstoreRecordMessage),sizeof(struct PeerstoreIterationStartMessage),sizeof(struct GNUNET_TRANSPORT_AddQueueMessage),sizeof(struct GNUNET_TRANSPORT_IncomingMessage),sizeof(struct PeerIdUpdateMessage),sizeof(struct GNUNET_NAT_RegisterMessage));hex(&pub,sizeof(pub));
 const uint64_t value=GNUNET_htonll(123456789);env=PEERSTORE_create_record_mq_envelope(0x10203040,"transport_tcp_communicator",&peer,"transport-tcp-communicator-handshake",&value,sizeof(value),GNUNET_TIME_UNIT_FOREVER_ABS,GNUNET_PEERSTORE_STOREOPTION_REPLACE,GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);const struct GNUNET_MessageHeader *message=GNUNET_MQ_env_get_msg(env);printf(",\"store\":");hex(message,ntohs(message->size));GNUNET_MQ_discard(env);
 struct sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;address.sin_port=htons(80);address.sin_addr.s_addr=htonl(0x7f000001);
#if HAVE_SOCKADDR_IN_SIN_LEN
 address.sin_len=sizeof(address);
#endif
 printf(",\"native_v4\":");hex(&address,sizeof(address));
 struct GNUNET_NAT_RegisterMessage *reg;env=GNUNET_MQ_msg_extra(reg,sizeof(address)+sizeof("communicator-tcp"),GNUNET_MESSAGE_TYPE_NAT_REGISTER);reg->flags=GNUNET_NAT_RF_ADDRESSES|GNUNET_NAT_RF_REVERSAL;reg->proto=IPPROTO_TCP;reg->str_len=htons(sizeof("communicator-tcp"));reg->num_addrs=htons(1);memcpy(&reg[1],&address,sizeof(address));memcpy((char*)&reg[1]+sizeof(address),"communicator-tcp",sizeof("communicator-tcp"));printf(",\"nat_register_layout\":");hex(reg,ntohs(reg->header.size));GNUNET_MQ_discard(env);puts("}");GNUNET_CRYPTO_zero_keys(&initial,sizeof(initial));GNUNET_CRYPTO_zero_keys(&derived,sizeof(derived));return 0;
}
