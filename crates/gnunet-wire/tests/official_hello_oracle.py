#!/usr/bin/env python3
"""Verify HELLO fixtures with pinned upstream structs and unmodified builder bodies."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
HASHES = {
    "src/lib/hello/hello-uri.c": "4c162df254446ca2ac7f363a50c2c938e4bfdd27b55b57d1e0d3b3ab205d2ecb",
    "src/include/gnunet_protocols.h": "9a86ea10c53da11d68c255fa732d24f9d8695a6405396b965893384d3c952392",
    "src/include/gnunet_signatures.h": "bb546c9f1af6f09664a8c09d75543bd78fa3f4a4ccd17cce5bff9f4c4a5eea90",
}


def block(source, start, semicolon=False):
    begin = source.index(start)
    opened = source.index("{", begin)
    end, depth = opened + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if semicolon:
        assert source[end] == ";"
        end += 1
    return source[begin:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = args.source.resolve()
    assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=30).strip() == PIN
    for name, expected in HASHES.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
    source = (root / "src/lib/hello/hello-uri.c").read_text()
    # Preserve upstream AGPL notice in the temporary translation unit. Only
    # fixture bytes and this independently written extraction harness are shipped.
    notice = source[:source.index("/**")]
    shim = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#define GNUNET_PACKED __attribute__((packed))
#define GNUNET_assert assert
#define GNUNET_malloc(n) calloc(1,(n))
struct GNUNET_MessageHeader { uint16_t size, type; } __attribute__((packed));
struct GNUNET_PeerIdentity { uint8_t public_key[32]; };
struct GNUNET_CRYPTO_EddsaSignature { uint8_t sig[64]; };
struct GNUNET_CRYPTO_SignaturePurpose { uint32_t size,purpose; } __attribute__((packed));
struct GNUNET_HashCode { uint8_t bits[64]; };
struct GNUNET_TIME_Absolute { uint64_t abs_value_us; };
struct GNUNET_TIME_AbsoluteNBO { uint64_t abs_value_us; } __attribute__((packed));
static struct GNUNET_TIME_AbsoluteNBO GNUNET_TIME_absolute_hton(struct GNUNET_TIME_Absolute t) {
  struct GNUNET_TIME_AbsoluteNBO n; uint8_t bytes[8];
  for(unsigned i=0;i<8;i++) bytes[i]=(uint8_t)(t.abs_value_us>>(56-8*i));
  memcpy(&n,bytes,8); return n;
}
#define GNUNET_TIME_UNIT_ZERO_ABS ((struct GNUNET_TIME_Absolute){0})
#define GNUNET_HELLO_ADDRESS_EXPIRATION UINT64_C(172800000000)
static struct GNUNET_TIME_Absolute GNUNET_TIME_relative_to_absolute(uint64_t ignored) { (void)ignored; abort(); }
'''
    structs = [block(source, "struct " + name + "\n", True) for name in (
        "PilsHelloSignaturePurpose", "HelloUriMessage", "BlockHeader", "DhtHelloMessage", "Address", "GNUNET_HELLO_Builder")]
    funcs = [block(source, begin) for begin in (
        "size_t\nGNUNET_HELLO_get_builder_to_block_size",
        "void\nGNUNET_HELLO_builder_to_block",
        "struct GNUNET_MessageHeader *\nGNUNET_HELLO_builder_to_dht_hello_msg")]
    harness = r'''
static void emit(const char *name, const void *bytes, size_t length) {
 printf("%s ",name);for(size_t i=0;i<length;i++)printf("%02x",((const uint8_t*)bytes)[i]);puts("");
}
int main(void) {
 _Static_assert(sizeof(struct BlockHeader)==104,"block header");
 _Static_assert(sizeof(struct DhtHelloMessage)==80,"DHT header");
 _Static_assert(sizeof(struct HelloUriMessage)==8,"HELLO envelope");
 struct GNUNET_PeerIdentity peer;struct GNUNET_CRYPTO_EddsaSignature sig;
 for(unsigned i=0;i<32;i++)peer.public_key[i]=(uint8_t)i;
 for(unsigned i=0;i<64;i++)sig.sig[i]=(uint8_t)(64+i);
 struct GNUNET_TIME_Absolute expiry={UINT64_C(0x0102030405060708)};
 const char tcp[]="tcp://127.0.0.1:2086",udp[]="udp://example:2086";
 struct Address a={0},b={0};a.uri=tcp;a.uri_len=sizeof(tcp);a.next=&b;b.prev=&a;b.uri=udp;b.uri_len=sizeof(udp);
 struct GNUNET_HELLO_Builder builder={.a_head=&a,.a_tail=&b,.a_length=2};
 size_t size=GNUNET_HELLO_get_builder_to_block_size(&builder);
 uint8_t raw[256];GNUNET_HELLO_builder_to_block(&builder,&peer,&sig,expiry,(char*)raw);emit("hello_block",raw,size);
 struct GNUNET_MessageHeader *dht=GNUNET_HELLO_builder_to_dht_hello_msg(&builder,&peer,&sig,expiry);
 emit("hello_dht",dht,ntohs(dht->size));free(dht);
 uint8_t framed[264]={0};struct HelloUriMessage *msg=(struct HelloUriMessage*)framed;
 msg->header.size=htons((uint16_t)(sizeof(*msg)+size));msg->header.type=htons(GNUNET_MESSAGE_TYPE_HELLO_URI);msg->url_counter=htons(2);
 GNUNET_HELLO_builder_to_block(&builder,&peer,&sig,expiry,(char*)&msg[1]);emit("hello_message",framed,ntohs(msg->header.size));
 struct GNUNET_HELLO_Builder empty={0};size=GNUNET_HELLO_get_builder_to_block_size(&empty);
 memset(framed,0,sizeof(framed));msg->header.size=htons((uint16_t)(sizeof(*msg)+size));msg->header.type=htons(GNUNET_MESSAGE_TYPE_HELLO_URI);
 GNUNET_HELLO_builder_to_block(&empty,&peer,&sig,expiry,(char*)&msg[1]);emit("hello_empty",framed,ntohs(msg->header.size));
 struct PilsHelloSignaturePurpose payload={0};payload.purpose.size=htonl(sizeof(payload));payload.purpose.purpose=htonl(GNUNET_SIGNATURE_PURPOSE_HELLO);payload.expiration_time=GNUNET_TIME_absolute_hton(expiry);
 for(unsigned i=0;i<64;i++)payload.h_addrs.bits[i]=(uint8_t)(128+i);
 emit("hello_signed_payload",&payload,sizeof(payload));return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="gnunet-hello-oracle-") as work:
        work = Path(work)
        (work / "oracle.c").write_text(notice + shim + "\n".join(structs + funcs) + harness)
        subprocess.run(["cc", "-std=c11", "-O2", "-I", str(root / "src/include"), str(work / "oracle.c"), "-o", str(work / "oracle")], check=True, timeout=60)
        output = subprocess.check_output([str(work / "oracle")], text=True, timeout=10)
    fixture = Path(__file__).parent / "fixtures"
    fixture.mkdir(exist_ok=True)
    for line in output.splitlines():
        name, data = line.split(" ", 1)
        path = fixture / (name + ".bin")
        encoded = bytes.fromhex(data)
        if args.write:
            path.write_bytes(encoded)
        else:
            assert path.read_bytes() == encoded, name
    print("official C HELLO oracle: 5 fixtures matched" if not args.write else "wrote 5 official C HELLO fixtures")


if __name__ == "__main__":
    main()
