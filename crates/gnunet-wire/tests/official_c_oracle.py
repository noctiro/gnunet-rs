#!/usr/bin/env python3
"""Regenerate wire fixtures from the pinned reference C declarations and macros.

Only structural bytes are generated: this does not run a GNUnet daemon or validate
DHT path signatures. Source C declarations are extracted at runtime, not vendored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"


def declaration(text, name):
    match = re.search(r"^struct " + re.escape(name) + r"\s*\{", text, re.M)
    if match is None:
        raise ValueError("missing reference declaration: " + name)
    end = text.index("\n};", match.start()) + 3
    return text[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("official_vectors"))
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("reference checkout differs from pinned revision")
    paths = {
        "common": "src/include/gnunet_common.h",
        "crypto": "src/include/gnunet_crypto_lib.h",
        "time": "src/include/gnunet_time_lib.h",
        "dht_api": "src/include/gnunet_dht_service.h",
        "dht": "src/service/dht/dht.h",
        "neighbours": "src/service/dht/gnunet-service-dht_neighbours.c",
        "protocols": "src/include/gnunet_protocols.h",
    }
    subprocess.run(["git", "-C", str(args.upstream), "diff", "--quiet", "HEAD", "--", *paths.values()], check=True)
    sources = {name: (args.upstream / path).read_text() for name, path in paths.items()}
    names = re.findall(r"^#define\s+(GNUNET_MESSAGE_TYPE_\w+)\s+\d+", sources["protocols"].replace("\\\n", " "), re.M)
    if len(names) != 677:
        raise ValueError("unexpected reference registry count")
    structs = [("common", "GNUNET_MessageHeader"), ("common", "GNUNET_HashCode"),
               ("crypto", "GNUNET_CRYPTO_SignaturePurpose"),
               ("crypto", "GNUNET_CRYPTO_EddsaPublicKey"), ("crypto", "GNUNET_PeerIdentity"),
               ("crypto", "GNUNET_CRYPTO_EddsaSignature"), ("time", "GNUNET_TIME_AbsoluteNBO"),
               ("dht_api", "GNUNET_DHT_PathElement"), ("dht", "PeerPutMessage"),
               ("neighbours", "PeerGetMessage"), ("neighbours", "PeerResultMessage")]
    notices = "\n".join(text[:text.index("*/") + 2] for text in sources.values())
    program = notices + "\n" + '''#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#define ENABLE_MALICIOUS 1
#include "gnunet_protocols.h"
#define GNUNET_PACKED __attribute__((packed))
#define DHT_BLOOM_SIZE 128
'''
    program += "\n".join(declaration(sources[source], name) for source, name in structs)
    program += r'''
static void be64(void *output, uint64_t value) {
  unsigned char *bytes = output;
  for (unsigned i = 0; i < 8; i++) bytes[7-i] = value >> (8*i);
}
static FILE *open_out(const char *name) { return fopen(name, "wb"); }
int main(void) {
  const unsigned char block[] = {0xde,0xad,0xbe,0xef};
  struct PeerGetMessage get = {0};
  get.header.size = htons(sizeof(get)+7);
  get.header.type = htons(GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
  get.type = htonl(0x01020304); get.options = htons(0x0047);
  get.hop_count = htons(9); get.desired_replication_level = htons(11);
  get.result_filter_size = htons(3);
  memset(get.bloomfilter,0xa5,sizeof(get.bloomfilter)); memset(&get.key,0xb6,sizeof(get.key));
  FILE *f = open_out("dht-get.bin");
  if (!f) return 1;
  fwrite(&get,sizeof(get),1,f); fwrite("\xab\xcd\xef" "abc?",7,1,f); fclose(f);
  struct PeerPutMessage put = {0};
  put.header.size = htons(sizeof(put)+sizeof(block));
  put.header.type = htons(GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
  put.type = htonl(0x01020304); put.options = htons(0x0041);
  put.hop_count = htons(9); put.desired_replication_level = htons(11);
  be64(&put.expiration_time, UINT64_C(0x0102030405060708));
  memset(put.bloomfilter,0xa5,sizeof(put.bloomfilter)); memset(&put.key,0xb6,sizeof(put.key));
  f = open_out("dht-put.bin"); if (!f) return 1;
  fwrite(&put,sizeof(put),1,f); fwrite(block,sizeof(block),1,f); fclose(f);
  struct GNUNET_PeerIdentity truncated; memset(&truncated,0xc7,sizeof(truncated));
  struct GNUNET_DHT_PathElement path[2];
  memset(&path[0].sig,0xd8,sizeof(path[0].sig)); memset(&path[0].pred,0xe9,sizeof(path[0].pred));
  memset(&path[1].sig,0xea,sizeof(path[1].sig)); memset(&path[1].pred,0xfb,sizeof(path[1].pred));
  struct GNUNET_CRYPTO_EddsaSignature sender; memset(&sender,0x9a,sizeof(sender));
  put.options = htons(0x000b); put.put_path_length = htons(1);
  put.header.size = htons(sizeof(put)+sizeof(truncated)+sizeof(path[0])+sizeof(sender)+sizeof(block));
  f = open_out("dht-put-tracked.bin"); if (!f) return 1;
  fwrite(&put,sizeof(put),1,f); fwrite(&truncated,sizeof(truncated),1,f);
  fwrite(path,sizeof(path[0]),1,f); fwrite(&sender,sizeof(sender),1,f); fwrite(block,sizeof(block),1,f); fclose(f);
  struct PeerResultMessage result = {0};
  result.header.type = htons(GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
  result.type = htonl(0x01020304); result.options = htons(0x000b);
  result.put_path_length=htons(1); result.get_path_length=htons(1);
  be64(&result.expiration_time,UINT64_C(0x0102030405060708)); memset(&result.key,0xb6,sizeof(result.key));
  result.header.size=htons(sizeof(result)+sizeof(truncated)+sizeof(path)+sizeof(sender)+sizeof(block));
  f = open_out("dht-result-tracked.bin"); if (!f) return 1;
  fwrite(&result,sizeof(result),1,f); fwrite(&truncated,sizeof(truncated),1,f);
  fwrite(path,sizeof(path),1,f); fwrite(&sender,sizeof(sender),1,f); fwrite(block,sizeof(block),1,f); fclose(f);
  struct GNUNET_CRYPTO_SignaturePurpose purpose = {htonl(16),htonl(0x01020304)};
  f=open_out("signature-purpose.bin"); if (!f) return 1;
  fwrite(&purpose,sizeof(purpose),1,f); fclose(f);
  f=open_out("message-registry.tsv"); if (!f) return 1;
'''
    for name in names:
        program += f'  fprintf(f,"{name.removeprefix("GNUNET_MESSAGE_TYPE_")}\\t%u\\n",(unsigned){name});\n'
    program += '  fclose(f); return 0;\n}\n'
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gnunet-wire-c-oracle-") as work:
        source = Path(work) / "oracle.c"
        binary = Path(work) / "oracle"
        source.write_text(program)
        compile_command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-I", str((args.upstream / "src/include").resolve()), str(source), "-o", str(binary)]
        subprocess.run(compile_command, check=True)
        subprocess.run([str(binary)], cwd=args.output, check=True)
    metadata = {
        "schema": 1, "revision": REVISION,
        "method": "Compiled the original reference C struct declarations and message macros; generated bytes using those C objects. No cryptographic validity or peer interoperation is claimed.",
        "registry_note": "Includes all 677 assignments, including the conditional RPS numeric assignment; no RPS runtime is compiled.",
        "inputs": [{"path": path, "sha256": hashlib.sha256((args.upstream/path).read_bytes()).hexdigest()} for path in paths.values()],
        "fixtures": [{"path": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(args.output.iterdir()) if p.is_file() and p.name != "provenance.json"],
    }
    (args.output / "provenance.json").write_text(json.dumps(metadata, indent=2)+"\n")


if __name__ == "__main__":
    main()
