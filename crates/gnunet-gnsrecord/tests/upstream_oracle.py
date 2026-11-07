#!/usr/bin/env python3
"""Regenerate wire fixtures by compiling the pinned, unmodified upstream C routines.

The upstream implementation is read from an explicit local checkout. Its function
bodies are extracted, not translated to Python/Rust. A minimal platform shim is
compiled in a temporary directory; no libgnunet installation or network is used.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
HASHES = {
    "src/lib/gnsrecord/gnsrecord_serialization.c": "4a87e23e767851edbc2c45a037e5284af0402449841e8e853323d8a031376a98",
    "src/lib/util/strings.c": "15559d5fda3c0254cda47cd88c5b09af758f19e085a99f228996dd94e6eaf4e9",
    "src/include/gnu_name_system_record_types.h": "118bee4e1a598ea8a8b0fa627d0c7b89ab6e4f948daa0b7fc664b65f40a12ba8",
    "src/include/gnunet_gnsrecord_lib.h": "e1dc92421834cb22dab480118df4df97034ee969bd70987ab7cac3cee4527864",
}


def block(source, start, *, semicolon=False):
    begin = source.index(start)
    opened = source.index("{", begin)
    depth = 1
    end = opened + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if semicolon:
        assert source[end] == ";"
        end += 1
    return source[begin:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--write", action="store_true", help="replace checked-in fixtures; default verifies")
    args = parser.parse_args()
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30).strip()
    assert revision == PIN, (revision, PIN)
    contents = {}
    for name, expected in HASHES.items():
        raw = (source / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, name
        contents[name] = raw.decode()
    records = contents["src/lib/gnsrecord/gnsrecord_serialization.c"]
    strings = contents["src/lib/util/strings.c"]
    header = contents["src/include/gnunet_gnsrecord_lib.h"]
    # Original GNUnet function bodies remain AGPL-3.0-or-later and exist only
    # in this generated temporary C translation unit, with their license notice.
    notice = records[:records.index("/**")]
    shim = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "gnu_name_system_record_types.h"
#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t) (SIZE_MAX >> 1))
#endif
#define GNUNET_PACKED __attribute__((packed))
#define DEBUG_GNSRECORDS 0
#define GNUNET_EXTRA_LOGGING 0
#define LOG(...) ((void) 0)
#define GNUNET_break(x) ((void) (x))
#define GNUNET_break_op(x) ((void) (x))
#define GNUNET_assert(x) assert(x)
#define GNUNET_memcpy memcpy
#define GNUNET_memcmp(a,b) memcmp((a),(b),sizeof(*(a)))
enum GNUNET_GenericReturnValue { GNUNET_SYSERR=-1, GNUNET_NO=0, GNUNET_OK=1 };
static uint64_t network64(uint64_t v) {
  uint8_t bytes[8]; uint64_t out;
  for (unsigned i=0;i<8;i++) bytes[i]=(uint8_t)(v>>(56-8*i));
  memcpy(&out,bytes,8); return out;
}
#define GNUNET_htonll network64
'''
    bodies = [
        block(header, "enum GNUNET_GNSRECORD_Flags\n", semicolon=True),
        block(header, "struct GNUNET_GNSRECORD_Data\n", semicolon=True),
        block(records, "struct NetworkRecord\n", semicolon=True),
        block(records, "ssize_t\nGNUNET_GNSRECORD_records_get_size"),
        block(records, "ssize_t\nGNUNET_GNSRECORD_records_serialize"),
        block(strings, "static unsigned int\ngetValue__"),
        block(strings, "char *\nGNUNET_STRINGS_data_to_string ("),
        block(strings, "enum GNUNET_GenericReturnValue\nGNUNET_STRINGS_string_to_data ("),
    ]
    harness = r'''
static void emit(const char *name, const void *bytes, size_t len) {
  printf("%s ",name);
  for (size_t i=0;i<len;i++) printf("%02x",((const uint8_t*)bytes)[i]);
  puts("");
}
static void record_case(const char *name, unsigned count, struct GNUNET_GNSRECORD_Data *rd) {
  uint8_t output[256]; ssize_t size=GNUNET_GNSRECORD_records_get_size(count,rd);
  assert(size>=0 && size<=(ssize_t)sizeof(output));
  assert(GNUNET_GNSRECORD_records_serialize(count,rd,(size_t)size,(char*)output)==size);
  emit(name,output,(size_t)size);
}
int main(void) {
  _Static_assert(sizeof(struct NetworkRecord)==16,"official record size");
  uint8_t addr[4]={192,0,2,1}, ten[10], twenty[20], key[32];
  memset(ten,'a',sizeof(ten)); memset(twenty,'b',sizeof(twenty));
  for (unsigned i=0;i<32;i++) key[i]=(uint8_t)i;
  struct GNUNET_GNSRECORD_Data a={addr,UINT64_C(0x0102030405060708),4,1,GNUNET_GNSRECORD_RF_CRITICAL|GNUNET_GNSRECORD_RF_SUPPLEMENTAL};
  record_case("a",1,&a);
  struct GNUNET_GNSRECORD_Data txt[3]={{key,0,0,16,0},{ten,0x11223344,10,16,GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION},{twenty,UINT64_MAX,20,16,GNUNET_GNSRECORD_RF_PRIVATE}};
  record_case("txt",3,txt);
  struct GNUNET_GNSRECORD_Data mixed[2]={{key,9,32,GNUNET_GNSRECORD_TYPE_PKEY,0},a};
  record_case("pkey_first",2,mixed);
  mixed[0].record_type=GNUNET_GNSRECORD_TYPE_EDKEY;
  record_case("edkey",1,mixed);
  mixed[1]=mixed[0]; mixed[0]=a;
  record_case("edkey_second",2,mixed);
  record_case("empty",0,NULL);
  for (unsigned type=65536; type<=65556; type+=20) {
    uint8_t zone[36]; uint32_t encoded=htonl(type); char text[59];
    memcpy(zone,&encoded,4); memcpy(zone+4,key,32);
    assert(GNUNET_STRINGS_data_to_string(zone,36,text,58)==text+58); text[58]=0;
    emit(type==65536?"pkey_zone":"edkey_zone",text,58);
    uint8_t decoded[36]; assert(GNUNET_STRINGS_string_to_data(text,58,decoded,36)==GNUNET_OK);
    assert(0==memcmp(decoded,zone,36));
    text[57] = 'X'; /* key's last symbol is W; low two padding bits differ. */
    assert(GNUNET_STRINGS_string_to_data(text,58,decoded,36)==GNUNET_OK);
    assert(0==memcmp(decoded,zone,36));
  }
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="gnunet-gnsrecord-oracle-") as work:
        work = Path(work)
        (work / "oracle.c").write_text(notice + shim + "\n".join(bodies) + harness)
        subprocess.run(["cc", "-std=c11", "-O2", "-I", str(source / "src/include"), str(work / "oracle.c"), "-o", str(work / "oracle")], check=True, timeout=60)
        output = subprocess.check_output([str(work / "oracle")], text=True, timeout=10)
    fixture = Path(__file__).parent / "fixtures"
    fixture.mkdir(exist_ok=True)
    for line in output.splitlines():
        name, hex_bytes = line.split(" ", 1)
        expected = bytes.fromhex(hex_bytes)
        path = fixture / (name + ".bin")
        if args.write:
            path.write_bytes(expected)
        else:
            assert path.read_bytes() == expected, name
    print("official C oracle: 8 fixtures matched" if not args.write else "wrote 8 official C fixtures")


if __name__ == "__main__":
    main()
