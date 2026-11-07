#!/usr/bin/env python3
"""Check a behavior trace against the pinned, unmodified C service handlers.

The harness substitutes allocation, scheduling and MQ delivery only. The original
SET, GET, WATCH, disconnect, notification, lookup and string routines execute in
a temporary C program. This is a service-core oracle, not a full daemon test.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
HASHES = {
    "src/service/statistics/gnunet-service-statistics.c": "e3f4d0e0445a892dc715d903018f2a5b62596e4d4431c1c519cc6cb0dcc7767f",
    "src/service/statistics/statistics.h": "38ad15e5b61387f1f91f57592b888331fa018f14575ac60a1233cec5163422ee",
    "src/include/gnunet_common.h": "03bc808f9b183fda2ece71d1e0c5453af127d7f9be59ba80d28df68e46ca6861",
    "src/include/gnunet_container_lib.h": "83e7081220d11f2b3dd5dee676e723481277d50e34a07dc4c52be64e3fa27a1e",
    "src/include/gnunet_protocols.h": "9a86ea10c53da11d68c255fa732d24f9d8695a6405396b965893384d3c952392",
    "src/lib/util/strings.c": "15559d5fda3c0254cda47cd88c5b09af758f19e085a99f228996dd94e6eaf4e9",
}


def block(source, prefix, structure=False):
    start = source.index(prefix)
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end + int(structure)]


def macro(source, name):
    start = source.index("#define " + name + "(")
    end = source.index("\n\n", start)
    return source[start:end]


def program(contents):
    service = contents["src/service/statistics/gnunet-service-statistics.c"]
    header = contents["src/service/statistics/statistics.h"]
    strings = contents["src/lib/util/strings.c"]
    common = contents["src/include/gnunet_common.h"]
    container = contents["src/include/gnunet_container_lib.h"]
    notices = "\n".join(text[:text.index("*/") + 2] for text in (service, header, strings, common, container))
    shim = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gnunet_protocols.h"
#define GNUNET_PACKED __attribute__((packed))
#define GNUNET_OK 1
#define GNUNET_YES 1
#define GNUNET_NO 0
#define GNUNET_SYSERR (-1)
#define GNUNET_MAX_MESSAGE_SIZE 65535
#define GNUNET_assert assert
#define GNUNET_break(x) ((void)(x))
#define GNUNET_log(...) ((void)0)
#define GNUNET_memcpy memcpy
#define GNUNET_malloc(size) calloc(1,size)
#define GNUNET_new(type) ((type *)calloc(1,sizeof(type)))
#define GNUNET_free free
#define GNUNET_SERVICE_client_continue(x) ((void)(x))
#define GNUNET_SERVICE_client_drop(x) abort()
#define GNUNET_SERVICE_client_mark_monitor(x) ((void)(x))
struct GNUNET_SERVICE_Client { unsigned id; };
struct GNUNET_MQ_Handle { unsigned id; };
struct GNUNET_MQ_Envelope { size_t size; void *bytes; };
static uint64_t network64(uint64_t value) {
  uint8_t out[8]; uint64_t result;
  for (unsigned i=0;i<8;i++) out[i]=(uint8_t)(value>>(56-8*i));
  memcpy(&result,out,8); return result;
}
#define GNUNET_htonll network64
#define GNUNET_ntohll network64
'''
    bodies = [block(common, "struct GNUNET_MessageHeader\n", True)]
    bodies += [block(header, "struct " + name + "\n", True) for name in (
        "GNUNET_STATISTICS_ReplyMessage", "GNUNET_STATISTICS_SetMessage", "GNUNET_STATISTICS_WatchValueMessage")]
    bodies += ["\n".join(re.findall(r"^#define GNUNET_STATISTICS_(?:PERSIST_BIT|SETFLAG_\w+) .+$", header, re.M))]
    bodies += [block(service, "struct " + name + "\n", True) for name in (
        "WatchEntry", "StatsEntry", "SubsystemEntry", "ClientEntry")]
    bodies += [macro(container, "GNUNET_CONTAINER_DLL_" + name) for name in ("insert", "remove")]
    bodies += [block(strings, "size_t\nGNUNET_STRINGS_buffer_fill ("),
               block(strings, "unsigned int\nGNUNET_STRINGS_buffer_tokenize (")]
    mq = r'''
static struct SubsystemEntry *sub_head, *sub_tail;
static uint32_t uidgen;
static unsigned client_count=2;
static int in_shutdown=0;
static void *nc=(void *)1;
static void do_shutdown(void) { abort(); }
static struct GNUNET_MQ_Envelope *new_message(void **message,size_t size,unsigned type) {
  struct GNUNET_MQ_Envelope *env=calloc(1,sizeof(*env));
  env->bytes=calloc(1,size); env->size=size; *message=env->bytes;
  struct GNUNET_MessageHeader *head=env->bytes;
  head->size=htons((uint16_t)size); head->type=htons((uint16_t)type);
  return env;
}
#define GNUNET_MQ_msg(m,t) new_message((void **)&(m),sizeof(*(m)),t)
#define GNUNET_MQ_msg_extra(m,n,t) new_message((void **)&(m),sizeof(*(m))+(n),t)
static void GNUNET_MQ_send(struct GNUNET_MQ_Handle *mq,struct GNUNET_MQ_Envelope *env) {
  printf("message %u ",mq->id);
  for (size_t i=0;i<env->size;i++) printf("%02x",((uint8_t *)env->bytes)[i]);
  puts(""); free(env->bytes); free(env);
}
'''
    handlers = [
        block(service, "static void\ntransmit ("),
        block(service, "static void\nhandle_get ("),
        block(service, "static void\nnotify_change ("),
        block(service, "static struct SubsystemEntry *\nfind_subsystem_entry ("),
        block(service, "static struct StatsEntry *\nfind_stat_entry ("),
        block(service, "static void\nhandle_set ("),
        block(service, "static void\nhandle_watch ("),
        block(service, "static void\nhandle_disconnect ("),
        block(service, "static void\nclient_disconnect_cb ("),
    ]
    harness = r'''
static struct ClientEntry *clients[2];
static void names(void *output,const char *sub,const char *name) {
  memcpy(output,sub,strlen(sub)+1);
  memcpy((char *)output+strlen(sub)+1,name,strlen(name)+1);
}
static void set(unsigned client,const char *sub,const char *name,uint32_t flags,uint64_t value) {
  size_t size=sizeof(struct GNUNET_STATISTICS_SetMessage)+strlen(sub)+strlen(name)+2;
  struct GNUNET_STATISTICS_SetMessage *msg=calloc(1,size);
  msg->header.size=htons((uint16_t)size); msg->header.type=htons(GNUNET_MESSAGE_TYPE_STATISTICS_SET);
  msg->flags=htonl(flags); msg->value=GNUNET_htonll(value); names(&msg[1],sub,name);
  handle_set(clients[client],msg); free(msg);
  struct StatsEntry *row=find_stat_entry(find_subsystem_entry(clients[client],sub),name);
  printf("set %u %" PRIu64 " %d %d\n",row->uid,row->value,row->set,row->persistent);
}
static void request(unsigned client,const char *sub,const char *name,int watch) {
  size_t size=sizeof(struct GNUNET_MessageHeader)+strlen(sub)+strlen(name)+2;
  struct GNUNET_MessageHeader *msg=calloc(1,size);
  msg->size=htons((uint16_t)size);
  msg->type=htons(watch?GNUNET_MESSAGE_TYPE_STATISTICS_WATCH:GNUNET_MESSAGE_TYPE_STATISTICS_GET);
  names(&msg[1],sub,name);
  if (watch) {
    uint32_t wid=clients[client]->max_wid;
    handle_watch(clients[client],msg); printf("watch %u %u\n",client,wid);
  } else { handle_get(clients[client],msg); }
  free(msg);
}
int main(void) {
  _Static_assert(sizeof(struct GNUNET_STATISTICS_WatchValueMessage)==24,"watch ABI");
  struct GNUNET_SERVICE_Client transport[2]={{0},{1}};
  struct GNUNET_MQ_Handle queues[2]={{0},{1}};
  for (unsigned i=0;i<2;i++) { clients[i]=calloc(1,sizeof(*clients[i])); clients[i]->client=&transport[i]; clients[i]->mq=&queues[i]; }
  request(0,"s","a",1);
  set(1,"s","a",2,0);
  set(1,"s","a",0,0);
  request(0,"s","a",1);
  set(1,"s","a",1,0);
  set(1,"s","a",2,5);
  request(1,"s","a",1);
  set(1,"s","a",3,(uint64_t)(int64_t)-7);
  set(1,"s","a",1,(uint64_t)(int64_t)-1);
  set(1,"s","a",2,UINT64_MAX);
  set(1,"s","a",1,1);
  set(1,"s","a",1,UINT64_C(0x8000000000000000));
  set(1,"s","a",0,UINT64_C(0x8000000000000005));
  set(1,"s","a",1,UINT64_C(0x8000000000000000));
  set(1,"s","a",1,INT64_MAX);
  set(1,"t","n",1,(uint64_t)(int64_t)-2);
  set(1,"s","z",1,0);
  request(0,"","",0);
  set(1,"t","n",1,0);
  set(1,"s","z",0,3);
  set(1,"s","a",2,5);
  set(1,"s","z",0,3);
  request(0,"","a",0);
  request(0,"s","",0);
  request(0,"","missing",0);
  client_disconnect_cb(NULL,&transport[0],clients[0]); clients[0]=NULL;
  puts("disconnect 0");
  set(1,"s","a",0,7);
  request(1,"","",1);
  set(1,"","",2,0);
  request(1,"","",0);
  struct GNUNET_MessageHeader barrier={htons(4),htons(GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT)};
  handle_disconnect(clients[1],&barrier);
  client_disconnect_cb(NULL,&transport[1],clients[1]);
  return 0;
}
'''
    return notices + shim + "\n".join(bodies) + mq + "\n".join(handlers) + harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30).strip()
    assert revision == PIN, revision
    contents = {}
    for path, expected in HASHES.items():
        raw = (source / path).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, path
        contents[path] = raw.decode()
    with tempfile.TemporaryDirectory(prefix="gnunet-statistics-oracle-") as folder:
        folder = Path(folder)
        code, binary = folder / "oracle.c", folder / "oracle"
        code.write_text(program(contents))
        outputs = []
        # INT64_MIN negation in the pinned C source is undefined by ISO C. Run
        # both ordinary optimized C and defined wrapping C; require agreement.
        for flags in (("-O2",), ("-O0", "-fwrapv")):
            subprocess.run(["cc", "-std=c11", *flags, "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter", "-Wno-sign-compare", "-I", str(source / "src/include"),
                            str(code), "-o", str(binary)], check=True, timeout=60)
            outputs.append(subprocess.check_output([str(binary)], timeout=10))
        assert outputs[0] == outputs[1], "pinned C arithmetic differs between optimization profiles"
    fixture = Path(__file__).with_name("fixtures") / "service_trace.txt"
    if args.write:
        fixture.write_bytes(outputs[0])
    else:
        assert fixture.read_bytes() == outputs[0], fixture
    print(f"Verified original C service handlers: {len(outputs[0].splitlines())} trace lines, 2 compiler profiles")


if __name__ == "__main__":
    main()
