#!/usr/bin/env python3
"""Real Unix IPC between the Rust CLI and pinned official GNUnet C protocol components.

Extracts and compiles the reference message structs, tokenizer and GET/SET check
functions. The small C endpoint replaces GNUnet's service scheduler and database;
this is NOT a full C-daemon or P2P peer-interoperability test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
EXPECTED_VALUE = 0x0102030405060708


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def structure(text, name):
    start = re.search(r"^struct " + re.escape(name) + r"\s*\{", text, re.M)
    if start is None:
        raise ValueError("missing reference structure " + name)
    end = text.index("\n};", start.start()) + 3
    return text[start.start():end]


def function(text, name):
    start = re.search(r"^(?:static )?(?:unsigned int|int)\s*\n" + re.escape(name) + r"\s*\(", text, re.M)
    if start is None:
        raise ValueError("missing reference function " + name)
    brace = text.index("{", start.end())
    depth = 1
    end = brace + 1
    while depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    return text[start.start():end]


def c_program(source):
    common = (source / "src/include/gnunet_common.h").read_text()
    statistics = (source / "src/service/statistics/statistics.h").read_text()
    service = (source / "src/service/statistics/gnunet-service-statistics.c").read_text()
    strings = (source / "src/lib/util/strings.c").read_text()
    notices = "\n".join(text[:text.index("*/") + 2] for text in (common, statistics, service, strings))
    program = notices + "\n" + r'''#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "gnunet_protocols.h"
#define GNUNET_PACKED __attribute__((packed))
#define GNUNET_OK 1
#define GNUNET_SYSERR (-1)
#define GNUNET_break(value) ((void)(value))
'''
    program += structure(common, "GNUNET_MessageHeader") + "\n"
    program += structure(statistics, "GNUNET_STATISTICS_ReplyMessage") + "\n"
    program += structure(statistics, "GNUNET_STATISTICS_SetMessage") + "\n"
    program += "\n".join(re.findall(r"^#define GNUNET_STATISTICS_(?:PERSIST_BIT|SETFLAG_\w+) .+$", statistics, re.M)) + "\n"
    program += function(strings, "GNUNET_STRINGS_buffer_tokenize") + "\n"
    program += function(service, "check_get") + "\n"
    program += function(service, "check_set") + "\n"
    program += r'''
_Static_assert(sizeof(struct GNUNET_MessageHeader)==4,"official header ABI");
_Static_assert(sizeof(struct GNUNET_STATISTICS_ReplyMessage)==16,"official VALUE ABI");
_Static_assert(sizeof(struct GNUNET_STATISTICS_SetMessage)==16,"official SET ABI");
static void fail(const char *reason) { fprintf(stderr,"C endpoint: %s (errno %d)\n",reason,errno); exit(2); }
static void be64(void *destination, uint64_t value) {
  unsigned char *bytes=destination;
  for (unsigned i=0;i<8;i++) bytes[7-i]=(unsigned char)(value>>(8*i));
}
static uint64_t read64(const void *source) {
  const unsigned char *bytes=source; uint64_t value=0;
  for (unsigned i=0;i<8;i++) value=(value<<8)|bytes[i];
  return value;
}
static void read_exact(int fd, void *destination, size_t size) {
  unsigned char *bytes=destination;
  while (size) {
    ssize_t count=read(fd,bytes,size);
    if (count<0 && errno==EINTR) continue;
    if (count<=0) fail("incomplete Rust request");
    bytes+=count; size-=(size_t)count;
  }
}
static size_t receive_frame(int fd, unsigned char *bytes) {
  read_exact(fd,bytes,sizeof(struct GNUNET_MessageHeader));
  struct GNUNET_MessageHeader *header=(struct GNUNET_MessageHeader*)bytes;
  size_t size=ntohs(header->size);
  if (size<sizeof(*header)) fail("invalid Rust frame size");
  read_exact(fd,bytes+sizeof(*header),size-sizeof(*header));
  return size;
}
static void write_fragmented(int fd,const void *source,size_t size) {
  const unsigned char *bytes=source;
  const struct timespec tick={0,1000000};
  for (size_t i=0;i<size;i++) {
    ssize_t count;
    do { count=write(fd,bytes+i,1); } while (count<0 && errno==EINTR);
    if (count!=1) fail("incomplete C reply");
    nanosleep(&tick,NULL);
  }
}
static void names(const void *buffer,size_t size) {
  const char *subsystem=NULL,*name=NULL;
  if (GNUNET_STRINGS_buffer_tokenize(buffer,size,2,&subsystem,&name)!=size) fail("reference string validation");
  if (strcmp(subsystem,"core") || strcmp(name,"peers")) fail("unexpected Rust selector");
}
static void self_check(void) {
  unsigned char bytes[32]={0};
  struct GNUNET_MessageHeader *get=(struct GNUNET_MessageHeader*)bytes;
  get->size=htons(4+11); get->type=htons(GNUNET_MESSAGE_TYPE_STATISTICS_GET);
  memcpy(bytes+4,"core\0peers\0",11);
  if (check_get(NULL,get)!=GNUNET_OK) fail("reference valid GET self-check");
  bytes[14]='x';
  if (check_get(NULL,get)!=GNUNET_SYSERR) fail("reference malformed GET self-check");
  struct GNUNET_STATISTICS_SetMessage *set=(struct GNUNET_STATISTICS_SetMessage*)bytes;
  set->header.size=htons(16+11); set->header.type=htons(GNUNET_MESSAGE_TYPE_STATISTICS_SET);
  memcpy(bytes+16,"core\0peers\0",11);
  if (check_set(NULL,set)!=GNUNET_OK) fail("reference valid SET self-check");
  bytes[26]='x';
  if (check_set(NULL,set)!=GNUNET_SYSERR) fail("reference malformed SET self-check");
}
int main(int argc,char **argv) {
  if (argc!=3) fail("expected socket and case arguments");
  signal(SIGPIPE,SIG_IGN); umask(0077);
  self_check();
  int server=socket(AF_UNIX,SOCK_STREAM,0); if (server<0) fail("socket");
  struct sockaddr_un address={0}; address.sun_family=AF_UNIX;
  if (strlen(argv[1])>=sizeof(address.sun_path)) fail("socket path too long");
  memcpy(address.sun_path,argv[1],strlen(argv[1])+1);
#ifdef __APPLE__
  address.sun_len=sizeof(address);
#endif
  if (bind(server,(struct sockaddr*)&address,sizeof(address)) || listen(server,1)) fail("bind/listen");
  puts("{\"event\":\"listening\",\"reference_validator_checks\":4}"); fflush(stdout);
  int client=accept(server,NULL,NULL); if (client<0) fail("accept");
  struct timeval timeout={15,0};
  if (setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) fail("receive timeout");
  unsigned char request[65535]; size_t size=receive_frame(client,request);
  const struct GNUNET_MessageHeader *header=(const struct GNUNET_MessageHeader*)request;
  if (strncmp(argv[2],"set",3)==0) {
    if (ntohs(header->type)!=GNUNET_MESSAGE_TYPE_STATISTICS_SET || size<18) fail("expected official SET");
    const struct GNUNET_STATISTICS_SetMessage *set=(const struct GNUNET_STATISTICS_SetMessage*)request;
    if (check_set(NULL,set)!=GNUNET_OK) fail("official check_set rejected Rust bytes");
    names(&set[1],size-sizeof(*set));
    if (ntohl(set->flags)!=(GNUNET_STATISTICS_SETFLAG_RELATIVE|GNUNET_STATISTICS_SETFLAG_PERSISTENT)) fail("relative/persistent flags");
    if (read64(&set->value)!=(uint64_t)(int64_t)-7) fail("signed relative delta");
    puts("{\"event\":\"reference_set_validated\",\"flags\":3,\"delta\":-7}");
    size=receive_frame(client,request);
    if (size!=sizeof(*header) || ntohs(header->type)!=GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT) fail("expected official DISCONNECT");
    struct GNUNET_MessageHeader response={htons(4),htons(strcmp(argv[2],"set-wrong-confirm")==0 ? GNUNET_MESSAGE_TYPE_STATISTICS_END : GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT_CONFIRM)};
    write_fragmented(client,&response,sizeof(response));
  } else {
    if (ntohs(header->type)!=GNUNET_MESSAGE_TYPE_STATISTICS_GET || size<6) fail("expected official GET");
    if (check_get(NULL,header)!=GNUNET_OK) fail("official check_get rejected Rust bytes");
    names(&header[1],size-sizeof(*header));
    puts("{\"event\":\"reference_get_validated\"}");
    if (strcmp(argv[2],"get-deadline")==0) {
      const struct timespec delay={11,0}; nanosleep(&delay,NULL);
    } else if (strcmp(argv[2],"get-truncated")==0) {
      const unsigned char prefix[]={0,27}; write_fragmented(client,prefix,sizeof(prefix));
    } else {
      unsigned char bytes[sizeof(struct GNUNET_STATISTICS_ReplyMessage)+11]={0};
      struct GNUNET_STATISTICS_ReplyMessage *reply=(struct GNUNET_STATISTICS_ReplyMessage*)bytes;
      reply->header.size=htons(sizeof(bytes)); reply->header.type=htons(GNUNET_MESSAGE_TYPE_STATISTICS_VALUE);
      reply->uid=htonl(GNUNET_STATISTICS_PERSIST_BIT|7);
      be64(&reply->value,UINT64_C(0x0102030405060708)); memcpy(&reply[1],"core\0peers\0",11);
      write_fragmented(client,bytes,sizeof(bytes));
      if (strcmp(argv[2],"get-no-end")!=0) {
        struct GNUNET_MessageHeader end={htons(4),htons(GNUNET_MESSAGE_TYPE_STATISTICS_END)};
        write_fragmented(client,&end,sizeof(end));
      }
    }
  }
  if (close(client) || close(server) || unlink(argv[1])) fail("cleanup");
  puts("{\"event\":\"reference_case_complete\"}"); fflush(stdout);
  return 0;
}
'''
    # umask is declared by sys/stat.h on both supported POSIX hosts.
    return program.replace("#include <sys/time.h>", "#include <sys/time.h>\n#include <sys/stat.h>")


def run_case(root, work, endpoint, binary, case, expect_success):
    directory = root / case
    directory.mkdir()
    socket = work / (case + ".sock")
    defaults = work / (case + "-config")
    defaults.mkdir(mode=0o700)
    environment = {**os.environ, "GNUNET_BASE_CONFIG": str(defaults)}
    started = time.monotonic()
    result = {"case": case, "expected_rust_success": expect_success, "passed": False}
    server = None
    try:
        with (directory / "c.stdout.txt").open("wb") as cout, (directory / "c.stderr.txt").open("wb") as cerr:
            server = subprocess.Popen([str(endpoint), str(socket), case], stdout=cout, stderr=cerr, stdin=subprocess.DEVNULL)
            limit = time.monotonic() + 5
            while True:
                if server.poll() is not None:
                    raise RuntimeError("reference C endpoint exited before listening")
                if b'"listening"' in (directory / "c.stdout.txt").read_bytes():
                    break
                if time.monotonic() >= limit:
                    raise TimeoutError("reference C endpoint did not become ready")
                time.sleep(.01)
            action = "set" if case.startswith("set") else "get"
            command = [str(binary), "statistics", action, str(socket), "core", "peers"]
            if action == "set":
                command.extend(["-7", "--relative", "--persistent"])
            result["rust_command"] = command
            child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env=environment)
            (directory / "rust.stdout.txt").write_bytes(child.stdout)
            (directory / "rust.stderr.txt").write_bytes(child.stderr)
            result["rust_exit_code"] = child.returncode
            server.wait(timeout=4)
            result["c_exit_code"] = server.returncode
        if server.returncode != 0:
            raise AssertionError("reference C endpoint rejected operation")
        rows = [json.loads(line) for line in child.stdout.splitlines()]
        if expect_success:
            if child.returncode != 0:
                raise AssertionError("Rust CLI rejected reference C reply")
            if case == "get":
                if len(rows) != 2:
                    raise AssertionError("GET did not produce exactly one VALUE and END")
                value, end = rows
                expected = {"event": "statistics_value", "uid": 7, "persistent": True,
                            "value": EXPECTED_VALUE, "subsystem": "core", "name": "peers",
                            "subsystem_bytes": list(b"core"), "name_bytes": list(b"peers")}
                if value != expected or end != {"event": "statistics_end", "count": 1}:
                    raise AssertionError("Rust decoded different C statistic fields")
            elif rows != [{"event": "statistics_set_confirmed"}]:
                raise AssertionError("SET did not receive exact official confirmation")
        else:
            if child.returncode == 0:
                raise AssertionError("malformed/incomplete C reply falsely completed Rust operation")
            if any(row.get("event") in ("statistics_end", "statistics_set_confirmed") for row in rows):
                raise AssertionError("failure emitted a successful completion")
            if case == "get-deadline" and b"deadline" not in child.stderr.lower():
                raise AssertionError("unresponsive C endpoint did not use original Rust deadline")
        c_rows = [json.loads(line) for line in (directory / "c.stdout.txt").read_bytes().splitlines()]
        if len(c_rows) != 3 or c_rows[0].get("reference_validator_checks") != 4:
            raise AssertionError("missing nonempty C reference checks")
        if c_rows[1].get("event") != "reference_" + action + "_validated" or c_rows[2].get("event") != "reference_case_complete":
            raise AssertionError("C did not validate and finish the actual request")
        if socket.exists():
            raise AssertionError("reference endpoint did not clean its socket")
        result.update(passed=True, c_reference_validator_checks=4, rust_rows=rows,
                      c_rows=c_rows, socket_removed=True)
    except BaseException as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        if server is not None and server.poll() is None:
            server.kill()
            server.wait(timeout=3)
            result["c_terminated_by_harness"] = True
            result["c_exit_code"] = server.returncode
        if socket.exists():
            socket.unlink()
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
        save(directory / "case.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="clean pinned official GNUnet checkout")
    parser.add_argument("--binary", required=True, type=Path, help="new official Rust gnunet-cli")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory, never overwritten")
    args = parser.parse_args()
    source, binary, output = args.source.resolve(), args.binary.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "level": "official-c-protocol-component", "full_c_daemon": False,
              "p2p_peer_interoperation": False, "status": "failed", "cases": [],
              "scope": "Real Rust CLI and compiled official C message structures, tokenizer and validators over Unix sockets; no GNUnet scheduler, persistent statistics database or P2P daemon is implemented by the endpoint."}
    try:
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if revision != REVISION:
            raise ValueError("upstream source revision does not match compatibility baseline")
        inputs = ["src/include/gnunet_common.h", "src/include/gnunet_protocols.h",
                  "src/service/statistics/statistics.h", "src/service/statistics/gnunet-service-statistics.c",
                  "src/lib/util/strings.c"]
        subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", *inputs], check=True)
        report["upstream"] = {"revision": revision, "inputs": [{"path": name, "sha256": sha(source / name)} for name in inputs]}
        version = subprocess.run([str(binary), "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if version.returncode or b"official GNUnet v0.29.1" not in version.stdout:
            raise ValueError("binary is not the new official GNUnet Rust CLI")
        snapshot = output / "gnunet-cli.snapshot"
        shutil.copyfile(binary, snapshot)
        snapshot.chmod(0o700)
        report["rust"] = {"input_binary": str(binary), "snapshot": str(snapshot),
                          "sha256": sha(snapshot), "version": version.stdout.decode().strip()}
        c_file, endpoint = output / "statistics-reference.c", output / "statistics-reference"
        c_file.write_text(c_program(source))
        compile_command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                           "-I", str(source / "src/include"), str(c_file), "-o", str(endpoint)]
        compiled = subprocess.run(compile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (output / "compile.stdout.txt").write_bytes(compiled.stdout)
        (output / "compile.stderr.txt").write_bytes(compiled.stderr)
        report["c_compile"] = {"command": compile_command, "exit_code": compiled.returncode,
                               "generated_source_sha256": sha(c_file)}
        if compiled.returncode:
            raise RuntimeError("reference component compilation failed")
        with tempfile.TemporaryDirectory(prefix="gni-", dir="/tmp") as work:
            for case, success in (("get", True), ("set", True), ("get-no-end", False),
                                  ("get-truncated", False), ("set-wrong-confirm", False), ("get-deadline", False)):
                report["cases"].append(run_case(output, Path(work), endpoint, snapshot, case, success))
        report["rust"]["snapshot_unchanged"] = sha(snapshot) == report["rust"]["sha256"]
        report["upstream"]["inputs_unchanged"] = all(sha(source / row["path"]) == row["sha256"] for row in report["upstream"]["inputs"])
        report["case_count"] = len(report["cases"])
        report["failed"] = sum(not case["passed"] for case in report["cases"])
        if report["case_count"] != 6 or report["failed"] or not report["rust"]["snapshot_unchanged"] or not report["upstream"]["inputs_unchanged"]:
            raise AssertionError("component interoperation failed or inputs changed")
        report["status"] = "passed"
    except BaseException as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        save(output / "result.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "failed": sum(not case["passed"] for case in report["cases"]), "evidence": str(output)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
