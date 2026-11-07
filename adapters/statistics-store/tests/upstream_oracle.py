#!/usr/bin/env python3
"""Compare real Rust database saves with original C save/inject handlers.

The original C bodies execute with a small stdio BIO/configuration shim. This
tests the official persistence format and replay, not the complete C daemon,
its scheduler/BIO implementation, filesystem crash recovery or storage hardware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "crates/gnunet-statistics/tests/upstream_oracle.py"
FIXTURE = Path(__file__).with_name("fixtures") / "snapshot.bin"
EXPECTED_ROWS = {("73", "61"): (0x0102030405060705, True), ("73", "62"): (7, True), ("78", "6e"): (0, True)}
TEST = "actual_snapshot_matches_original_c_save_and_exports_for_c_inject"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def program(base, contents):
    original = base["program"](contents)
    # Reuse only declarations/shims and original handlers, not the base actions.
    original = original[:original.index("static struct ClientEntry *clients[2];")]
    service = contents["src/service/statistics/gnunet-service-statistics.c"]
    shim = r'''
#include <unistd.h>
struct GNUNET_CONFIGURATION_Handle { int unused; };
static const struct GNUNET_CONFIGURATION_Handle *cfg;
static const char *database;
static int GNUNET_CONFIGURATION_get_value_filename(const struct GNUNET_CONFIGURATION_Handle *handle,
  const char *section,const char *option,char **filename) {
  (void)handle; assert(strcmp(section,"STATISTICS")==0); assert(strcmp(option,"DATABASE")==0);
  *filename=malloc(strlen(database)+1); strcpy(*filename,database); return GNUNET_OK;
}
#define GNUNET_log_config_missing(...) ((void)0)
#define GNUNET_log_strerror_file(...) ((void)0)
#define GNUNET_DISK_directory_create_for_file(...) GNUNET_OK
struct GNUNET_BIO_WriteHandle { FILE *file; };
static struct GNUNET_BIO_WriteHandle *GNUNET_BIO_write_open_file(const char *filename) {
  struct GNUNET_BIO_WriteHandle *handle=malloc(sizeof(*handle));
  handle->file=fopen(filename,"wb"); if (!handle->file) { free(handle); return NULL; } return handle;
}
static int GNUNET_BIO_write(struct GNUNET_BIO_WriteHandle *handle,const char *description,
  const void *bytes,size_t length) {
  (void)description; return fwrite(bytes,1,length,handle->file)==length?GNUNET_OK:GNUNET_SYSERR;
}
static int GNUNET_BIO_write_close(struct GNUNET_BIO_WriteHandle *handle,void *error) {
  (void)error; int result=fclose(handle->file); free(handle); return result==0?GNUNET_OK:GNUNET_SYSERR;
}
'''
    bodies = base["block"](service, "static void\nsave (")
    bodies += base["block"](service, "static int\ncheck_set (")
    bodies += base["block"](service, "static int\ninject_message (")
    harness = r'''
static void set(const char *sub,const char *name,uint32_t flags,uint64_t value) {
  size_t length=sizeof(struct GNUNET_STATISTICS_SetMessage)+strlen(sub)+strlen(name)+2;
  struct GNUNET_STATISTICS_SetMessage *msg=calloc(1,length);
  msg->header.size=htons((uint16_t)length); msg->header.type=htons(GNUNET_MESSAGE_TYPE_STATISTICS_SET);
  msg->flags=htonl(flags); msg->value=GNUNET_htonll(value);
  strcpy((char *)&msg[1],sub); strcpy((char *)&msg[1]+strlen(sub)+1,name);
  struct GNUNET_SERVICE_Client transport={0};
  struct ClientEntry client={0}; client.client=&transport;
  handle_set(&client,msg); free(msg);
}
static void print_hex(const char *text) {
  for (size_t i=0;i<strlen(text);i++) printf("%02x",(unsigned char)text[i]);
}
int main(int argc,char **argv) {
  assert(argc==3); database=argv[2];
  if (strcmp(argv[1],"generate")==0) {
    set("s","a",2,UINT64_C(0x0102030405060708));
    set("s","b",2,7);
    set("s","a",3,(uint64_t)(int64_t)-8);
    set("s","z",0,99);
    set("x","n",2,0);
    set("s","a",3,5);
    save();
    FILE *file=fopen(database,"rb"); assert(file); unsigned bytes=0;
    printf("snapshot "); for (int c;(c=fgetc(file))!=EOF;bytes++) printf("%02x",c);
    assert(fclose(file)==0); assert(bytes==60); puts("");
  } else {
    assert(strcmp(argv[1],"inject")==0);
    FILE *file=fopen(database,"rb"); assert(file);
    unsigned rows=0;
    for (;;) {
      unsigned char bytes[65535]; size_t received=fread(bytes,1,4,file);
      if (received==0) break;
      assert(received==4); struct GNUNET_MessageHeader *header=(void *)bytes;
      size_t length=ntohs(header->size); assert(length>=18);
      assert(fread(bytes+4,1,length-4,file)==length-4);
      assert(inject_message(NULL,header)==GNUNET_OK); rows++;
    }
    assert(fclose(file)==0); assert(rows==3);
    for (struct SubsystemEntry *sub=sub_head;sub;sub=sub->next)
      for (struct StatsEntry *row=sub->stat_head;row;row=row->next) {
        printf("row "); print_hex(sub->service); printf(" "); print_hex(row->name);
        printf(" %" PRIu64 " %d\n",row->value,row->persistent);
      }
    /* Preserve the actual Rust input artifact; free rows through original save
       into a separate diagnostic redump instead. */
    char *redump=malloc(strlen(database)+16); sprintf(redump,"%s.c-redump",database);
    database=redump; save(); free(redump);
  }
  return 0;
}
'''
    return original + shim + bodies + harness


def run(argv, folder, name, env=None):
    result = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=180)
    (folder / (name + ".stdout.txt")).write_bytes(result.stdout)
    (folder / (name + ".stderr.txt")).write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f"{name} exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    return result.stdout, {"argv": [str(arg) for arg in argv], "exit_code": result.returncode,
                           "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr),
                           "stdout": name + ".stdout.txt", "stderr": name + ".stderr.txt"}


def test_executable(output):
    artifacts = [json.loads(line) for line in output.splitlines()]
    candidates = [Path(row["executable"]) for row in artifacts
                  if row.get("reason") == "compiler-artifact"
                  and Path(row["manifest_path"]).resolve() == (ROOT / "adapters/statistics-store/Cargo.toml").resolve()
                  and row.get("target", {}).get("kind") == ["test"]
                  and row["target"].get("name") == "filesystem"
                  and row.get("profile", {}).get("test") is True
                  and row.get("executable")]
    if len(candidates) != 1:
        raise ValueError("actual unique Rust test executable was not identified")
    return candidates[0].resolve(strict=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="new evidence directory; also execute the actual Rust snapshot test")
    parser.add_argument("--write", action="store_true", help="explicitly regenerate committed C snapshot fixture")
    args = parser.parse_args()
    source = args.source.resolve()
    base = runpy.run_path(str(BASE))
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30).strip()
    if revision != base["PIN"]:
        raise ValueError("wrong pinned upstream revision")
    contents = {}
    for path, expected in base["HASHES"].items():
        data = (source / path).read_bytes()
        if digest(data) != expected:
            raise ValueError("reference input changed: " + path)
        contents[path] = data.decode()
    if args.output is not None:
        folder = args.output.resolve()
        folder.mkdir(parents=True, exist_ok=False)
        work = None
    else:
        work = tempfile.TemporaryDirectory(prefix="gnunet-statistics-store-oracle-")
        folder = Path(work.name)
    report = {"kind": "official-statistics-store-components", "status": "failed", "full_c_daemon": False,
              "crash_or_hardware_durability_tested": False, "revision": revision, "commands": [], "comparisons": []}
    packages = ("adapters/statistics-store", "crates/gnunet-statistics", "crates/gnunet-types", "crates/gnunet-wire", "crates/gnunet-client")
    consumed = [path for package in packages for path in sorted((ROOT / package / "src").rglob("*.rs"))]
    consumed += [ROOT / package / "Cargo.toml" for package in packages]
    consumed += [Path(__file__).resolve(), BASE, ROOT / "Cargo.lock", ROOT / "Cargo.toml", ROOT / "rust-toolchain.toml",
                 Path(__file__).with_name("filesystem.rs"), FIXTURE]
    report["rust_source_inputs"] = [{"path": str(path.relative_to(ROOT)), "sha256": digest(path.read_bytes())} for path in consumed]
    try:
        code, binary, snapshot = folder / "oracle.c", folder / "oracle", folder / "c-snapshot.bin"
        code.write_text(program(base, contents))
        _, command = run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                           "-Wno-sign-compare", "-Wno-unused-function", "-I", str(source / "src/include"), str(code), "-o", str(binary)], folder, "compile")
        report["commands"].append(command)
        output, command = run([str(binary), "generate", str(snapshot)], folder, "c-generate")
        report["commands"].append(command)
        data = snapshot.read_bytes()
        if not data or output != b"snapshot " + data.hex().encode() + b"\n":
            raise ValueError("C save produced missing/different actual output")
        if args.write:
            FIXTURE.parent.mkdir(parents=True, exist_ok=True)
            FIXTURE.write_bytes(data)
        elif FIXTURE.read_bytes() != data:
            raise ValueError("actual C save differs from committed fixture")
        report["comparisons"].append({"name": "c-save-vs-fixture", "bytes": len(data), "sha256": digest(data)})
        if args.output is not None:
            rust_snapshot = folder / "rust-snapshot.bin"
            environment = dict(os.environ, GNUNET_STATISTICS_SNAPSHOT=str(rust_snapshot))
            built, command = run(["cargo", "test", "-p", "gnunet-statistics-store", "--test", "filesystem",
                                  "--locked", "--no-run", "--message-format=json"], folder, "rust-build", environment)
            report["commands"].append(command)
            rust_binary = test_executable(built)
            output, command = run([str(rust_binary), TEST, "--exact"], folder, "rust-save", environment)
            report["commands"].append(command)
            if b"running 1 test" not in output or f"test {TEST} ... ok".encode() not in output or b"1 passed; 0 failed" not in output:
                raise ValueError("actual unique Rust snapshot test did not execute")
            if rust_snapshot.read_bytes() != data:
                raise ValueError("actual Rust filesystem save differs from original C save")
            report["comparisons"].append({"name": "rust-save-vs-c-save", "bytes": len(data), "sha256": digest(data)})
            output, command = run([str(binary), "inject", str(rust_snapshot)], folder, "c-inject-rust")
            report["commands"].append(command)
            rows = {}
            for line in output.decode().splitlines():
                kind, sub, name, value, persistent = line.split()
                if kind != "row" or (sub, name) in rows or persistent not in {"0", "1"}:
                    raise ValueError("malformed/duplicate actual C inject output")
                rows[sub, name] = (int(value), persistent == "1")
            if rows != EXPECTED_ROWS:
                raise ValueError("actual original C inject values differ from Rust snapshot")
            report["comparisons"].extend({"name": "c-inject-" + "-".join(key), "value": value, "persistent": persistent} for key, (value, persistent) in sorted(rows.items()))
            if rust_snapshot.read_bytes() != data:
                raise ValueError("actual Rust input changed during C inject")
            report["rust_test_binary"] = {"path": str(rust_binary), "sha256": digest(rust_binary.read_bytes())}
        report["executed_checks"] = len(report["comparisons"])
        report["c_binary_sha256"] = digest(binary.read_bytes())
        report["reference_inputs"] = [{"path": path, "sha256": expected} for path, expected in sorted(base["HASHES"].items())]
        report["rust_inputs_unchanged"] = all(digest((ROOT / row["path"]).read_bytes()) == row["sha256"] for row in report["rust_source_inputs"])
        if not report["rust_inputs_unchanged"]:
            raise ValueError("Rust persistence sources changed during component run")
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["executed_checks"] = len(report["comparisons"])
        (folder / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "executed_checks": report["executed_checks"], "evidence": str(folder / "result.json")}))
    if work is not None:
        work.cleanup()


if __name__ == "__main__":
    main()
