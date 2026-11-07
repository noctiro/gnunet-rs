#!/usr/bin/env python3
"""Execute pinned original C configuration parser/scalar/expansion functions.

Allocation/logging and include dispatch are harness boundaries. Include behavior
is covered by Rust filesystem tests, not claimed by these function fixtures.
"""
import argparse
import hashlib
import json
import os
import shutil
import re
from pathlib import Path
import subprocess
import tempfile

PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
PARSER = {
    "basic": b"# comment\n[First]\na = 1\nb=\"two\"\n[SECOND]\nkey=x\n[first]\nA = changed\n",
    "opaque": b"[s]\nbytes=\xff\xfe\nempty =\nquote=\"\nslashes=one\\ntwo\n",
    "whitespace": b"  # ignored\n%ignored\n[s]\n\tkey\t=\t value\twith\ttabs\r\ninline = value # retained\n",
    "partial_error": b"[s]\nfirst=ok\nthis is invalid\nsecond=ignored\n",
    "option_no_section": b"first=invalid\n",
    "semicolon": b";not a comment\n",
    "trailing_section_space": b"[s] \nx=not applied\n",
    "leading_section_space": b" [s]\nx=not applied\n",
    "empty_section_key": b"[]\n=value\n",
    "missing_quote": b"[s]\nx=\"unterminated\ny=bare\"\n",
    "empty_header": b"[unused]\n[s]\nx=1\n",
    "unknown_directive": b"[s]\nx=1\n@UNKNOWN@ here\n",
    "inline_no_source": b"@INLINE@ absent\n",
}
NUMBERS = {"zero": b"0", "negative": b"-1", "signed": b" +42 \t", "suffix": b"1x", "hex": b"0x10", "empty": b"", "maximum": b"18446744073709551615"}
SIZES = {"mixed": b"1KiB 2 kB 3B", "legacy_tb": b"1TB", "empty": b"", "multiply_units": b"2kB MiB", "negative": b"-1B", "overflow_wrap": b"18446744073709551615 KiB", "invalid": b"1 xb"}
TIMES = {"mixed": b"1h 2min 3s 4ms 5us", "forever": b"FoReVeR", "week_year": b"1w 1y", "quotes": b"1' 2\"", "unit_only": b"s", "empty": b"", "invalid": b"1fortnight"}
EXPAND = {"paths_precedence": b"$ROOT/a", "braced": b"x${ROOT}/z", "nested": b"${UNSET:-${ROOT}}/z", "unknown": b"$GNUNET_CONFIG_ORACLE_MISSING/x", "unmatched": b"${ROOT/x", "inside": b"a/$ORACLE_ENV/z", "empty_set": b"${EMPTY:-default}/z", "separators": b"$ROOT\\file", "punctuation": b"$ROOT!", "doubled": b"$$ROOT"}


def body(source, prefix, structure=False):
    start = source.index(prefix)
    opening = source.index("{", start)
    depth = 0
    tokens = re.compile(r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|/\*.*?\*/|//[^\n]*|[{}]""", re.S)
    for token in tokens.finditer(source, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[start:token.end() + int(structure)]
    raise ValueError("unclosed C function or structure")


def literal(value):
    return '"' + ''.join('\\%03o' % byte for byte in value) + '"'


def program(config, strings):
    notice = config[:config.index("*/") + 2] + "\n" + strings[:strings.index("*/") + 2]
    shim = r'''
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#define GNUNET_OK 1
#define GNUNET_YES 1
#define GNUNET_NO 0
#define GNUNET_SYSERR (-1)
#define GNUNET_GenericReturnValue result_code
enum result_code { ignored_code = 99 };
#define GNUNET_ERROR_TYPE_WARNING 0
#define GNUNET_ERROR_TYPE_DEBUG 0
#define LOG(...) ((void)0)
#define _(x) (x)
#define GNUNET_assert(x) do { if (!(x)) abort(); } while (0)
#define GNUNET_malloc(n) calloc(1, (n) ? (n) : 1)
#define GNUNET_new(type) calloc(1,sizeof(type))
#define GNUNET_free(x) free(x)
#define GNUNET_strdup(x) strdup(x)
#define GNUNET_strndup(x,n) strndup((x),(n))
#define GNUNET_realloc(p,n) realloc((p),(n))
#define GNUNET_memcpy memcpy
struct GNUNET_TIME_Relative { uint64_t rel_value_us; };
#define GNUNET_TIME_UNIT_FOREVER_REL ((struct GNUNET_TIME_Relative){UINT64_MAX})
static int GNUNET_asprintf(char **out,const char *fmt,...) {
  va_list a,b; va_start(a,fmt);va_copy(b,a);int n=vsnprintf(NULL,0,fmt,a);va_end(a);
  if(n<0)abort();*out=calloc(1,(size_t)n+1);vsnprintf(*out,(size_t)n+1,fmt,b);va_end(b);return n;
}
'''
    types = "\n".join(body(config, "struct " + name + "\n", True) for name in ("ConfigSource", "ConfigEntry", "ConfigSection"))
    handle = r'''
struct GNUNET_CONFIGURATION_Handle { struct ConfigSection *sections; bool diagnostics; const char *restrict_section; };
static int handle_inline(struct GNUNET_CONFIGURATION_Handle *cfg,const char*p,bool glob,const char*r,const char*s,unsigned n){(void)cfg;(void)p;(void)glob;(void)r;(void)s;(void)n;return GNUNET_SYSERR;}
void GNUNET_CONFIGURATION_set_value_string(struct GNUNET_CONFIGURATION_Handle*,const char*,const char*,const char*);
char *GNUNET_CONFIGURATION_expand_dollar(const struct GNUNET_CONFIGURATION_Handle*,char*);
'''
    functions = [
        body(config, "static struct ConfigSection *\nfind_section"),
        body(config, "static struct ConfigEntry *\nfind_entry"),
        body(config, "static void\nadd_entry_source"),
        body(config, "void\nGNUNET_CONFIGURATION_set_value_string"),
        body(config, "enum GNUNET_GenericReturnValue\nGNUNET_CONFIGURATION_deserialize"),
        body(config, "static bool\ndo_skip"),
        body(config, "char *\nGNUNET_CONFIGURATION_serialize"),
        body(config, "enum GNUNET_GenericReturnValue\nGNUNET_CONFIGURATION_get_value_number"),
        body(config, "enum GNUNET_GenericReturnValue\nGNUNET_CONFIGURATION_get_value_string"),
        body(config, "static char *\nexpand_dollar"),
        body(config, "char *\nGNUNET_CONFIGURATION_expand_dollar"),
        body(strings, "struct ConversionTable\n", True),
        body(strings, "static enum GNUNET_GenericReturnValue\nconvert_with_table"),
        body(strings, "enum GNUNET_GenericReturnValue\nGNUNET_STRINGS_fancy_size_to_bytes"),
        body(strings, "enum GNUNET_GenericReturnValue\nGNUNET_STRINGS_fancy_time_to_relative"),
    ]
    harness = r'''
static void hex(const unsigned char *data,size_t size){for(size_t i=0;i<size;i++)printf("%02x",data[i]);}
int main(void){setenv("ORACLE_ENV","/env",1);unsetenv("GNUNET_CONFIG_ORACLE_MISSING");unsetenv("UNSET");
'''
    for name, data in PARSER.items():
        harness += '{struct GNUNET_CONFIGURATION_Handle cfg={0};const char*input=' + literal(data) + ';int ret=GNUNET_CONFIGURATION_deserialize(&cfg,input,strlen(input),NULL);size_t size;char*out=GNUNET_CONFIGURATION_serialize(&cfg,&size);printf("parser|' + name + '|%d|",ret);hex((const unsigned char*)out,size);puts("");}\n'
    for kind, cases in (("number", NUMBERS), ("size", SIZES), ("time", TIMES)):
        for name, data in cases.items():
            if kind == "number":
                expression = 'struct GNUNET_CONFIGURATION_Handle cfg={0};GNUNET_CONFIGURATION_set_value_string(&cfg,"s","v",input);int ret=GNUNET_CONFIGURATION_get_value_number(&cfg,"s","v",&number);'
            elif kind == "size":
                expression = 'int ret=GNUNET_STRINGS_fancy_size_to_bytes(input,&number);'
            else:
                expression = 'struct GNUNET_TIME_Relative rel={0};int ret=GNUNET_STRINGS_fancy_time_to_relative(input,&rel);number=rel.rel_value_us;'
            harness += '{const char*input=' + literal(data) + ';unsigned long long number=0;' + expression + 'printf("' + kind + '|' + name + '|%d|%llu\\n",ret,ret==GNUNET_OK?number:0);}\n'
    harness += '{struct GNUNET_CONFIGURATION_Handle cfg={0};GNUNET_CONFIGURATION_set_value_string(&cfg,"PATHS","ROOT","/config");GNUNET_CONFIGURATION_set_value_string(&cfg,"PATHS","EMPTY","");\n'
    for name, data in EXPAND.items():
        harness += '{char*out=GNUNET_CONFIGURATION_expand_dollar(&cfg,strdup(' + literal(data) + '));printf("expand|' + name + '|1|");hex((const unsigned char*)out,strlen(out));puts("");free(out);}\n'
    harness += '}return 0;}\n'
    return notice + shim + types + handle + "\n".join(functions) + harness


ROOT = Path(__file__).resolve().parents[3]
TRACE_TEST = "original_c_parser_scalars_and_expansion_match_all_44_observations"


def source_snapshot(source):
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PIN:
        raise ValueError("wrong reference revision")
    paths = ("src/lib/util/configuration.c", "src/lib/util/strings.c")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", *paths], check=True)
    return {"revision": revision, "files": {path: hashlib.sha256((source / path).read_bytes()).hexdigest() for path in paths}}


def rust_snapshot():
    folder = Path(__file__).resolve().parents[1]
    paths = [p for p in folder.rglob("*") if p.is_file() and "__pycache__" not in p.parts and "target" not in p.parts]
    paths.extend(ROOT / p for p in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def trace_rows(output):
    rows = output.decode("ascii").splitlines()
    required = {(kind, name) for kind, cases in (("parser", PARSER), ("number", NUMBERS), ("size", SIZES), ("time", TIMES), ("expand", EXPAND)) for name in cases}
    keys = set()
    for row in rows:
        parts = row.split("|")
        if len(parts) != 4 or (parts[0], parts[1]) not in required or parts[2] not in {"1", "-1"}:
            raise ValueError("malformed actual configuration trace")
        key = (parts[0], parts[1])
        if key in keys:
            raise ValueError("duplicate actual configuration trace")
        keys.add(key)
        if parts[0] in {"parser", "expand"}:
            if len(parts[3]) % 2 or re.fullmatch(r"[0-9a-f]*", parts[3]) is None:
                raise ValueError("invalid actual hex trace")
        elif not parts[3].isdigit():
            raise ValueError("invalid actual numeric trace")
    if keys != required:
        raise ValueError("empty or incomplete actual configuration trace")
    return rows


def run_logged(output, name, argv, environment=None, timeout=180):
    result = subprocess.run(argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    for stream, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        (output / (name + "." + stream + ".txt")).write_bytes(data)
    row = {"argv": [str(x) for x in argv], "exit_code": result.returncode,
           "stdout": name + ".stdout.txt", "stderr": name + ".stderr.txt",
           "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
    return result, row


def execute_c(source, folder, receipt=None):
    paths = ("src/lib/util/configuration.c", "src/lib/util/strings.c")
    raw = [(source / path).read_bytes() for path in paths]
    source_path, binary = folder / "oracle.c", folder / "oracle"
    source_path.write_text(program(*(data.decode() for data in raw)))
    argv = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-misleading-indentation", str(source_path), "-o", str(binary)]
    if receipt is None:
        subprocess.run(argv, check=True)
    else:
        result, row = run_logged(folder, "c-build", argv)
        receipt["commands"].append(row)
        if result.returncode:
            raise ValueError("C oracle compilation failed")
    output = subprocess.check_output([str(binary)], timeout=10)
    trace_rows(output)
    if receipt is not None:
        (folder / "c-trace.txt").write_bytes(output)
        receipt["commands"].append({"argv": [str(binary)], "exit_code": 0, "stdout": "c-trace.txt", "stdout_sha256": hashlib.sha256(output).hexdigest()})
        receipt["c_artifact"] = {"path": binary.name, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "source": source_path.name, "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest()}
    return output


def run_receipt(source, output):
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": 1, "status": "failed", "kind": "official-config-function-differential", "full_c_daemon": False,
               "scope": "Original C parser/scalar/dollar functions versus the actual Rust configuration functions; filesystem include loading is Rust-tested separately.",
               "commands": [], "executed_checks": 0}
    try:
        before = rust_snapshot()
        receipt["rust_inputs"] = before
        receipt["upstream"] = source_snapshot(source)
        c_output = execute_c(source, output, receipt)
        fixture = Path(__file__).with_name("fixtures") / "functions.txt"
        if c_output != fixture.read_bytes():
            raise ValueError("actual C function trace differs from fixture")
        build, row = run_logged(output, "rust-build", ["cargo", "test", "-p", "gnunet-config", "--test", "functions", "--locked", "--no-run", "--message-format=json"])
        receipt["commands"].append(row)
        if build.returncode:
            raise ValueError("Rust configuration function test compilation failed")
        artifacts = [json.loads(line) for line in build.stdout.decode().splitlines() if line.startswith("{")]
        artifacts = [item for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "functions" and item.get("executable")]
        if len(artifacts) != 1:
            raise ValueError("compiled Rust test executable is absent or ambiguous")
        binary = output / "rust-functions.snapshot"
        shutil.copyfile(artifacts[0]["executable"], binary)
        binary.chmod(0o700)
        receipt["rust_artifact"] = {"path": binary.name, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        trace = output / "rust-trace.txt"
        environment = dict(os.environ, GNUNET_CONFIG_TRACE=str(trace))
        tested, row = run_logged(output, "rust-test", [str(binary), "--exact", TRACE_TEST, "--nocapture"], environment)
        receipt["commands"].append(row)
        if tested.returncode or b"test result: ok. 1 passed; 0 failed" not in tested.stdout or b"running 1 test" not in tested.stdout:
            raise ValueError("actual Rust configuration trace test did not execute successfully")
        rust_output = trace.read_bytes()
        c_rows, rust_rows = trace_rows(c_output), trace_rows(rust_output)
        if c_rows != rust_rows:
            raise ValueError("actual C and Rust configuration function rows differ")
        receipt["comparisons"] = [{"row": index + 1, "sha256": hashlib.sha256(row.encode()).hexdigest()} for index, row in enumerate(c_rows)]
        receipt["executed_checks"] = len(c_rows)
        receipt["fixture_comparisons"] = len(c_rows)
        receipt["rust_trace_sha256"] = hashlib.sha256(rust_output).hexdigest()
        receipt["source_unchanged"] = rust_snapshot() == before and source_snapshot(source) == receipt["upstream"]
        receipt["artifacts_unchanged"] = hashlib.sha256(binary.read_bytes()).hexdigest() == receipt["rust_artifact"]["sha256"] and hashlib.sha256((output / receipt["c_artifact"]["path"]).read_bytes()).hexdigest() == receipt["c_artifact"]["sha256"]
        if not receipt["source_unchanged"] or not receipt["artifacts_unchanged"] or not receipt["executed_checks"]:
            raise ValueError("configuration proof inputs changed or no actual comparisons executed")
        receipt["status"] = "passed"
    except Exception as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error)
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "executed_checks": receipt["executed_checks"], "evidence": str(output / "result.json")}))
    return 0 if receipt["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output", type=Path, help="new evidence directory; also execute and compare the actual Rust trace")
    args = parser.parse_args()
    source = args.source.resolve()
    if args.output:
        if args.write:
            parser.error("--write and --output cannot be combined")
        return run_receipt(source, args.output.resolve())
    snapshot = source_snapshot(source)
    with tempfile.TemporaryDirectory(prefix="gnunet-config-oracle-") as work:
        output = execute_c(source, Path(work))
    fixture = Path(__file__).with_name("fixtures") / "functions.txt"
    if args.write:
        fixture.parent.mkdir(exist_ok=True)
        fixture.write_bytes(output)
    elif fixture.read_bytes() != output:
        raise SystemExit("actual C functions differ from fixtures")
    print(json.dumps({"checks": len(trace_rows(output)), "sha256": hashlib.sha256(output).hexdigest(), "sources": snapshot["files"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
