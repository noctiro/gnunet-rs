#!/usr/bin/env python3
"""Fresh normal-C/Rust DNS packet proof, with separately verified native IDNA.

This runs the actual pinned C library and production Rust package. It grants no
whole-DNS or daemon acceptance and never updates the conformance ledger.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "crates/gnunet-dns"
HELPERS = ROOT / "tools/reference/dns"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "build", "library", "idn2-library", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = module("dns_inputs", ROOT / "tools/interop/run_reference.py")
    reference = module("dns_reference", ROOT / "tools/reference/build_reference.py")
    source = args.source.resolve()
    result = {"kind": "normal-c-rust-dns-wire", "status": "failed",
              "full_native_idna_verified": False, "whole_dns_verified": False,
              "commands": [], "production_c_ffi": False}
    before = inputs.fingerprints(ROOT)
    official_before = reference.source_state(source)
    libraries = {str(p.resolve()): sha(p) for p in (args.library, args.idn2_library)}
    build_inputs = {str(p): sha(p) for p in [args.build.resolve() / "compile_commands.json",
                                            args.build.resolve() / "gnunet_private_config.h",
                                            args.build.resolve() / "src/include/gnunet_config.h"]}
    save(output / "inputs-before.json", before)

    def run(name, argv, cwd=ROOT, extra=None):
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(extra or {})}
        completed = subprocess.run(list(map(str, argv)), cwd=cwd, env=env,
                                   capture_output=True, text=True, timeout=1200)
        log = output / (name + ".log")
        log.write_text(completed.stdout + "\n" + completed.stderr)
        result["commands"].append({"name": name, "argv": list(map(str, argv)),
                                   "cwd": str(cwd), "exit_code": completed.returncode,
                                   "log": str(log), "log_sha256": sha(log)})
        if completed.returncode:
            raise ValueError(name + " failed; see " + str(log))
        return completed.stdout

    try:
        common = ["--source", source, "--build", args.build.resolve(), "--library",
                  args.library.resolve(), "--idn2-library", args.idn2_library.resolve()]
        run("fresh-normal-c", [sys.executable, "-B", HELPERS / "parser_reference.py",
                               *common, "--output", output / "c"])
        c = json.loads((output / "c/parser-result.json").read_text())
        if not c["source_and_library_unchanged"] or len(c["observations"]) != 153:
            raise ValueError("normal C observer is incomplete or changed")
        run("classify-corpus", [sys.executable, "-B", HELPERS / "corpus.py", "--reference",
                                output / "c", "--output", output / "generated"])
        generated = output / "generated"
        if (generated / "tests/c_corpus.tsv").read_bytes() != (FIXTURES / "tests/c_corpus.tsv").read_bytes():
            raise ValueError("fresh normal C corpus differs from checked fixture")
        classification = json.loads((generated / "c-corpus-map.json").read_text())
        expected = json.loads((FIXTURES / "c-corpus-map.json").read_text())
        if classification["rows"] != expected["rows"] or classification["classifications"] != expected["classifications"]:
            raise ValueError("C corpus adjudication changed")
        flags = json.loads((output / "c/compile-flags.json").read_text())
        library = Path(flags["library"])

        def compile_probe(name, filename):
            binary = output / name
            run("compile-" + name, [*flags["flags"], FIXTURES / "tests" / filename,
                                     "-L" + str(library.parent), "-Wl,-rpath," + str(library.parent),
                                     "-lgnunetutil", "-o", binary], cwd=flags["build"])
            return binary

        hex_probe = compile_probe("hex-pairs", "hex_pair_oracle.c")
        pairs = run("all-native-hex-pairs", [hex_probe], cwd=output)
        if pairs != (FIXTURES / "tests/hex_pairs.tsv").read_text() or len(pairs.splitlines()) != 5786:
            raise ValueError("native hex conversion domain differs")
        run("rust-tests", ["cargo", "test", "-p", "gnunet-dns", "--locked", "--offline"],
            extra={"GNUNET_DNS_CORPUS_REPORT": str(output / "rust-corpus-result.json"),
                   "GNUNET_DNS_CORE_OUTPUT": str(output / "fresh-rust")})
        log = (output / "rust-tests.log").read_text()
        tests = re.findall(r"^test (.+?) \.\.\. ok$", log, re.M)
        if len(tests) != 19:
            raise ValueError("actual Rust packet test set changed; review the witness map")
        matrix = json.loads((output / "rust-corpus-result.json").read_text())
        if matrix["total"] != 153 or matrix["full_idna_verified"] is not False:
            raise ValueError("pending native text conversion was hidden")
        probe = output / "c/parser-probe"
        start = time.time_ns() // 1000
        packet = json.loads(run("c-opens-rust-packet", [probe, "packet", output / "fresh-rust/rust.packet", "0"]))
        end = time.time_ns() // 1000
        owner = b"owner.example".hex()
        if not packet["accepted"] or packet["id_bytes"] != "1234" or packet["flags_bytes"] != "8180":
            raise ValueError("normal C rejected or misread the Rust packet")
        if packet["questions"] != [{"name": owner, "type": 255, "class": 3}]:
            raise ValueError("normal C query fields differ")
        sections = [packet[k] for k in ("answers", "authority", "additional")]
        if list(map(len, sections)) != [4, 3, 2] or [r["type"] for s in sections for r in s] != [2, 5, 12, 39, 15, 33, 6, 1, 65000]:
            raise ValueError("normal C section/type interpretation differs")
        for section in sections:
            for record in section:
                if record["name"] != owner or record["class"] != 3 or not start + 123_000_000 <= record["expires_us"] <= end + 123_000_000:
                    raise ValueError("normal C owner/class/absolute TTL differs")
        if [r["data"] for r in sections[0]] != [owner] * 4:
            raise ValueError("hostname RDATA differs")
        if sections[1][0]["data"] != {"preference": 513, "host": owner} or sections[1][1]["data"] != {"priority": 1, "weight": 2, "port": 443, "target": owner}:
            raise ValueError("MX/SRV fields differ")
        if sections[1][2]["data"] != {"mname": owner, "rname": owner, "serial": 0x12345678, "refresh": 123, "retry": 456, "expire": 789, "minimum": 321}:
            raise ValueError("SOA fields differ")
        if [r["data"] for r in sections[2]] != ["010203", "00726177ff"]:
            raise ValueError("raw opaque bytes differ")
        dname = json.loads(run("c-opens-dname", [probe, "record", output / "fresh-rust/rust.dname.record", "0"]))
        if dname["rc"] != 1 or dname["record"]["type"] != 39 or dname["record"]["data"] != owner:
            raise ValueError("C did not accept corrected DNAME encoding")
        uri = json.loads(run("known-native-uri-defect", [probe, "record", output / "fresh-rust/rust.uri.record", "0"]))
        if uri["rc"] != -1:
            raise ValueError("previously reviewed native URI behavior changed")
        cert_probe = compile_probe("cert-fields", "cert_fields_oracle.c")
        cert = json.loads(run("cert-field-projection", [cert_probe, output / "fresh-rust/rust.cert.rfc.rdata"]))
        if {k: cert[k] for k in ("type", "key_tag", "algorithm", "data", "projection_is_field_only")} != {"type": 65535, "key_tag": 0x1234, "algorithm": 255, "data": "00ff616263", "projection_is_field_only": True}:
            raise ValueError("CERT field-only projection differs")
        after = inputs.fingerprints(ROOT)
        save(output / "inputs-after.json", after)
        if before != after or official_before != reference.source_state(source):
            raise ValueError("Rust/normative or original C inputs changed during proof")
        if any(sha(path) != digest for path, digest in {**libraries, **build_inputs}.items()):
            raise ValueError("normal reference library/build inputs changed")
        result.update({"status": "passed-wire-scope", "inputs": before, "inputs_unchanged": True,
                       "official_source": official_before, "libraries": libraries,
                       "generated_build_inputs": build_inputs, "actual_rust_tests": tests,
                       "corpus": matrix, "classifications": classification["classifications"],
                       "hex_domain_pairs": 65536, "hex_converting_pairs": 5786,
                       "normal_c_opens_rust": {"packet": packet, "dname": dname,
                                                "uri_native_rejection": uri, "cert_field_projection": cert},
                       "limitations": ["This wire-only proof excludes native text conversion; use gnunet-idna/verify.py for its separate full native-profile evidence.",
                                        "CERT5/URI/DNAME/count/cursor corrections are explicit, not false byte equivalence.",
                                        "No DNSSTUB/service/full-DNS owner acceptance is awarded."]})
    except Exception as error:
        result["failure"] = repr(error)
    result["artifacts"] = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}
    save(output / "result.json", result)
    print(json.dumps({"status": result["status"], "result": str(output / "result.json"),
                      "failure": result.get("failure")}))
    return int(result["status"] != "passed-wire-scope")


if __name__ == "__main__":
    sys.exit(main())
