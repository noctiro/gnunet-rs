#!/usr/bin/env python3
"""Compare live normal GNUnet libraries and actual Rust in both directions.

Requires clean pinned source and an existing unmodified Meson build containing
libgnunethello + libgnunetutil. This script never rebuilds or edits that build.
A separate --deterministic-build selects the official conditional compilation.
All generated drivers, input/output, receipts and logs stay in a NEW --output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
PUBLIC_FUNCTIONS = sorted((
    "address_to_prefix build_url builder_add_address builder_address_list_cmp "
    "builder_del_address builder_free builder_from_parser builder_hash_addresses "
    "builder_iterate builder_new builder_to_block builder_to_dht_hello_msg "
    "builder_to_env builder_to_url builder_to_url2 dht_msg_to_block "
    "get_builder_to_block_size get_expiration_time_from_msg parser_free "
    "parser_from_block parser_from_block_ parser_from_msg parser_from_msg_ "
    "parser_from_url parser_get_id parser_iterate parser_to_block "
    "parser_to_dht_hello_msg parser_to_env parser_to_url"
).split())
SOURCES = ["src/lib/hello/hello-uri.c", "src/include/gnunet_hello_uri_lib.h",
           "src/include/gnunet_container_lib.h", "src/include/gnunet_signatures.h",
           "src/include/gnunet_protocols.h", "src/lib/util/strings.c",
           "src/lib/util/time.c", "src/lib/hello/meson.build"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--deterministic-build", type=Path)
    parser.add_argument("--deps-prefix", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.source = args.source.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    crate = Path(__file__).resolve().parents[1]
    workspace = crate.parents[1]
    commands, checks, cases, profiles = [], [], [], {}
    rust_paths = [workspace / "Cargo.toml", workspace / "Cargo.lock"]
    for package in [crate, workspace / "crates/gnunet-types", workspace / "crates/gnunet-wire", workspace / "crates/gnunet-crypto"]:
        rust_paths.extend(f for f in package.rglob("*") if f.is_file())
    rust_inputs = {str(f.relative_to(workspace)): sha(f) for f in sorted(rust_paths)}
    source_inputs = {name: sha(args.source / name) for name in SOURCES}
    corpus = args.output / "cases"
    corpus.mkdir()
    env = os.environ.copy()

    def command(argv, expected=0, cwd=None, extra_env=None):
        runtime = env.copy()
        if extra_env:
            runtime.update(extra_env)
        result = subprocess.run(list(map(str, argv)), cwd=cwd, env=runtime,
                                capture_output=True, text=True)
        item = {"argv": list(map(str, argv)), "cwd": str(cwd) if cwd else None,
                "exit_code": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr}
        commands.append(item)
        assert result.returncode == expected, item
        return result.stdout

    assert command(["git", "-C", args.source, "rev-parse", "HEAD"]).strip() == REVISION
    assert not command(["git", "-C", args.source, "status", "--porcelain", "--untracked-files=no"]).strip()

    def compile_driver(build, profile):
        build = build.resolve()
        entries = json.loads((build / "compile_commands.json").read_text())
        unit = next(x for x in entries if x["file"].endswith("/hello-uri.c"))
        assert (build / unit["file"]).resolve() == args.source / "src/lib/hello/hello-uri.c"
        raw = shlex.split(unit["command"])
        flags, position = [], 0
        while position < len(raw):
            value = raw[position]
            if value in ("-o", "-MQ", "-MF"):
                position += 2
                continue
            if value in ("-MD", "-c") or value == unit["file"]:
                position += 1
                continue
            flags.append(value)
            position += 1
        macros = command([*flags, "-E", "-dM", unit["file"]], cwd=build)
        macro_lines = [line for line in macros.splitlines()
                       if line.startswith("#define HELLO_DETERMINISTIC_PID_DERIVATION ")]
        if profile == "normal":
            assert not macro_lines or macro_lines == ["#define HELLO_DETERMINISTIC_PID_DERIVATION 0"]
        else:
            assert macro_lines == ["#define HELLO_DETERMINISTIC_PID_DERIVATION 1"]
        libs = []
        for name in ("hello", "util"):
            directory = build / "src/lib" / name
            choices = [f for f in directory.glob("libgnunet" + name + "*")
                       if f.is_file() and not f.is_symlink()
                       and (f.name.endswith(".dylib") or ".so." in f.name)]
            assert len(choices) == 1, choices
            libs.append(choices[0])
        directories = [f.parent for f in libs]
        if args.deps_prefix:
            directories.append(args.deps_prefix.resolve() / "lib")
        driver = args.output / ("hello-" + profile)
        command([*flags, crate / "tests/normal_c_oracle.c",
                 *("-L" + str(d) for d in directories),
                 *("-Wl,-rpath," + str(d) for d in directories),
                 "-lgnunethello", "-lgnunetutil", "-o", driver], cwd=build)
        nm_args = ["nm", "-gU", libs[0]] if sys.platform == "darwin" else ["nm", "-D", "--defined-only", libs[0]]
        symbols = sorted(line.split()[-1].lstrip("_")[len("GNUNET_HELLO_"):]
                         for line in command(nm_args).splitlines()
                         if line.split() and line.split()[-1].lstrip("_").startswith("GNUNET_HELLO_"))
        assert symbols == PUBLIC_FUNCTIONS
        profiles[profile] = {"build": str(build), "compile_command": unit,
                             "macro_lines": macro_lines,
                             "macro_output_sha256": hashlib.sha256(macros.encode()).hexdigest(),
                             "generated_configuration": {str(f.relative_to(build)): sha(f) for f in
                                 [build / "src/include/gnunet_config.h", build / "gnunet_private_config.h"]},
                             "libraries": {str(f): sha(f) for f in libs},
                             "driver_sha256": sha(driver), "public_symbols": symbols}
        return driver

    drivers = {"normal": compile_driver(args.build, "normal")}
    if args.deterministic_build:
        drivers["deterministic"] = compile_driver(args.deterministic_build, "deterministic")
    addresses = args.output / "addresses.bin"
    addresses.write_bytes(b"z://Z\0a+udp://127.0.0.1:1234/path?x=y&z=w\0a://first\0a://first\0")

    def case(name, kind, data, expected, profile="normal", verify=True, c_unchecked=None, peer=None):
        name = profile + "-" + name
        source = corpus / (name + ".input")
        source.write_bytes(data)
        prefix = corpus / (name + ".c")
        if c_unchecked is None:
            c_unchecked = not verify
        peer_input = args.output / (profile + ".peer")
        peer_name = "-"
        if peer is not None:
            peer_input = corpus / (name + ".peer")
            peer_input.write_bytes(peer)
            peer_name = peer_input.name
        command([drivers[profile], "unchecked" if c_unchecked else "inspect", kind,
                 source, peer_input, prefix], expected=0 if expected else 3)
        cases.append({"id": name, "kind": kind, "profile": profile,
                      "verify": verify, "c_noverify": c_unchecked, "peer_input": peer_name, "accepted": expected,
                      "input": source.name, "canonical_c": prefix.with_suffix(".c.block").name if expected else None})

    for profile, driver in drivers.items():
        prefix = args.output / profile
        command([driver, "build", addresses, prefix])
        block = prefix.with_suffix(".block").read_bytes()
        assert block[104:] == b"z://Z\0a://first\0a+udp://127.0.0.1:1234/path?x=y&z=w\0"
        expected_hash = hashlib.sha512(b"" if profile == "normal" else block[104:]).digest()
        assert prefix.with_suffix(".hash").read_bytes() == expected_hash
        command([driver, "api", prefix])
        command([driver, "contract", prefix])
        relations = json.loads(command([driver, "relations"]))
        prefix.with_suffix(".relations.json").write_text(json.dumps(relations) + "\n")
        for kind in ("block", "message", "dht", "url"):
            case("positive-" + kind, kind, prefix.with_suffix("." + kind).read_bytes(), True, profile)
        changed = block.replace(b"a://first", b"a://other")
        case("changed-address", "block", changed, profile == "normal", profile)
        parts = block[104:].split(b"\0")[:-1]
        case("unsorted", "block", block[:104] + b"\0".join(parts[::-1]) + b"\0", True, profile)
        case("duplicate", "block", block + b"z://Z\0", False, profile)
        for label, offset in (("peer", 0), ("signature", 32), ("expiry", 96)):
            changed = bytearray(block)
            changed[offset] ^= 1
            case("changed-" + label, "block", changed, False, profile)
        for kind in ("message", "dht"):
            value = bytearray(prefix.with_suffix("." + kind).read_bytes())
            value[4:8] = b"\xff\xff\x00\x00"
            case(kind + "-ignored-reserved-count", kind, value, True, profile)

        # Distinguish C's noverify flag from the Rust parse/verify pipeline.
        # DHT's internal dht_msg_to_block validates even when noverify=YES.
        for kind in ("block", "message", "dht"):
            value = prefix.with_suffix("." + kind).read_bytes()
            case("valid-noverify-" + kind, kind, value, True, profile,
                 verify=(kind == "dht"), c_unchecked=True)
            changed = bytearray(value)
            changed[{"block": 32, "message": 40, "dht": 8}[kind]] ^= 1
            case("bad-signature-" + kind, kind, changed, False, profile)
            case("bad-signature-noverify-" + kind, kind, changed, kind != "dht", profile,
                 verify=(kind == "dht"), c_unchecked=True)
        wrong_peer = bytearray(prefix.with_suffix(".peer").read_bytes())
        wrong_peer[0] ^= 1
        for unchecked in (False, True):
            case("dht-wrong-peer-" + str(unchecked), "dht", prefix.with_suffix(".dht").read_bytes(),
                 False, profile, c_unchecked=unchecked, peer=wrong_peer)
        for kind, lengths in (("message", (4, 7, 8, 111)), ("dht", (4, 7, 8, 79))):
            original = prefix.with_suffix("." + kind).read_bytes()
            for length in lengths:
                typed = length.to_bytes(2, "big") + original[2:length]
                case("typed-short-" + kind + "-" + str(length), kind, typed, False, profile)
        expired_prefix = args.output / (profile + "-expired")
        command([driver, "build", addresses, expired_prefix, "1"])
        for kind in ("block", "message", "dht", "url"):
            value = expired_prefix.with_suffix("." + kind).read_bytes()
            case("expired-" + kind, kind, value, False, profile)
            if kind != "url":
                case("expired-noverify-" + kind, kind, value, kind != "dht", profile,
                     verify=(kind == "dht"), c_unchecked=True)

    normal = args.output / "normal"
    url = normal.with_suffix(".url").read_bytes()
    bare = url.split(b"?")[0]
    case("url-prefix-case", "url", url.replace(b"gnunet://hello/", b"GNUNET://HELLO/", 1), True)
    case("base32-lowercase", "url", bare.lower() + b"?test=x", True)
    for name, value in (("plus", b"x+y"), ("percent-plus", b"x%2By"),
                        ("percent-space", b"x%20y"), ("partial-hex", b"x%2Zy"),
                        ("invalid-hex-literal", b"x%GGy"), ("nul-truncates", b"x%00suffix")):
        case(name, "url", bare + b"?test=" + value, True)
    for name, value in (("empty-query", b"?"), ("empty-value", b"?test="),
                        ("empty-scheme", b"?=x"), ("duplicate-query", b"?test=x&test=x"),
                        ("trailing-amp", b"?test=x&")):
        case(name, "url", bare + value, False)
    key, sig, expiry = bare[len(b"gnunet://hello/"):].split(b"/")
    aliases = key.replace(b"0", b"O").replace(b"1", b"l").replace(b"V", b"u")
    sig_aliases = sig.replace(b"0", b"o").replace(b"1", b"I").replace(b"V", b"U")
    case("base32-aliases", "url", b"gnunet://hello/" + aliases + b"/" + sig_aliases + b"/" + expiry + b"?test=x", True)
    alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    tail = alphabet.index(key[-1])
    tail_alias = key[:-1] + bytes([alphabet[tail | 15]])
    case("base32-unused-tailbits", "url", b"gnunet://hello/" + tail_alias + b"/" + sig + b"/" + expiry + b"?test=x", True)
    sig_tail = alphabet.index(sig[-1])
    sig_tail_alias = sig[:-1] + bytes([alphabet[sig_tail | 7]])
    case("signature-unused-tailbits", "url", b"gnunet://hello/" + key + b"/" + sig_tail_alias + b"/" + expiry + b"?test=x", True)
    for name, numeric in (("leading-plus", b"+" + expiry), ("leading-space", b" " + expiry), ("negative-one", b"-1")):
        case(name, "url", b"gnunet://hello/" + key + b"/" + sig + b"/" + numeric + b"?test=x", True)
    for name, addresses_data in (("space", b"test://x y\0"), ("odd", b"test://\xc0A\0test://\xf8BBBB\0four://\xf0ABC\0six://\xfcABCDE\0other://caf\xc3\xa9\0"), ("empty", b"")):
        source = args.output / (name + ".addrs")
        source.write_bytes(addresses_data)
        prefix = args.output / name
        command([drivers["normal"], "build", source, prefix])
        case(name + "-url", "url", prefix.with_suffix(".url").read_bytes(), True)
    if "deterministic" in drivers:
        source = args.output / "conditional-space.addrs"
        source.write_bytes(b"test://x y\0")
        prefix = args.output / "conditional-space"
        command([drivers["deterministic"], "build", source, prefix])
        value = prefix.with_suffix(".url").read_bytes()
        case("space-url-loses-signature-binding", "url", value, False, "deterministic")
        case("percent-space-preserves-binding", "url", value.replace(b"?test=x+y", b"?test=x%20y"), True, "deterministic")
    rows = ["\t".join((c["id"], c["kind"], c["profile"], "verify" if c["verify"] else "unchecked", "1" if c["accepted"] else "0", c["input"], c["peer_input"])) for c in cases]
    assert rows
    (corpus / "cases.tsv").write_text("\n".join(rows) + "\n")
    rust = args.output / "rust"

    command(["cargo", "test", "-p", "gnunet-hello", "--locked", "--offline"], cwd=workspace,
            extra_env={"GNUNET_HELLO_OUTPUT": str(rust), "GNUNET_HELLO_CASES": str(corpus), "GNUNET_HELLO_CONTRACTS": str(args.output), "GNUNET_HELLO_PROFILES": ",".join(drivers)})
    assert rust_inputs == {str(f.relative_to(workspace)): sha(f) for f in sorted(rust_paths)}, "Rust inputs changed during execution"
    assert not command(["git", "-C", args.source, "status", "--porcelain", "--untracked-files=no"]).strip()
    assert source_inputs == {name: sha(args.source / name) for name in SOURCES}, "C sources changed during execution"
    for profile in profiles.values():
        assert profile["libraries"] == {path: sha(path) for path in profile["libraries"]}, "C libraries changed during execution"
        build = Path(profile["build"])
        assert profile["generated_configuration"] == {path: sha(build / path) for path in profile["generated_configuration"]}, "C build configuration changed during execution"
    assert int((corpus / "rust-executed.txt").read_text()) == len(cases)
    for c in cases:
        if c["accepted"]:
            assert (corpus / c["canonical_c"]).read_bytes() == (corpus / (c["id"] + ".rust.block")).read_bytes(), c["id"]
        checks.append({"id": c["id"], "passed": True, "accepted": c["accepted"], "direction": "C-to-Rust"})
    for profile, driver in drivers.items():
        for trace in ("relations", "contract"):
            c_trace = json.loads((args.output / (profile + "." + trace + ".json")).read_text())
            rust_trace = json.loads((rust / (profile + "." + trace + ".json")).read_text())
            assert c_trace == rust_trace, (profile, trace, c_trace, rust_trace)
            checks.append({"id": profile + "-exact-" + trace + "-trace", "passed": True, "direction": "both"})
        for kind in ("block", "message", "dht", "url"):
            assert (args.output / (profile + ".default." + kind)).read_bytes() == (rust / (profile + ".default." + kind)).read_bytes()
            checks.append({"id": profile + "-explicit-time-default-" + kind, "passed": True, "direction": "both"})
        rust_prefix = "rust" if profile == "normal" else "bound"
        c_prefix = args.output / profile
        for suffix in ("block", "message", "dht", "url", "region", "signature", "hash"):
            assert (rust / (rust_prefix + "." + suffix)).read_bytes() == c_prefix.with_suffix("." + suffix).read_bytes()
            checks.append({"id": profile + "-fresh-bytes-" + suffix, "passed": True, "direction": "both"})
        for kind in ("block", "message", "dht", "url"):
            prefix = args.output / (profile + "-opens-rust-" + kind)
            command([driver, "inspect", kind, rust / (rust_prefix + "." + kind), rust / "rust.peer", prefix])
            assert prefix.with_suffix(".block").read_bytes() == c_prefix.with_suffix(".block").read_bytes()
            checks.append({"id": profile + "-C-opens-Rust-" + kind, "passed": True, "direction": "Rust-to-C"})
    result = {"status": "passed", "source_revision": REVISION, "production_c_ffi": False,
              "source_inputs": source_inputs, "c_inputs_unchanged": True,
              "profiles": profiles, "check_count": len(checks), "checks": checks,
              "runtime_corpus_cases": len(cases), "corpus_cases": cases, "commands": commands,
              "rust_inputs": rust_inputs, "rust_inputs_unchanged": True,
              "limitations": ["Malformed C URL percent triplets with fewer than two following bytes are excluded because upstream may access freed storage; Rust rejects them safely.",
                              "C DHT noverify still verifies internally; Rust structural parsing remains explicitly unverified.",
                              "The conditional profile covers HELLO hashing/signatures/encoding; it does not certify PILS identity derivation or full GNUnet conditional-mode behavior.",
                              "C callback/free ownership maps to safe borrowed iterators, explicit peer values and Rust borrow release; compile-fail controls and exact value traces test this decomposition, not C ABI compatibility.",
                              "This HELLO proof does not certify a complete GNUnet implementation."]}
    result["artifacts"] = {str(f.relative_to(args.output)): sha(f) for f in sorted(args.output.rglob("*")) if f.is_file()}
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "passed", "checks": len(checks), "runtime_corpus_cases": len(cases), "profiles": sorted(profiles)}))


if __name__ == "__main__":
    main()
