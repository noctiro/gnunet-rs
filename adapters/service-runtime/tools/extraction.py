#!/usr/bin/env python3
"""Source-bound migration check; does not compile or alter original inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PACKAGE = Path(__file__).resolve().parents[1]
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def bodies(text, name):
    result = []
    for match in re.finditer(r"\bfn\s+" + re.escape(name) + r"\s*\(", text):
        start = text.index("{", match.end())
        i, depth, state, comment_depth = start, 0, "code", 0
        while i < len(text):
            c, pair = text[i], text[i:i+2]
            if state == "line":
                if c == "\n": state = "code"
            elif state == "block":
                if pair == "/*": comment_depth += 1; i += 1
                elif pair == "*/":
                    comment_depth -= 1; i += 1
                    if comment_depth == 0: state = "code"
            elif state in ("string", "char"):
                if c == "\\": i += 1
                elif (c == '"' and state == "string") or (c == "'" and state == "char"): state = "code"
            elif pair == "//": state = "line"; i += 1
            elif pair == "/*": state = "block"; comment_depth = 1; i += 1
            elif c == '"': state = "string"
            elif c == "'" and ((i+2 < len(text) and text[i+2] == "'") or (i+3 < len(text) and text[i+1] == "\\" and text[i+3] == "'")): state = "char"
            elif c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    result.append(text[start:i+1]); break
            i += 1
        else: raise ValueError("unterminated function: " + name)
    return result

def prove(repository, upstream):
    baseline_path = PACKAGE / "tools/migration-baseline.json"
    baseline = json.loads(baseline_path.read_text())
    rows = []
    current = (PACKAGE / "src/activation.rs").read_text()
    for item in baseline["native_functions"]:
        found = bodies(current, item["function"])
        index = item["definition_index"]
        assert index < len(found), "native function missing: " + item["function"]
        assert hashlib.sha256(found[index].encode()).hexdigest() == item["body_sha256"], "native body changed: " + item["function"]
        rows.append(dict(item))
    assert len(rows) == 10, len(rows)
    assert len(re.findall(r"\bunsafe\s*(?:\{|fn\b)", current)) == baseline["native_unsafe_occurrences"]
    for name in ["lib.rs", "listeners.rs", "path.rs"]:
        assert not re.search(r"\bunsafe\s*(?:\{|fn\b)", (PACKAGE / "src" / name).read_text())
    fixture = (PACKAGE / "examples/activation_probe.rs").read_text()
    assert len(re.findall(r"\bunsafe\s*(?:\{|fn\b)", fixture)) == baseline["fixture_unsafe_occurrences"]
    assert digest(PACKAGE / "tests/activation_abi.c") == baseline["original_inputs"]["apps/gnunet-service-statistics/tests/activation_abi.c"]
    for item in baseline["fixture_native_functions"]:
        found = bodies(fixture, item["function"])
        assert len(found) == 1 and hashlib.sha256(found[0].encode()).hexdigest() == item["body_sha256"], "fixture body changed: " + item["function"]
    path = (PACKAGE / "src/path.rs").read_text()
    for item in baseline["pure_path_functions"]:
        found = bodies(path, item["function"])
        assert len(found) == 1 and hashlib.sha256(found[0].encode()).hexdigest() == item["body_sha256"], "path body changed: " + item["function"]
    tcp = bodies((PACKAGE / "src/listeners.rs").read_text(), "tcp")
    assert len(tcp) == 1 and hashlib.sha256(tcp[0].encode()).hexdigest() == baseline["tcp_body_sha256"], "TCP options/backlog body changed"
    revision = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    assert revision == REVISION, revision
    for relative, expected in baseline["upstream_inputs"].items():
        assert digest(upstream / relative) == expected, "official source changed: " + relative
    return {"status": "passed", "upstream_revision": revision,
            "baseline": {"path": str(baseline_path), "sha256": digest(baseline_path)},
            "historical_original_inputs": baseline["original_inputs"],
            "upstream_inputs": baseline["upstream_inputs"],
            "native_functions": rows, "native_unsafe_occurrences": baseline["native_unsafe_occurrences"],
            "fixture_native_functions": baseline["fixture_native_functions"],
            "pure_path_functions": baseline["pure_path_functions"],
            "tcp_body_sha256": baseline["tcp_body_sha256"],
            "changes": baseline["changes"],
            "scope": "Checks reviewed migration hashes; functional acceptance also requires actual shared-runtime tests and normal C subprocess comparisons."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repository, upstream, output = args.repository.resolve(), args.upstream.resolve(), args.output.resolve()
    for source in [PACKAGE, repository, upstream]:
        assert not output.is_relative_to(source) and not source.is_relative_to(output), "output overlaps source"
    assert not output.exists(), "output must be fresh"
    result = prove(repository, upstream)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "passed", "native_function_bodies": len(result["native_functions"])}))

if __name__ == "__main__": main()
