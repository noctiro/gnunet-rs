#!/usr/bin/env python3
"""Actual inherited sockets, descriptor ownership, private bind and C behavior.

The parent passes listening sockets via subprocess pass_fds using official numeric
LISTEN_FDNAMES. No systemd library or descriptor-3 guess is used. Only owned child
processes and private Unix/loopback sockets are started; all have bounded cleanup.
The normal C STATISTICS daemon is loaded from a hash-checked reference receipt.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--rust-service", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = json.loads(args.reference.read_text())
    assert receipt["status"] == "passed" and receipt["upstream"]["revision"] == REVISION
    for item in [*receipt["artifacts"].values(), *receipt["libraries"], *receipt["default_configurations"]]:
        assert digest(item["path"]) == item["sha256"], item["path"]
    binaries = args.output / "binaries"
    binaries.mkdir()
    participants = {}
    def snapshot(name, original):
        original = Path(original).resolve()
        destination = binaries / name
        shutil.copy2(original, destination)
        destination.chmod(0o500)
        assert digest(destination) == digest(original)
        participants[name] = {"original": str(original), "snapshot": str(destination), "sha256": digest(destination)}
        return destination
    args.probe = snapshot("probe", args.probe)
    c_service = snapshot("c-service", receipt["artifacts"]["service"]["path"])
    if args.rust_service:
        args.rust_service = snapshot("rust-service", args.rust_service)
    owned = Path(tempfile.mkdtemp(prefix="gn-act-", dir="/private/tmp"))
    owned.chmod(0o700)
    checks, commands = [], []
    base = {k: v for k, v in os.environ.items() if not k.startswith(("LISTEN_", "ACTIVATION_PROBE_", "GNUNET_"))}
    base.update(receipt["runtime_environment"], LC_ALL="C")
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
        directory = owned / name.lower()
        directory.mkdir(mode=0o700)
        base[name] = str(directory)
    inputs = [ROOT / "src/lib.rs", ROOT / "src/listeners.rs", ROOT / "src/path.rs", ROOT / "Cargo.toml", ROOT / "src/activation.rs",
              ROOT / "examples/activation_probe.rs",
              Path(__file__).resolve(), ROOT / "README.md",
              ROOT / "tests/activation_abi.c"]
    before = {str(p.relative_to(ROOT)): digest(p) for p in inputs}

    def check(name, condition, detail=None):
        item = {"id": name, "passed": bool(condition)}
        if detail is not None:
            item["observation"] = detail
        checks.append(item)
        assert condition, item

    def probe(name, fds=(), declaration=None, extra=None, stdin=None, stdout=None, stderr=None):
        env = dict(base)
        env.update(declaration or {})
        env.update(extra or {})
        env["ACTIVATION_PROBE_TRACK_FDS"] = ":".join(map(str, fds))
        report_path = owned / (name + ".json")
        env["ACTIVATION_PROBE_REPORT_PATH"] = str(report_path)
        result = subprocess.run([str(args.probe.resolve())], env=env, pass_fds=tuple(fds),
                                stdin=stdin, stdout=stdout if stdout is not None else subprocess.PIPE,
                                stderr=stderr if stderr is not None else subprocess.PIPE,
                                text=True, timeout=10)
        report = json.loads(report_path.read_text())
        commands.append({"name": name, "argv": [str(args.probe.resolve())],
                         "pass_fds": list(fds), "declaration": declaration,
                         "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "report": report})
        check(name + "-process", result.returncode == 0)
        return report

    def listener_set(stem, ipv6=True):
        endpoints, originals, duplicated = [], [], []
        for index in range(2):
            path = owned / (stem + f"-{index}.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(8)
            originals.append(listener); endpoints.append((socket.AF_UNIX, str(path)))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(8)
        originals.append(listener); endpoints.append((socket.AF_INET, listener.getsockname()))
        if ipv6:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(("::1", 0)); listener.listen(8)
            originals.append(listener); endpoints.append((socket.AF_INET6, listener.getsockname()))
        for index, listener in enumerate(originals):
            duplicated.append(fcntl.fcntl(listener, fcntl.F_DUPFD_CLOEXEC, 40 + 20 * index))
        return endpoints, originals, duplicated

    def release(originals, duplicated):
        for fd in duplicated:
            os.close(fd)
        for listener in originals:
            listener.close()

    try:
        if sys.platform == "darwin":
            abi = args.output / "native-abi"
            compiled = subprocess.run(["cc", str(ROOT / "tests/activation_abi.c"), "-o", str(abi)], capture_output=True, text=True)
            assert compiled.returncode == 0, compiled.stderr
            native = subprocess.run([str(abi)], check=True, capture_output=True, text=True)
            layout = json.loads(native.stdout)
            row = probe("native-ABI")
            check("macos-SDK-prefix-and-capacity", layout["options_offset"] == row["darwin_socket_layout"][0] and layout["socket_fdinfo_size"] <= row["darwin_socket_layout"][1] and layout["flavor"] == 3 and layout["acceptconn"] == 2, layout)
            commands.append({"name": "native-ABI-oracle", "argv": [str(abi)], "stdout": native.stdout, "source_sha256": digest(ROOT / "tests/activation_abi.c")})
        endpoints, originals, fds = listener_set("probe-many")
        try:
            for stem, mode, section in [("capture", "serve", "unused"), ("runtime-statistics", "runtime-serve", "statistics"), ("runtime-resolver", "runtime-serve", "resolver")]:
                configured = owned / (stem + "-unused.sock")
                order = [3, 0, 2, 1]
                offered = [fds[i] for i in order]
                env = dict(base, LISTEN_FDS=str(len(offered)), LISTEN_FDNAMES=":".join(map(str, offered)), LISTEN_PID="0",
                           ACTIVATION_PROBE_MODE=mode, ACTIVATION_PROBE_SECTION=section, ACTIVATION_PROBE_CONFIGURED_PATH=str(configured), ACTIVATION_PROBE_TRACK_FDS=":".join(map(str, offered)))
                process = subprocess.Popen([str(args.probe.resolve())], env=env, pass_fds=offered,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    assert select.select([process.stdout], [], [], 5)[0], "probe readiness timeout"
                    check(stem + "-all-listeners-ready", process.stdout.readline().strip() == "READY 4")
                    for position in order:
                        family, address = endpoints[position]
                        with socket.socket(family, socket.SOCK_STREAM) as client:
                            client.settimeout(5); client.connect(address); client.sendall(b"?")
                            check(stem + "-actual-listener-echo-" + str(position), client.recv(1) == b"A")
                    stdout, stderr = process.communicate(timeout=5)
                    row = json.loads(stdout.splitlines()[-1])
                    check(stem + "-all-original-fds-owned-and-closed", row["owned_closed"] and row["original_fds_open"] == [False] * 4, row)
                    check(stem + "-adopted-listeners-close-on-exec", all(f & fcntl.FD_CLOEXEC for f in row["live_flags"]))
                    check(stem + "-successful-capture-clears-only-count-hint", row["count_hint_removed"])
                    check(stem + "-actual-serve-exit", process.returncode == 0, stderr)
                    commands.append({"name": stem + "-actual-four-listeners", "argv": [str(args.probe.resolve())], "pass_fds": offered,
                                     "exit_code": process.returncode, "stdout": stdout, "stderr": stderr})
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait(timeout=5)
                check(stem + "-configured-path-unbound", not configured.exists())
            declaration = {"LISTEN_FDS": "1", "LISTEN_FDNAMES": str(fds[0]), "LISTEN_PID": "999999999"}
            row = probe("single-call-guard", [fds[0]], declaration, {"ACTIVATION_PROBE_MODE": "duplicate-capture"})
            check("single-call-guard-no-second-ownership", row["duplicate_capture_rejected"] and row["owned_closed"])
            for name, values in [
                ("missing-both", {}), ("missing-names", {"LISTEN_FDS": "1"}),
                ("missing-count", {"LISTEN_FDNAMES": str(fds[0])}),
                ("zero-count", {"LISTEN_FDS": "0", "LISTEN_FDNAMES": str(fds[0])}),
                ("invalid-count", {"LISTEN_FDS": "invalid", "LISTEN_FDNAMES": str(fds[0])}),
                ("overflow-count", {"LISTEN_FDS": "4294967296", "LISTEN_FDNAMES": str(fds[0])})]:
                row = probe(name, [fds[0]], values)
                check(name + "-not-activation-no-close", row["accepted"] and row["listeners"] == 0 and row["original_fds_open"] == [True])
            for name, values in [
                ("duplicate-number", {"LISTEN_FDS": "2", "LISTEN_FDNAMES": f"{fds[0]}:{fds[0]}"}),
                ("too-few-names", {"LISTEN_FDS": "2", "LISTEN_FDNAMES": str(fds[0])}),
                ("too-many-names", {"LISTEN_FDS": "1", "LISTEN_FDNAMES": f"{fds[0]}:{fds[1]}"}),
                ("nonnumeric-name", {"LISTEN_FDS": "2", "LISTEN_FDNAMES": f"{fds[0]}:statistics.socket"}),
                ("out-of-range-name", {"LISTEN_FDS": "2", "LISTEN_FDNAMES": f"{fds[0]}:1024"}),
                ("closed-descriptor", {"LISTEN_FDS": "2", "LISTEN_FDNAMES": f"{fds[0]}:235"})]:
                row = probe(name, [fds[0], fds[1]], values)
                check(name + "-all-validation-before-ownership", not row["accepted"] and row["original_fds_open"] == [True, True])
            row = probe("original-cloexec-set", [fds[0]], declaration, {"ACTIVATION_PROBE_CLOEXEC_FD": str(fds[0])})
            check("original-cloexec-rejected-without-close", not row["accepted"] and row["original_fds_open"] == [True])
            row = probe("empty-colon-components", [fds[0]], {"LISTEN_FDS": " +1", "LISTEN_FDNAMES": f":{fds[0]}::"})
            check("strtok-empty-components-and-numeric-syntax", row["accepted"] and row["listeners"] == 1 and row["owned_closed"])
            family, address = endpoints[0]
            with socket.socket(family, socket.SOCK_STREAM) as pending:
                pending.settimeout(5); pending.connect(address); pending.sendall(b"?")
                row = probe("queued-before-capture", [fds[0]], declaration, {"ACTIVATION_PROBE_MODE": "serve"})
                check("validation-does-not-consume-queued-connection", row["listeners"] == 1 and row["owned_closed"] and pending.recv(1) == b"A")
            row = probe("fd-zero", (), {"LISTEN_FDS": "1", "LISTEN_FDNAMES": "0"}, stdin=originals[0])
            check("fd-zero-listener-moved-closed-and-stdin-restored", row["accepted"] and row["listeners"] == 1 and row["owned_closed"] and row["stdio_restored"] == [True] and all(fd >= 3 for fd in row["listener_fds"]))
            for low, key in [(1, "stdout"), (2, "stderr")]:
                row = probe("fd-" + str(low), (), {"LISTEN_FDS": "1", "LISTEN_FDNAMES": str(low)}, **{key: originals[0]})
                check("stdio-" + str(low) + "-listener-moved-and-standard-slot-restored", row["accepted"] and row["listeners"] == 1 and row["owned_closed"] and row["stdio_restored"] == [True] and all(fd >= 3 for fd in row["listener_fds"]))
            pending = []
            try:
                for family, address in endpoints[:3]:
                    client = socket.socket(family, socket.SOCK_STREAM)
                    client.settimeout(5); client.connect(address); client.sendall(b"?"); pending.append(client)
                row = probe("all-low-stdio-queued", (), {"LISTEN_FDS": "3", "LISTEN_FDNAMES": "0:1:2"}, {"ACTIVATION_PROBE_MODE": "serve"}, stdin=originals[0], stdout=originals[1], stderr=originals[2])
                check("all-low-listeners-move-without-dropping-queued-connections", row["listeners"] == 3 and row["owned_closed"] and row["stdio_restored"] == [True]*3 and len(set(row["listener_fds"])) == 3 and all(fd >= 3 for fd in row["listener_fds"]) and all(client.recv(1) == b"A" for client in pending))
            finally:
                for client in pending: client.close()
        finally:
            release(originals, fds)
        for name, resource in [("file", open(os.devnull, "rb")), ("udp", socket.socket(socket.AF_INET, socket.SOCK_DGRAM))]:
            try:
                fd = resource.fileno()
                row = probe("reject-" + name, [fd], {"LISTEN_FDS": "1", "LISTEN_FDNAMES": str(fd)})
                check(name + "-not-listener-no-close", not row["accepted"] and row["original_fds_open"] == [True])
            finally:
                resource.close()
        bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            bound.bind(str(owned / "not-listening.sock"))
            fd = bound.fileno()
            row = probe("bound-not-listening", [fd], {"LISTEN_FDS": "1", "LISTEN_FDNAMES": str(fd)})
            check("bound-stream-must-actually-listen", not row["accepted"] and row["original_fds_open"] == [True])
        finally:
            bound.close()
        pair = socket.socketpair()
        try:
            fd = pair[0].fileno(); row = probe("connected-stream", [fd], {"LISTEN_FDS": "1", "LISTEN_FDNAMES": str(fd)})
            check("connected-stream-not-listening-no-close", not row["accepted"] and row["original_fds_open"] == [True])
        finally:
            for stream in pair: stream.close()
        for previous in ("022", "027", "777"):
            row = probe("private-umask-" + previous, extra={"ACTIVATION_PROBE_MODE": "private-bind", "ACTIVATION_PROBE_UMASK": previous, "ACTIVATION_PROBE_PATH": str(owned / ("private-" + previous + ".sock"))})
            check("private-bind-atomic-mode-and-restore-" + previous, row["private_mode"] == 0o700 and row["bind_failure_observed"] and row["mask_restored"], row)

        def service(name, binary, rust=False):
            endpoints, originals, fds = listener_set(name)
            # Official GNUNET_NETWORK handles are nonblocking before the C
            # launcher passes them. C's accept loop relies on that flag; Rust's
            # capture additionally normalizes Python's blocking inputs above.
            for listener in originals:
                listener.setblocking(False)
            configured = owned / (name + "-configured-unused.sock")
            conf = owned / (name + ".conf")
            conf.write_text(f"[PATHS]\nGNUNET_RUNTIME_DIR={owned}\nGNUNET_DATA_HOME={owned}\nGNUNET_CACHE_HOME={owned}\nGNUNET_CONFIG_HOME={owned}\n[statistics]\nUNIXPATH={configured}\nDATABASE={owned / (name + '.dat')}\nPORT=0\nHOSTNAME=localhost\nACCEPT_FROM=127.0.0.1;\nACCEPT_FROM6=::1;\nUNIX_MATCH_UID=YES\nUNIX_MATCH_GID=NO\nDISABLE_SOCKET_FORWARDING=YES\n")
            env = dict(base, LISTEN_FDS=str(len(fds)), LISTEN_FDNAMES=":".join(map(str, reversed(fds))), LISTEN_PID="0")
            argv = [str(binary), "-c", str(conf)] + ([] if rust else ["-L", "ERROR"])
            out = (args.output / (name + ".stdout")).open("wb"); err = (args.output / (name + ".stderr")).open("wb")
            process = subprocess.Popen(argv, env=env, pass_fds=fds, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            try:
                for index, (family, address) in enumerate(endpoints):
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(5); client.connect(address)
                        payload = b"activation-probe-absent\0absent\0"
                        client.sendall(struct.pack("!HH", len(payload) + 4, 169) + payload)
                        answer = b""
                        while len(answer) < 4:
                            data = client.recv(4 - len(answer))
                            if not data: break
                            answer += data
                        check(name + "-official-GET-END-listener-" + str(index), answer == struct.pack("!HH", 4, 171), answer.hex())
                check(name + "-inherited-only-no-configured-bind", not configured.exists())
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=8)
                check(name + "-graceful-exit", code == 0, code)
                for _, address in endpoints[:2]:
                    check(name + "-inherited-path-not-unlinked-" + Path(address).name, Path(address).exists())
                commands.append({"name": name, "argv": argv, "pass_fds": fds, "declaration": {"LISTEN_FDS": str(len(fds)), "LISTEN_FDNAMES": env["LISTEN_FDNAMES"], "LISTEN_PID": "0"}, "exit_code": code})
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=5)
                out.close(); err.close(); release(originals, fds)
        service("normal-C", c_service)
        if args.rust_service:
            service("actual-Rust", args.rust_service.resolve(), True)
        if args.rust_service:
            # These real application paths write through libstd stdout/stderr,
            # so pure fd ownership/type probes cannot substitute for them.
            defaults = owned / "empty-defaults"
            defaults.mkdir()
            for low in (0, 1, 2):
                path = owned / ("stdio-service-" + str(low) + ".sock")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path)); listener.listen(5)
                config_path = owned / ("stdio-service-" + str(low) + ".conf")
                config_path.write_text(f"[statistics]\nUNIXPATH={owned / ('unused-stdio-' + str(low))}\nPORT=0\nHOSTNAME=localhost\n")
                ready = owned / ("stdio-ready-" + str(low))
                env = dict(base, GNUNET_BASE_CONFIG=str(defaults), LISTEN_FDS="1", LISTEN_FDNAMES=str(low), LISTEN_PID="0")
                redirection = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
                redirection[("stdin", "stdout", "stderr")[low]] = listener
                argv = [str(args.rust_service), "-c", str(config_path), "--ready-file", str(ready)]
                process = subprocess.Popen(argv, env=env, text=True, **redirection)
                try:
                    until = time.monotonic() + 5
                    while not ready.exists() and process.poll() is None and time.monotonic() < until:
                        time.sleep(.005)
                    check("Rust-stdio-" + str(low) + "-NoDB-ready", ready.exists())
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(5); client.connect(str(path)); payload = b"low-fd-absent\0absent\0"
                        client.sendall(struct.pack("!HH", len(payload)+4,169)+payload)
                        answer = b""
                        while len(answer)<4:
                            part=client.recv(4-len(answer))
                            if not part: break
                            answer+=part
                        check("Rust-stdio-" + str(low) + "-NoDB-official-GET", answer == struct.pack("!HH",4,171))
                    process.send_signal(signal.SIGTERM)
                    stdout, stderr = process.communicate(timeout=8)
                    check("Rust-stdio-" + str(low) + "-NoDB-graceful-exit", process.returncode == 0)
                    commands.append({"name": "Rust-stdio-"+str(low), "argv": argv, "declaration": {"LISTEN_FDS":"1","LISTEN_FDNAMES":str(low)}, "exit_code":process.returncode,"stdout":stdout,"stderr":stderr})
                finally:
                    if process.poll() is None: process.kill(); process.wait(timeout=5)
                    listener.close()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(owned / "stdio-help.sock"));listener.listen(5)
            try:
                env=dict(base,GNUNET_BASE_CONFIG=str(defaults),LISTEN_FDS="1",LISTEN_FDNAMES="1")
                argv=[str(args.rust_service),"--help"]
                help_result=subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,stdout=listener,stderr=subprocess.PIPE,text=True,timeout=5)
                check("Rust-stdout-listener-help-exits-successfully",help_result.returncode==0,help_result.stderr)
                commands.append({"name":"Rust-stdout-help","argv":argv,"exit_code":help_result.returncode,"stderr":help_result.stderr})
            finally:listener.close()
        after = {str(p.relative_to(ROOT)): digest(p) for p in inputs}
        check("native-source-inputs-unchanged", before == after)
        result = {"status": "passed", "scope": "Official numeric-fd activation, real inherited Unix/IPv4/IPv6 listeners, native ownership and atomic private Unix creation", "checks": checks, "commands": commands,
                  "reference": {"path": str(args.reference.resolve()), "sha256": digest(args.reference), "upstream": receipt["upstream"]},
                  "source_inputs": before, "inputs_unchanged": before == after, "participants": participants,
                  "probe": {"path": str(args.probe.resolve()), "sha256": digest(args.probe)},
                  "actual_rust_service_tested": bool(args.rust_service), "actual_shared_runtime_tested": True, "production_c_ffi": False,
                  "limitations": ["C tolerates invalid partial prefixes, duplicates and non-listening handles; Rust rejects before ownership to avoid aliasing or silently dropping declared sockets.", "The temporary umask requires the documented synchronous startup section without unrelated concurrent file creators."]}
        if args.rust_service: result["rust_service"] = {"path": str(args.rust_service.resolve()), "sha256": digest(args.rust_service)}
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "checks": len(checks), "actual_rust_service_tested": bool(args.rust_service)}))
    finally:
        shutil.rmtree(owned)


if __name__ == "__main__":
    main()
