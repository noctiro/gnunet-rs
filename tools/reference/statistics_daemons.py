#!/usr/bin/env python3
"""Exercise actual official C STATISTICS programs and the Rust implementation.

Both directions use unmodified, normally linked C executables from the pinned
Meson build receipt. All services bind private Unix sockets in an owned 0700
temporary directory. No ARM, peer transport, bootstrap or public network starts.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from build_reference import REVISION, source_state
from source_fingerprint import fingerprints

ROOT = Path(__file__).resolve().parents[2]
SUBSYSTEM = "rust-c-interop"
COUNTER = "counter"
TRANSIENT = "transient"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def signal_owned(process, signum):
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        # It exited between poll and the signal. wait() still reaps that exact
        # owned child; no replacement PID or unrelated process is signalled.
        pass


def read_dump(path):
    """Validate official persistent SET framing, independently of Rust codecs."""
    data = path.read_bytes()
    rows = []
    offset = 0
    while offset < len(data):
        header = data[offset:offset + 4]
        if len(header) != 4:
            raise ValueError("persistent file has a partial message header")
        length, kind = int.from_bytes(header[:2], "big"), int.from_bytes(header[2:], "big")
        frame = data[offset:offset + length]
        if kind != 168 or length < 18 or len(frame) != length:
            raise ValueError("persistent file is not a complete official SET stream")
        flags = int.from_bytes(frame[4:8], "big")
        names = frame[16:].split(b"\0")
        if flags != 2 or len(names) != 3 or names[-1] != b"":
            raise ValueError("persistent file has noncanonical flags or names")
        rows.append({"subsystem": names[0].hex(), "name": names[1].hex(), "value": int.from_bytes(frame[8:16], "big")})
        offset += length
    if not rows:
        raise ValueError("persistent dump is empty")
    return rows


class Harness:
    def __init__(self, output, env):
        self.output = output
        self.env = env
        self.commands = []
        self.checks = []
        self.services = []
        self.cleanup_errors = []
        self.probes = []
        self.diagnostics = {"commands": [], "checks": [], "probes": []}
        self.serial = 0

    def check(self, name, condition, detail=None, diagnostic=False):
        row = {"name": name, "passed": bool(condition)}
        if detail is not None:
            row["observation"] = detail
        (self.diagnostics["checks"] if diagnostic else self.checks).append(row)
        if not condition:
            raise ValueError("actual observation failed: " + name)

    def command(self, name, argv, expected=0, timeout=15):
        # Normal one-shot clients are owned just like daemons. An interruption
        # must leave them visible to the enclosing suite's actual cleanup.
        started = time.monotonic()
        owned = self.start(name, argv)
        process, row = owned["process"], owned["row"]
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            signal_owned(process, signal.SIGKILL)
            code = process.wait(timeout=5)
        except BaseException as error:
            row["interrupted"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            row.update(timed_out=timed_out, elapsed_seconds=round(time.monotonic() - started, 6))
            if process.poll() is not None:
                self.close_logs(owned)
        self.check(name + "-exit", code == expected and not timed_out, {"actual": code, "expected": expected})
        return owned["out_path"].read_bytes()

    def start(self, name, argv, watch=False, diagnostic=False, pass_fds=(), env=None):
        self.serial += 1
        stem = f"{self.serial:02d}-{name}"
        out, err = self.output / (stem + ".stdout"), self.output / (stem + ".stderr")
        row = {"name": name, "argv": [str(arg) for arg in argv],
               "stdout": out.name, "stderr": err.name, "owned_process_group": True, "diagnostic": diagnostic}
        if pass_fds:
            row["inherited_fds"] = list(pass_fds)
        owned = {"process": None, "row": row, "stdout": None, "stderr": None,
                 "master": None, "slave": None, "pending": b"", "out_path": out, "err_path": err}
        # Register resources before launch. Handled signals record at most one
        # pending intent per kind until Popen has returned and ownership is set.
        # No blocked signal mask is inherited by the exec child.
        self.services.append(owned)
        (self.diagnostics["commands"] if diagnostic else self.commands).append(row)
        previous, pending = {}, {}
        original = None

        def defer(signum, frame):
            pending.setdefault(signum, frame)

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                handler = signal.getsignal(signum)
                if callable(handler):
                    previous[signum] = handler
                    signal.signal(signum, defer)
            owned["stdout"] = out.open("wb")
            owned["stderr"] = err.open("wb")
            if watch:
                owned["master"], owned["slave"] = pty.openpty()
                child_stdout = owned["slave"]
            else:
                child_stdout = owned["stdout"]
            owned["process"] = subprocess.Popen(argv, env=env if env is not None else self.env, stdin=subprocess.DEVNULL,
                                                stdout=child_stdout, stderr=owned["stderr"],
                                                start_new_session=True, pass_fds=tuple(pass_fds))
            row["pid"] = owned["process"].pid
            if owned["slave"] is not None:
                os.close(owned["slave"])
                owned["slave"] = None
        except BaseException as error:
            original = error
            row["launch_failure"] = type(error).__name__ + ": " + str(error)
            # A log/PTY failure after creation must still retire the actual
            # child, without replacing the original launch/interruption cause.
            try:
                self.cleanup_owned(owned)
            except BaseException as cleanup:
                self.cleanup_error(owned, "launch-cleanup", cleanup)
        finally:
            if pending:
                row["deferred_signals"] = list(pending)
            for signum, handler in previous.items():
                try:
                    signal.signal(signum, handler)
                except BaseException as error:
                    self.cleanup_error(owned, "restore-signal-" + str(signum), error)
                    if original is None:
                        original = error
        if original is not None:
            raise original
        # The exact owned child is now in the enclosing cleanup registry.
        # main's SIGTERM handler raises InterruptedError; normal SIGINT raises
        # KeyboardInterrupt. SIG_DFL/SIG_IGN were never replaced here.
        for signum, frame in pending.items():
            previous[signum](signum, frame)
        return owned

    def finish(self, owned, expected=0):
        process = owned["process"]
        if process.poll() is None:
            signal_owned(process, signal.SIGTERM)
        try:
            code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            signal_owned(process, signal.SIGKILL)
            code = process.wait(timeout=5)
            owned["row"]["forced_kill"] = True
        self.close_logs(owned)
        self.check(owned["row"]["name"] + "-graceful-exit", code == expected and not owned["row"].get("forced_kill"), {"actual": code, "expected": expected})

    def cleanup_error(self, owned, phase, error):
        self.cleanup_errors.append({"name": owned["row"]["name"], "phase": phase,
                                    "error": type(error).__name__ + ": " + str(error)})

    def close_logs(self, owned):
        failures_before = len(self.cleanup_errors)

        def attempt(phase, operation):
            try:
                return True, operation()
            except BaseException as error:
                self.cleanup_error(owned, phase, error)
                return False, None

        def drain():
            while select.select([owned["master"]], [], [], 0)[0]:
                try:
                    data = os.read(owned["master"], 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                owned["stdout"].write(data)

        if owned["master"] is not None:
            attempt("pty-drain", drain)
            if attempt("pty-close", lambda: os.close(owned["master"]))[0]:
                owned["master"] = None
        if owned["slave"] is not None:
            if attempt("slave-close", lambda: os.close(owned["slave"]))[0]:
                owned["slave"] = None
        for label in ("stdout", "stderr"):
            stream = owned[label]
            if stream is not None:
                if not stream.closed:
                    attempt(label + "-close", stream.close)
                ok, value = attempt(label + "-digest", lambda: digest(owned["out_path" if label == "stdout" else "err_path"]))
                if ok:
                    owned["row"][label + "_sha256"] = value
        if owned["process"] is not None:
            ok, value = attempt("exit-observation", owned["process"].poll)
            if ok:
                owned["row"]["exit_code"] = value
        if len(self.cleanup_errors) != failures_before:
            raise RuntimeError("owned log finalization failed; see independent cleanup_errors")

    def cleanup_owned(self, owned):
        def attempt(phase, operation):
            try:
                return True, operation()
            except BaseException as error:
                self.cleanup_error(owned, phase, error)
                return False, None

        process = owned["process"]
        if process is not None:
            ok, code = attempt("poll", process.poll)
            if not ok or code is None:
                attempt("SIGTERM", lambda: signal_owned(process, signal.SIGTERM))
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    attempt("SIGKILL", lambda: signal_owned(process, signal.SIGKILL))
                    owned["row"]["forced_cleanup"] = True
                    attempt("reap-after-kill", lambda: process.wait(timeout=5))
                except BaseException as error:
                    self.cleanup_error(owned, "wait-after-term", error)
                    attempt("SIGKILL", lambda: signal_owned(process, signal.SIGKILL))
                    owned["row"]["forced_cleanup"] = True
                    attempt("reap-after-wait-error", lambda: process.wait(timeout=5))
        # close_logs attempts each PTY/log/digest independently before raising.
        # Its original failures are already retained individually.
        try:
            self.close_logs(owned)
        except BaseException as error:
            self.cleanup_error(owned, "close-logs", error)

    def cleanup(self):
        for owned in self.services:
            try:
                self.cleanup_owned(owned)
            except BaseException as error:
                self.cleanup_error(owned, "owned-cleanup", error)

    def ready(self, owned, path, stdout_line=None):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if owned["process"].poll() is not None:
                raise ValueError("service exited before readiness: " + owned["row"]["name"])
            initialized = stdout_line is None
            if stdout_line is not None:
                # Read only a bounded prefix of this exact owned child's log.
                # The normal Rust SERVICE flushes this line after initialization.
                with owned["out_path"].open("rb") as stream:
                    observed = stream.read(16_385)
                if len(observed) > 16_384:
                    raise ValueError("service readiness stdout limit exceeded")
                initialized = stdout_line in observed.splitlines(keepends=True)
            if path.exists() and initialized:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(.1)
                    try:
                        probe.connect(str(path))
                        if stdout_line is not None:
                            self.check(owned["row"]["name"] + "-initialized-stdout", True, {"owned_pid": owned["process"].pid, "line": stdout_line.decode().rstrip("\n")}, diagnostic=owned["row"]["diagnostic"])
                        self.check(owned["row"]["name"] + "-listening", True, diagnostic=owned["row"]["diagnostic"])
                        return
                    except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
                        pass
            time.sleep(.02)
        raise ValueError("service readiness deadline elapsed: " + owned["row"]["name"])

    def watch_value(self, owned, expected):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if b"\n" in owned["pending"]:
                line, owned["pending"] = owned["pending"].split(b"\n", 1)
                self.check(owned["row"]["name"] + "-value-" + str(expected), line.strip() == str(expected).encode(), {"actual_line": line.decode(errors="replace"), "expected": expected})
                return
            if owned["process"].poll() is not None:
                raise ValueError("watch ended before notification")
            readable, _, _ = select.select([owned["master"]], [], [], .05)
            if readable:
                try:
                    chunk = os.read(owned["master"], 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        raise ValueError("watch terminal closed before notification") from error
                    raise
                if not chunk:
                    raise ValueError("watch terminal reached EOF before notification")
                owned["stdout"].write(chunk); owned["stdout"].flush()
                owned["pending"] += chunk
        raise ValueError("actual C WATCH_VALUE deadline elapsed")

    def malformed(self, name, path):
        frames = {"undersized-header": b"\0\x03\0\xa9", "partial-eof": b"\0\x08\0\xa9s\0x"}
        for case, frame in frames.items():
            started = time.monotonic()
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(3)
                peer.connect(str(path))
                try:
                    peer.sendall(frame)
                    peer.shutdown(socket.SHUT_WR)
                    closed = peer.recv(1) == b""
                    observation = "eof" if closed else "unexpected-data"
                except (ConnectionResetError, BrokenPipeError):
                    closed, observation = True, "peer-reset"
            row = {"service": name, "case": case, "sent_hex": frame.hex(), "observed": observation,
                   "elapsed_seconds": round(time.monotonic() - started, 6)}
            self.probes.append(row)
            self.check(name + "-reject-" + case, closed, row)

    def unknown_type(self, name, path, expect_timeout):
        # v0.29.1 MQ_inject_message handles SYSERR but not NO. An unmatched
        # message therefore leaves needs_continue set in the C service. Record
        # this actual source discrepancy instead of inventing a C close event
        # or forcing the Rust service to retain an unusable connection.
        started = time.monotonic()
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(.2)
            peer.connect(str(path))
            try:
                peer.sendall(b"\0\x04\xff\xfe")
                peer.shutdown(socket.SHUT_WR)
                observation = "eof" if peer.recv(1) == b"" else "unexpected-data"
            except socket.timeout:
                observation = "read-timeout"
            except (ConnectionResetError, BrokenPipeError):
                observation = "peer-reset"
        row = {"service": name, "case": "unknown-type", "sent_hex": "0004fffe", "observed": observation,
               "elapsed_seconds": round(time.monotonic() - started, 6), "known_reference_variance": True}
        self.diagnostics["probes"].append(row)
        expected = {"read-timeout"} if expect_timeout else {"eof", "peer-reset"}
        self.check(name + "-unknown-type-observation", observation in expected, row, diagnostic=True)

    def reference_unknown_shutdown(self, owned):
        """Observe and clean the known C invalid-message bug in isolation.

        The forced kill is explicit diagnostic cleanup. It must never be
        confused with the normal persistent restart cases' graceful exit zero.
        """
        process = owned["process"]
        signal_owned(process, signal.SIGTERM)
        try:
            code = process.wait(timeout=.5)
            paused = False
        except subprocess.TimeoutExpired:
            paused = True
            signal_owned(process, signal.SIGKILL)
            code = process.wait(timeout=5)
        owned["row"].update(known_reference_variance=True, observed_soft_shutdown_timeout=paused,
                             intentional_diagnostic_kill=paused)
        self.close_logs(owned)
        self.check("c-unknown-type-soft-shutdown-variance-observed", paused and code == -signal.SIGKILL,
                   {"soft_shutdown_timed_out": paused, "exit_code_after_owned_cleanup": code}, diagnostic=True)


def config(path, socket_path, database):
    path.write_text(f"""[PATHS]
GNUNET_RUNTIME_DIR = {path.parent}
GNUNET_DATA_HOME = {path.parent}
GNUNET_CACHE_HOME = {path.parent}
GNUNET_CONFIG_HOME = {path.parent}
[statistics]
UNIXPATH = {socket_path}
DATABASE = {database}
HOSTNAME = localhost
PORT = 0
START_ON_DEMAND = NO
UNIX_MATCH_UID = YES
UNIX_MATCH_GID = NO
ACCEPT_FROM = 127.0.0.1;
ACCEPT_FROM6 = ::1;
DISABLE_SOCKET_FORWARDING = YES
""")


def rust_get(harness, binary, path, name, value, persistent=None):
    raw = harness.command("rust-get-" + name, [str(binary), "statistics", "get", str(path), SUBSYSTEM, name])
    rows = [json.loads(line) for line in raw.splitlines()]
    if value is None:
        harness.check("rust-empty-" + name, rows == [{"event": "statistics_end", "count": 0}] and type(rows[0].get("count")) is int, rows)
        return
    harness.check("rust-get-" + name + "-exact-end", len(rows) == 2 and rows[-1] == {"event": "statistics_end", "count": 1} and type(rows[-1].get("count")) is int, rows)
    row = rows[0]
    harness.check("rust-get-" + name + "-value", row.get("event") == "statistics_value" and type(row.get("value")) is int and row.get("value") == value and row.get("subsystem") == SUBSYSTEM and row.get("name") == name and row.get("subsystem_bytes") == list(SUBSYSTEM.encode()) and row.get("name_bytes") == list(name.encode()), row)
    if persistent is not None:
        harness.check("rust-get-" + name + "-persistent", type(row.get("persistent")) is bool and row.get("persistent") == persistent, row)


def rust_set(harness, binary, path, name, value, persistent=False, relative=False):
    argv = [str(binary), "statistics", "set", str(path), SUBSYSTEM, name, str(value)]
    if persistent:
        argv.append("--persistent")
    if relative:
        argv.append("--relative")
    raw = harness.command("rust-set-" + name, argv)
    harness.check("rust-set-" + name + "-confirmed", [json.loads(line) for line in raw.splitlines()] == [{"event": "statistics_set_confirmed"}])


def c_get(harness, binary, conf, name, expected):
    raw = harness.command("c-get-" + name, [str(binary), "-c", str(conf), "-L", "ERROR", "-q", "-s", SUBSYSTEM, "-n", name])
    harness.check("c-get-" + name + "-value", raw.strip() == str(expected).encode(), {"actual": raw.decode(errors="replace"), "expected": expected})


def c_set(harness, binary, conf, name, value, persistent=False):
    argv = [str(binary), "-c", str(conf), "-L", "ERROR", "-s", SUBSYSTEM, "-n", name]
    if persistent:
        argv.append("-p")
    harness.command("c-set-" + name, [*argv, str(value)])


def snapshot(binary, directory, name):
    target = directory / name
    shutil.copy2(binary, target)
    target.chmod(0o700)
    if digest(binary) != digest(target):
        raise ValueError("participant snapshot changed")
    return target


def run_suite(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "kind": "official-c-statistics-daemon-ipc", "status": "failed",
              "full_c_statistics_daemon": False, "full_gnunet_peer": False, "p2p_peer_interoperation": False,
              "scope": "Actual upstream STATISTICS daemon and CLI in both directions, WATCH and observed graceful persistent restart. No whole GNUnet peer, ARM activation, crash consistency or full API-inventory certification.",
              "selected_profile": "first-normal" if args.normal_only else "normal-with-protocol-diagnostics",
              "unexecuted_profiles": ["malformed/partial-EOF", "unknown-message-type"] if args.normal_only else [],
              "executed_checks": 0, "commands": [], "checks": []}
    harness = None
    owned = None
    try:
        receipt = json.loads(args.reference.read_text())
        if receipt.get("status") != "passed" or receipt.get("kind") != "unmodified-official-c-reference-build" or receipt["upstream"]["revision"] != REVISION:
            raise ValueError("a successful pinned unmodified-C build receipt is required")
        original_state = source_state(Path(receipt["source"]))
        if original_state != receipt["upstream"]:
            raise ValueError("reference source changed since build")
        reference_runtime_inputs = [*receipt["artifacts"].values(), *receipt["libraries"], *receipt["default_configurations"]]
        for row in reference_runtime_inputs:
            if digest(row["path"]) != row["sha256"]:
                raise ValueError("reference artifact changed: " + row["path"])
        before = fingerprints(ROOT)
        report["input_fingerprints"] = before
        report["upstream"] = receipt["upstream"]
        report["reference_receipt"] = {"path": str(args.reference.resolve()), "sha256": digest(args.reference)}
        binaries = output / "binaries"
        binaries.mkdir()
        participants = {"c_client": Path(receipt["artifacts"]["client"]["path"]), "c_service": Path(receipt["artifacts"]["service"]["path"]),
                        "rust_client": args.rust_client.resolve(), "rust_service": args.rust_service.resolve()}
        report["participants"] = {name: {"original": str(path), "sha256": digest(path)} for name, path in participants.items()}
        active = {name: snapshot(path, binaries, name) for name, path in participants.items()}
        for name, path in active.items():
            report["participants"][name]["snapshot"] = str(path)
        # Do not let a developer's GNUNET_BASE_CONFIG, activation hints or test
        # overrides replace these private fixtures. HOME is left untouched;
        # task-specific XDG locations isolate configuration/data without
        # changing the user's actual environment or home directory.
        env = {name: value for name, value in os.environ.items() if not name.startswith("GNUNET_")}
        env.update(receipt["runtime_environment"], LC_ALL="C")
        harness = Harness(output, env)
        report["commands"], report["checks"] = harness.commands, harness.checks
        report["diagnostics"] = harness.diagnostics
        report["malformed_probes"] = harness.probes
        owned = Path(tempfile.mkdtemp(prefix="gn-iop-", dir="/private/tmp"))
        owned.chmod(0o700)
        for name, relative in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime")):
            directory = owned / relative
            directory.mkdir(mode=0o700)
            env[name] = str(directory)
        report["owned_runtime"] = str(owned)
        # Rust client against the actual unmodified reference daemon.
        c_socket, c_dump, c_conf = owned / "c.sock", owned / "c.dat", owned / "c.conf"
        config(c_conf, c_socket, c_dump)
        shutil.copy2(c_conf, output / "c-service.conf")
        c_server = harness.start("c-service-first", [str(active["c_service"]), "-c", str(c_conf), "-L", "ERROR"])
        harness.ready(c_server, c_socket)
        report["full_c_statistics_daemon"] = True
        rust_set(harness, active["rust_client"], c_socket, COUNTER, 41, persistent=True)
        rust_get(harness, active["rust_client"], c_socket, COUNTER, 41, True)
        c_get(harness, active["c_client"], c_conf, COUNTER, 41)
        if not args.normal_only:
            harness.malformed("c-service", c_socket)
            c_get(harness, active["c_client"], c_conf, COUNTER, 41)
        c_set(harness, active["c_client"], c_conf, COUNTER, 57)
        rust_get(harness, active["rust_client"], c_socket, COUNTER, 57, False)
        rust_set(harness, active["rust_client"], c_socket, COUNTER, 99, persistent=True)
        rust_set(harness, active["rust_client"], c_socket, TRANSIENT, 7)
        c_get(harness, active["c_client"], c_conf, TRANSIENT, 7)
        harness.finish(c_server)
        c_rows = read_dump(c_dump)
        harness.check("c-dump-official-set-stream", any(row["subsystem"] == SUBSYSTEM.encode().hex() and row["name"] == COUNTER.encode().hex() and row["value"] == 99 for row in c_rows), c_rows)
        shutil.copy2(c_dump, output / "c-statistics.dat")
        c_restart = harness.start("c-service-restart", [str(active["c_service"]), "-c", str(c_conf), "-L", "ERROR"])
        harness.ready(c_restart, c_socket)
        rust_get(harness, active["rust_client"], c_socket, COUNTER, 99, True)
        rust_get(harness, active["rust_client"], c_socket, TRANSIENT, None)
        harness.finish(c_restart)
        if not args.normal_only:
            # Keep the known invalid-message reference bug off the successful
            # persistent-restart instances. It cannot earn compatibility credit.
            bad_socket, bad_conf = owned / "bad-c.sock", owned / "bad-c.conf"
            config(bad_conf, bad_socket, owned / "bad-c.dat")
            bad_reference = harness.start("c-service-known-invalid-message-variance", [str(active["c_service"]), "-c", str(bad_conf), "-L", "ERROR"], diagnostic=True)
            harness.ready(bad_reference, bad_socket)
            harness.unknown_type("c-service", bad_socket, expect_timeout=True)
            harness.reference_unknown_shutdown(bad_reference)
        # Unmodified reference C client against the real Rust service host.
        r_socket, r_dump, r_conf = owned / "r.sock", owned / "r.dat", owned / "r.conf"
        config(r_conf, r_socket, r_dump)
        shutil.copy2(r_conf, output / "rust-service.conf")
        def start_rust(generation, configuration=r_conf, socket_path=r_socket):
            command = [str(active["rust_service"]), "-c", str(configuration), "-L", "ERROR"]
            service = harness.start("rust-service-" + str(generation), command)
            harness.ready(service, socket_path, b"READY statistics wire=0.29.1 persistence=official-set-snapshot authentication=kernel-unix\n")
            return service
        rust_server = start_rust(0)
        c_set(harness, active["c_client"], r_conf, COUNTER, 55, persistent=True)
        rust_get(harness, active["rust_client"], r_socket, COUNTER, 55, True)
        c_get(harness, active["c_client"], r_conf, COUNTER, 55)
        if not args.normal_only:
            harness.malformed("rust-service", r_socket)
            harness.unknown_type("rust-service", r_socket, expect_timeout=False)
            c_get(harness, active["c_client"], r_conf, COUNTER, 55)
        watcher = harness.start("c-watch-rust-service", [str(active["c_client"]), "-c", str(r_conf), "-L", "ERROR", "-q", "-w", "-s", SUBSYSTEM, "-n", COUNTER], watch=True)
        harness.watch_value(watcher, 55)
        rust_set(harness, active["rust_client"], r_socket, COUNTER, 57, persistent=True)
        harness.watch_value(watcher, 57)
        rust_set(harness, active["rust_client"], r_socket, COUNTER, -9, persistent=True, relative=True)
        harness.watch_value(watcher, 48)
        harness.finish(watcher)
        harness.check("c-watch-exact-notifications", watcher["out_path"].read_bytes().splitlines() == [b"55", b"57", b"48"])
        c_get(harness, active["c_client"], r_conf, COUNTER, 48)
        c_set(harness, active["c_client"], r_conf, TRANSIENT, 7)
        rust_get(harness, active["rust_client"], r_socket, TRANSIENT, 7, False)
        harness.finish(rust_server)
        harness.check("rust-first-socket-cleanup", not r_socket.exists())
        r_rows = read_dump(r_dump)
        harness.check("rust-dump-official-set-stream", any(row["subsystem"] == SUBSYSTEM.encode().hex() and row["name"] == COUNTER.encode().hex() and row["value"] == 48 for row in r_rows), r_rows)
        shutil.copy2(r_dump, output / "rust-statistics.dat")
        rust_restart = start_rust(1)
        c_get(harness, active["c_client"], r_conf, COUNTER, 48)
        rust_get(harness, active["rust_client"], r_socket, COUNTER, 48, True)
        rust_get(harness, active["rust_client"], r_socket, TRANSIENT, None)
        harness.finish(rust_restart)
        harness.check("rust-restart-socket-cleanup", not r_socket.exists())
        # Load each implementation's real persistent file with the other
        # implementation; byte inspection alone would not establish this.
        cross_c_socket, cross_c_conf, cross_c_dump = owned / "xc.sock", owned / "xc.conf", owned / "xc.dat"
        shutil.copy2(r_dump, cross_c_dump)
        config(cross_c_conf, cross_c_socket, cross_c_dump)
        cross_c = harness.start("c-service-load-rust-dump", [str(active["c_service"]), "-c", str(cross_c_conf), "-L", "ERROR"])
        harness.ready(cross_c, cross_c_socket)
        c_get(harness, active["c_client"], cross_c_conf, COUNTER, 48)
        rust_get(harness, active["rust_client"], cross_c_socket, COUNTER, 48, True)
        harness.finish(cross_c)
        cross_r_socket, cross_r_conf, cross_r_dump = owned / "xr.sock", owned / "xr.conf", owned / "xr.dat"
        shutil.copy2(c_dump, cross_r_dump)
        config(cross_r_conf, cross_r_socket, cross_r_dump)
        cross_r = start_rust("load-c-dump", cross_r_conf, cross_r_socket)
        c_get(harness, active["c_client"], cross_r_conf, COUNTER, 99)
        rust_get(harness, active["rust_client"], cross_r_socket, COUNTER, 99, True)
        harness.finish(cross_r)
        harness.check("rust-cross-load-socket-cleanup", not cross_r_socket.exists())
        report["source_unchanged"] = fingerprints(ROOT) == before
        report["reference_unchanged"] = source_state(Path(receipt["source"])) == original_state
        report["reference_runtime_inputs_unchanged"] = all(digest(row["path"]) == row["sha256"] for row in reference_runtime_inputs)
        report["participants_unchanged"] = all(digest(path) == report["participants"][name]["sha256"] == digest(active[name]) for name, path in participants.items())
        report["reference_diagnostics"] = [{"name": row["name"], "stderr": row["stderr"], "bytes": (output / row["stderr"]).stat().st_size, "stderr_sha256": row["stderr_sha256"]}
                                           for row in harness.commands + harness.diagnostics["commands"] if row["name"].startswith("c-") and (output / row["stderr"]).stat().st_size]
        report["known_variances"] = ["Pinned C WATCH client interprets persistence using the VALUE UID high bit, while the actual C and Rust servers emit flags bit 2. Numeric watch values are checked; this report does not erase that upstream flag interpretation discrepancy."]
        if not args.normal_only:
            report["known_variances"].append("Pinned C MQ_inject_message does not handle NO for an unmatched type, leaving that invalid-message connection paused and preventing soft shutdown. A separate C diagnostic instance observes the read/soft-shutdown timeout and is explicitly killed and reaped. Normal persistent C instances must exit zero. Rust closes unsupported requests. This is not identical invalid-message behavior or whole-service compatibility credit.")
        harness.check("all-proof-inputs-unchanged", report["source_unchanged"] and report["reference_unchanged"] and report["reference_runtime_inputs_unchanged"] and report["participants_unchanged"])
        report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        cleanup_errors = []
        if harness is not None:
            try:
                harness.cleanup()
            except BaseException as error:
                cleanup_errors.append({"phase": "harness-cleanup", "error": type(error).__name__ + ": " + str(error)})
            cleanup_errors.extend(harness.cleanup_errors)
            report["executed_checks"] = len(harness.checks)
            report["diagnostic_observations"] = len(harness.diagnostics["checks"])
            report["owned_processes_reaped"] = True
            for child in harness.services:
                try:
                    if child["process"] is not None and child["process"].poll() is None:
                        report["owned_processes_reaped"] = False
                        cleanup_errors.append({"name": child["row"]["name"], "phase": "final-reap-observation", "error": "owned child remains live"})
                except BaseException as error:
                    report["owned_processes_reaped"] = False
                    cleanup_errors.append({"name": child["row"]["name"], "phase": "final-reap-observation", "error": type(error).__name__ + ": " + str(error)})
        if owned is not None:
            try:
                shutil.rmtree(owned)
                report["owned_runtime_removed"] = not owned.exists()
            except BaseException as error:
                report["owned_runtime_removed"] = False
                cleanup_errors.append({"phase": "runtime-directory", "error": type(error).__name__ + ": " + str(error)})
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["status"] = "failed"
        try:
            save(output / "result.json", report)
        except BaseException as error:
            report["status"] = "failed"
            report["report_failure"] = type(error).__name__ + ": " + str(error)
    print(json.dumps({"status": report["status"], "executed_checks": report["executed_checks"], "report": str(output / "result.json"), "failure": report.get("failure"), "cleanup_errors": report.get("cleanup_errors", []), "report_failure": report.get("report_failure")}))
    return 0 if report["status"] == "passed" else 1


def main():
    def interrupted(signum, _frame):
        raise InterruptedError("harness interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path, help="build_reference.py build-result.json")
    parser.add_argument("--rust-client", required=True, type=Path)
    parser.add_argument("--rust-service", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--normal-only", action="store_true", help="Select normal Unix GET/SET, C WATCH and graceful persistence restart; exclude protocol-error probes")
    return run_suite(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
