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
import sys
import tempfile
import time

from build_reference import REVISION, source_state
from linux_images import Images
from source_fingerprint import fingerprints

ROOT = Path(__file__).resolve().parents[2]
SUBSYSTEM = "rust-c-interop"
COUNTER = "counter"
TRANSIENT = "transient"


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def artifact(path, output):
    return {"path": path.relative_to(output).as_posix(), "sha256": digest(path)}


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
    def __init__(self, output, env, images=None):
        self.output = output
        self.env = env
        self.commands = []
        self.checks = []
        self.services = []
        self.cleanup_errors = []
        self.probes = []
        self.diagnostics = {"commands": [], "checks": [], "probes": []}
        self.configurations = {}
        self.serial = 0
        self.images = images

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
        owned = self.start(name, argv, one_shot=True)
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

    def start(self, name, argv, watch=False, diagnostic=False, pass_fds=(), env=None, one_shot=False):
        self.serial += 1
        stem = f"{self.serial:02d}-{name}"
        out, err = self.output / (stem + ".stdout"), self.output / (stem + ".stderr")
        row = {"name": name, "argv": [str(arg) for arg in argv],
               "stdout": out.name, "stderr": err.name, "owned_process_group": True,
               "diagnostic": diagnostic, "one_shot": one_shot}
        for flag, value in zip(row["argv"][1:], row["argv"][2:]):
            if flag == "-c" and value in self.configurations:
                row["configuration"] = self.configurations[value]
                break
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
        if "ready_images" in owned["row"]:
            self.capture_images(owned, "pre_stop_images")
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
                    key = label + "_sha256"
                    if owned["row"].setdefault(key, value) != value:
                        self.cleanup_error(owned, label + "-digest", ValueError("retained log changed"))
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

    def capture_images(self, owned, phase):
        row = owned["row"]
        if self.images is None or row["diagnostic"]:
            return
        try:
            row[phase] = self.images.capture(owned["process"], row["argv"][0])
        except (OSError, ValueError) as error:
            row[phase] = {"unavailable": str(error)}

    def retain_config(self, path, socket_path, database, name):
        config(path, socket_path, database)
        target = self.output / name
        shutil.copy2(path, target)
        self.configurations[str(path)] = artifact(target, self.output)

    def configurations_unchanged(self):
        return all(digest(original) == digest(self.output / ref["path"]) == ref["sha256"]
                   for original, ref in self.configurations.items())

    def image_coverage(self, participants, normal_passed):
        # A passing behavior run may lack mapped-file proof. Keep the image
        # qualification explicit and scope it to actual long-lived actors.
        coverage = {"status": "not-requested"}
        if self.images is None:
            return coverage
        staged = {row["snapshot"]: row["sha256"] for row in participants.values()}
        observed, uncovered, errors, checked = [], [], [], {}
        for row in self.commands:
            command = row["stdout"]
            if row["one_shot"]:
                uncovered.append(command)
                continue
            try:
                ready, final = row.get("ready_images", {}), row.get("pre_stop_images", {})
                if "binary" not in ready or "binary" not in final:
                    raise ValueError("missing live image snapshot")
                if ready != final:
                    raise ValueError("mapped images changed between observations")
                if staged.get(row["argv"][0]) != ready["binary"]["sha256"]:
                    raise ValueError("mapped executable differs from the staged actor")
                binary, *dependencies = [entry["artifact"] for entry in ready["mapped_files"]]
                loaded = {ref["path"]: ref["sha256"] for ref in dependencies}
                if binary != ready["binary"] or loaded != ready["loaded_files"]:
                    raise ValueError("mapped-file inventory disagrees with retained artifacts")
                if (type(row.get("exit_code")) is not int or row["exit_code"] != 0
                        or row.get("forced_kill") or row.get("forced_cleanup")
                        or row.get("launch_failure")):
                    raise ValueError("missing normal actor exit")
                for path, expected in {**loaded, binary["path"]: binary["sha256"]}.items():
                    if path not in checked:
                        checked[path] = digest(self.output / path)
                    if checked[path] != expected:
                        raise ValueError("retained mapped-file bytes changed")
            except (OSError, ValueError) as error:
                errors.append({"stdout": command, "reason": str(error)})
            else:
                observed.append(command)
        return {
            "status": "matched-long-lived-actors" if normal_passed and observed and not errors else "incomplete",
            "matched_long_lived": observed,
            "unobserved_one_shot": uncovered,
            "excluded_diagnostic": [row["stdout"] for row in self.diagnostics["commands"]],
            "failures": errors,
        }

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
                    except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
                        time.sleep(.02)
                        continue
                if stdout_line is not None:
                    self.check(owned["row"]["name"] + "-initialized-stdout", True, {"owned_pid": owned["process"].pid, "line": stdout_line.decode().rstrip("\n")}, diagnostic=owned["row"]["diagnostic"])
                self.check(owned["row"]["name"] + "-listening", True, diagnostic=owned["row"]["diagnostic"])
                self.capture_images(owned, "ready_images")
                return
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


def text_selector(binary, conf, name, *, quiet=False):
    argv = [str(binary), "-c", str(conf), "-L", "ERROR"]
    if quiet:
        argv.append("-q")
    return [*argv, "-s", SUBSYSTEM, "-n", name]


def c_get(harness, binary, conf, name, expected):
    raw = harness.command("c-get-" + name, text_selector(binary, conf, name, quiet=True))
    harness.check("c-get-" + name + "-value", raw.strip() == str(expected).encode(), {"actual": raw.decode(errors="replace"), "expected": expected})
    return raw


def c_set(harness, binary, conf, name, value, persistent=False):
    argv = text_selector(binary, conf, name)
    if persistent:
        argv.append("-p")
    harness.command("c-set-" + name, [*argv, str(value)])


def standalone_rust_roundtrip(harness, rust, reference, conf, name, value):
    raw = harness.command("rust-statistics-set-" + name, [*text_selector(rust, conf, name), "-p", str(value)])
    harness.check("rust-statistics-set-" + name + "-stdout", raw == b"", raw.decode(errors="replace"))
    actual = harness.command("rust-statistics-get-" + name, text_selector(rust, conf, name, quiet=True))
    c_output = c_get(harness, reference, conf, name, value)
    expected = f"{value:16}\n"
    harness.check("rust-statistics-get-" + name + "-text", actual == c_output == expected.encode(),
                  {"rust": actual.decode(errors="replace"), "c": c_output.decode(errors="replace"), "expected": expected})


def snapshot(binary, directory, name):
    target = directory / name
    shutil.copy2(binary, target)
    target.chmod(0o700)
    if digest(binary) != digest(target):
        raise ValueError("participant snapshot changed")
    return target


def normal_cases(harness, active, owned, report, normal_only):
    output = harness.output
    # Rust client against the actual unmodified reference daemon.
    c_socket, c_dump, c_conf = owned / "c.sock", owned / "c.dat", owned / "c.conf"
    harness.retain_config(c_conf, c_socket, c_dump, "c-service.conf")
    c_server = harness.start("c-service-first", [str(active["c_service"]), "-c", str(c_conf), "-L", "ERROR"])
    harness.ready(c_server, c_socket)
    report["full_c_statistics_daemon"] = True
    rust_set(harness, active["rust_client"], c_socket, COUNTER, 41, persistent=True)
    rust_get(harness, active["rust_client"], c_socket, COUNTER, 41, True)
    c_get(harness, active["c_client"], c_conf, COUNTER, 41)
    if not normal_only:
        harness.malformed("c-service", c_socket)
        c_get(harness, active["c_client"], c_conf, COUNTER, 41)
    standalone_rust_roundtrip(harness, active["rust_statistics"], active["c_client"], c_conf, COUNTER, 43)
    rust_get(harness, active["rust_client"], c_socket, COUNTER, 43, True)
    c_set(harness, active["c_client"], c_conf, COUNTER, 57)
    rust_get(harness, active["rust_client"], c_socket, COUNTER, 57, False)
    rust_set(harness, active["rust_client"], c_socket, COUNTER, 99, persistent=True)
    rust_set(harness, active["rust_client"], c_socket, TRANSIENT, 7)
    c_get(harness, active["c_client"], c_conf, TRANSIENT, 7)
    harness.finish(c_server)
    c_retained = output / "c-statistics.dat"
    shutil.copy2(c_dump, c_retained)
    c_rows = read_dump(c_retained)
    harness.check("c-dump-official-set-stream", any(row["subsystem"] == SUBSYSTEM.encode().hex() and row["name"] == COUNTER.encode().hex() and row["value"] == 99 for row in c_rows), c_rows)
    c_restart = harness.start("c-service-restart", [str(active["c_service"]), "-c", str(c_conf), "-L", "ERROR"])
    harness.ready(c_restart, c_socket)
    rust_get(harness, active["rust_client"], c_socket, COUNTER, 99, True)
    rust_get(harness, active["rust_client"], c_socket, TRANSIENT, None)
    harness.finish(c_restart)
    if not normal_only:
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
    harness.retain_config(r_conf, r_socket, r_dump, "rust-service.conf")
    def start_rust(generation, configuration=r_conf, socket_path=r_socket):
        command = [str(active["rust_service"]), "-c", str(configuration), "-L", "ERROR"]
        service = harness.start("rust-service-" + str(generation), command)
        harness.ready(service, socket_path, b"READY statistics persistence=official-set-snapshot\n")
        return service
    rust_server = start_rust(0)
    c_set(harness, active["c_client"], r_conf, COUNTER, 55, persistent=True)
    rust_get(harness, active["rust_client"], r_socket, COUNTER, 55, True)
    c_get(harness, active["c_client"], r_conf, COUNTER, 55)
    if not normal_only:
        harness.malformed("rust-service", r_socket)
        harness.unknown_type("rust-service", r_socket, expect_timeout=False)
        c_get(harness, active["c_client"], r_conf, COUNTER, 55)
    watcher = harness.start("c-watch-rust-service", [str(active["c_client"]), "-c", str(r_conf), "-L", "ERROR", "-q", "-w", "-s", SUBSYSTEM, "-n", COUNTER], watch=True)
    harness.watch_value(watcher, 55)
    harness.capture_images(watcher, "ready_images")
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
    r_retained = output / "rust-statistics.dat"
    shutil.copy2(r_dump, r_retained)
    r_rows = read_dump(r_retained)
    harness.check("rust-dump-official-set-stream", any(row["subsystem"] == SUBSYSTEM.encode().hex() and row["name"] == COUNTER.encode().hex() and row["value"] == 48 for row in r_rows), r_rows)
    report["persistent_dumps"] = [artifact(path, output) for path in (c_retained, r_retained)]
    rust_restart = start_rust(1)
    c_get(harness, active["c_client"], r_conf, COUNTER, 48)
    rust_get(harness, active["rust_client"], r_socket, COUNTER, 48, True)
    rust_get(harness, active["rust_client"], r_socket, TRANSIENT, None)
    harness.finish(rust_restart)
    harness.check("rust-restart-socket-cleanup", not r_socket.exists())
    # Load each implementation's real persistent file with the other
    # implementation; byte inspection alone would not establish this.
    cross_c_socket, cross_c_conf, cross_c_dump = owned / "xc.sock", owned / "xc.conf", owned / "xc.dat"
    shutil.copy2(r_retained, cross_c_dump)
    harness.retain_config(cross_c_conf, cross_c_socket, cross_c_dump, "c-load-rust-dump.conf")
    cross_c = harness.start("c-service-load-rust-dump", [str(active["c_service"]), "-c", str(cross_c_conf), "-L", "ERROR"])
    harness.ready(cross_c, cross_c_socket)
    c_get(harness, active["c_client"], cross_c_conf, COUNTER, 48)
    rust_get(harness, active["rust_client"], cross_c_socket, COUNTER, 48, True)
    harness.finish(cross_c)
    cross_r_socket, cross_r_conf, cross_r_dump = owned / "xr.sock", owned / "xr.conf", owned / "xr.dat"
    shutil.copy2(c_retained, cross_r_dump)
    harness.retain_config(cross_r_conf, cross_r_socket, cross_r_dump, "rust-load-c-dump.conf")
    cross_r = start_rust("load-c-dump", cross_r_conf, cross_r_socket)
    c_get(harness, active["c_client"], cross_r_conf, COUNTER, 99)
    rust_get(harness, active["rust_client"], cross_r_socket, COUNTER, 99, True)
    harness.finish(cross_r)
    harness.check("rust-cross-load-socket-cleanup", not cross_r_socket.exists())


def watch_initial(harness, active, owned, report):
    value = 55
    socket_path, database, configuration = owned / "watch.sock", owned / "watch.dat", owned / "watch.conf"
    names = SUBSYSTEM.encode() + b"\0" + COUNTER.encode() + b"\0"
    # Public SET dump framing, independent of the Rust store encoder.
    frame = (16 + len(names)).to_bytes(2, "big") + b"\x00\xa8\x00\x00\x00\x02"
    fixture = harness.output / "watch-initial-input.dat"
    fixture.write_bytes(frame + value.to_bytes(8, "big") + names)
    report["persistent_dumps"] = [artifact(fixture, harness.output)]
    shutil.copy2(fixture, database)
    harness.retain_config(configuration, socket_path, database, "watch-initial.conf")

    service = harness.start("rust-service-watch-initial",
                            [str(active["rust_service"]), "-c", str(configuration), "-L", "ERROR"])
    harness.ready(service, socket_path, b"READY statistics persistence=official-set-snapshot\n")
    command = [str(active["c_client"]), "-c", str(configuration), "-L", "ERROR",
               "-q", "-w", "-s", SUBSYSTEM, "-n", COUNTER]
    watcher = harness.start("c-watch-initial", command, watch=True)
    harness.watch_value(watcher, value)
    harness.capture_images(watcher, "ready_images")
    harness.finish(watcher)
    harness.check("c-watch-exact-initial-value",
                  watcher["out_path"].read_bytes().splitlines() == [str(value).encode()])
    harness.finish(service)
    harness.check("watch-initial-socket-cleanup", not socket_path.exists())


def run_suite(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    capture_requested = getattr(args, "capture_linux_images", False)
    watch_initial_only = getattr(args, "watch_initial_only", False)
    report = {"schema": 1, "kind": "official-c-statistics-daemon-ipc", "status": "failed",
              "full_c_statistics_daemon": False, "full_gnunet_peer": False, "p2p_peer_interoperation": False,
              "scope": "Actual upstream STATISTICS daemon and CLI in both directions, standalone Rust CLI absolute SET and selector GET, WATCH and observed graceful persistent restart. No whole GNUnet peer, ARM activation, crash consistency or full API-inventory certification.",
              "selected_profile": "first-normal" if args.normal_only else "normal-with-protocol-diagnostics",
              "unexecuted_profiles": ["malformed/partial-EOF", "unknown-message-type"] if args.normal_only else [],
              "executed_checks": 0, "commands": [], "checks": [],
              "linux_image_capture": {"status": "incomplete" if capture_requested else "not-requested"}}
    if watch_initial_only:
        report.update(selected_profile="watch-initial-only",
                      scope="Official C WATCH initial numeric notification from an actual Rust STATISTICS daemon over private Unix IPC. Startup uses an independently encoded persistent SET fixture.",
                      unexecuted_profiles=["SET", "GET", "WATCH changes", "persistence restart", "diagnostics"])
    harness = None
    owned = None
    try:
        raw_receipt = args.reference.read_bytes()
        receipt = json.loads(raw_receipt)
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
        frozen_receipt = output / "reference-build.json"
        frozen_receipt.write_bytes(raw_receipt)
        report["reference_receipt"] = {"path": str(args.reference.resolve()),
                                       "sha256": hashlib.sha256(raw_receipt).hexdigest()}
        report["retained_reference_receipt"] = artifact(frozen_receipt, output)
        binaries = output / "binaries"
        binaries.mkdir()
        participants = {"c_client": Path(receipt["artifacts"]["client"]["path"]),
                        "rust_service": args.rust_service.resolve()}
        if not watch_initial_only:
            participants.update(c_service=Path(receipt["artifacts"]["service"]["path"]),
                                rust_client=args.rust_client.resolve(),
                                rust_statistics=args.rust_statistics.resolve())
        report["participants"] = {name: {"original": str(path), "sha256": digest(path)} for name, path in participants.items()}
        active = {name: snapshot(path, binaries, name) for name, path in participants.items()}
        for name, path in active.items():
            report["participants"][name]["snapshot"] = str(path)
        # Do not let a developer's GNUNET_BASE_CONFIG, activation hints or test
        # overrides replace these private fixtures. HOME is left untouched;
        # task-specific XDG locations isolate configuration/data without
        # changing the user's actual environment or home directory.
        excluded = ("GNUNET_", "LD_", "DYLD_") if watch_initial_only else ("GNUNET_",)
        env = {name: value for name, value in os.environ.items() if not name.startswith(excluded)}
        if watch_initial_only:
            prefix = Path(receipt["prefix"])
            expected_env = {"GNUNET_PREFIX": str(prefix), "LD_LIBRARY_PATH": str(prefix / "lib"),
                            "DYLD_LIBRARY_PATH": str(prefix / "lib")}
            if receipt["runtime_environment"] != expected_env:
                raise ValueError("reference runtime environment must match the normal staged library prefix")
        env.update(receipt["runtime_environment"], LC_ALL="C")
        images = Images(output) if capture_requested else None
        harness = Harness(output, env, images)
        report["commands"], report["checks"] = harness.commands, harness.checks
        report["configurations"] = harness.configurations
        report["diagnostics"] = harness.diagnostics
        report["malformed_probes"] = harness.probes
        owned = Path(tempfile.mkdtemp(prefix="gn-iop-"))
        owned.chmod(0o700)
        for name, relative in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime")):
            directory = owned / relative
            directory.mkdir(mode=0o700)
            env[name] = str(directory)
        report["owned_runtime"] = str(owned)
        if watch_initial_only:
            watch_initial(harness, active, owned, report)
        else:
            normal_cases(harness, active, owned, report, args.normal_only)
        report["source_unchanged"] = fingerprints(ROOT) == before
        report["reference_unchanged"] = source_state(Path(receipt["source"])) == original_state
        report["reference_receipt_unchanged"] = (digest(args.reference) == digest(frozen_receipt)
                                                == report["reference_receipt"]["sha256"])
        report["reference_runtime_inputs_unchanged"] = all(digest(row["path"]) == row["sha256"] for row in reference_runtime_inputs)
        report["configurations_unchanged"] = harness.configurations_unchanged()
        report["participants_unchanged"] = all(digest(path) == report["participants"][name]["sha256"] == digest(active[name]) for name, path in participants.items())
        report["persistent_dumps_unchanged"] = all(
            digest(output / ref["path"]) == ref["sha256"] for ref in report["persistent_dumps"]
        )
        report["reference_diagnostics"] = [{"name": row["name"], "stderr": row["stderr"], "bytes": (output / row["stderr"]).stat().st_size, "stderr_sha256": row["stderr_sha256"]}
                                           for row in harness.commands + harness.diagnostics["commands"] if row["name"].startswith("c-") and (output / row["stderr"]).stat().st_size]
        report["known_variances"] = ["Pinned C WATCH client interprets persistence using the VALUE UID high bit, while the actual C and Rust servers emit flags bit 2. Numeric watch values are checked; this report does not erase that upstream flag interpretation discrepancy."]
        if not args.normal_only and not watch_initial_only:
            report["known_variances"].append("Pinned C MQ_inject_message does not handle NO for an unmatched type, leaving that invalid-message connection paused and preventing soft shutdown. A separate C diagnostic instance observes the read/soft-shutdown timeout and is explicitly killed and reaped. Normal persistent C instances must exit zero. Rust closes unsupported requests. This is not identical invalid-message behavior or whole-service compatibility credit.")
        harness.check("all-proof-inputs-unchanged", all(report[key] for key in (
            "source_unchanged", "reference_unchanged", "reference_receipt_unchanged",
            "reference_runtime_inputs_unchanged", "configurations_unchanged",
            "participants_unchanged", "persistent_dumps_unchanged",
        )))
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
        if harness is not None:
            report["linux_image_capture"] = harness.image_coverage(report["participants"], report["status"] == "passed")
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
    parser.add_argument("--rust-client", type=Path, help="Rust gnunet-cli binary for the full suite")
    parser.add_argument("--rust-statistics", type=Path, help="standalone Rust gnunet-statistics binary for the full suite")
    parser.add_argument("--rust-service", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--normal-only", action="store_true", help="Select normal Unix GET/SET, C WATCH and graceful persistence restart; exclude protocol-error probes")
    profiles.add_argument("--watch-initial-only", action="store_true", help="Observe an official C WATCH of preloaded Rust STATISTICS state using only the two long-lived programs")
    parser.add_argument("--capture-linux-images", action="store_true", help="Retain executable file mappings of ready daemons and the C WATCH client through graceful shutdown")
    args = parser.parse_args()
    if not args.watch_initial_only and (args.rust_client is None or args.rust_statistics is None):
        parser.error("the daemon suite requires --rust-client and --rust-statistics")
    if args.capture_linux_images and sys.platform != "linux":
        parser.error("--capture-linux-images requires Linux /proc")
    return run_suite(args)


if __name__ == "__main__":
    raise SystemExit(main())
