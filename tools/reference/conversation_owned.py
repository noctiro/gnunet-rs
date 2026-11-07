"""Bounded owned normal-process IO for the Conversation controller.

Importing defines code only. There is no component runner, subprocess, key,
socket, device, source fingerprint or signal operation at module import.
"""
import errno
import hashlib
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import termios
import time


class Blocked(RuntimeError):
    """A concrete prerequisite/approval is absent; never a protocol pass."""


class ObservationError(RuntimeError):
    """An actual owned operation failed or its original target elapsed."""


def described(error):
    return {"type": type(error).__name__, "message": str(error)}


def file_hash(path, maximum=1 << 30):
    """Hash only an explicitly named participant/public metadata file."""
    count = 0
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            data = stream.read(1 << 16)
            if not data:
                break
            count += len(data)
            if count > maximum:
                raise Blocked("named participant/metadata exceeds the finite file bound")
            h.update(data)
    return h.hexdigest(), count


class Deadline:
    def __init__(self, seconds, parent=None):
        if not 0 < seconds <= 1800:
            raise Blocked("deadline must be finite, positive and at most1800s")
        self.hard = time.monotonic() + seconds
        if parent is not None:
            self.hard = min(self.hard, parent.hard)

    def remaining(self):
        value = self.hard - time.monotonic()
        if value <= 0:
            raise ObservationError("original owned operation deadline elapsed")
        return value

    def check(self):
        self.remaining()


class Owner:
    """Every row is registered before acquiring descriptors or starting Popen."""
    def __init__(self, serial, name, role, argv):
        self.process = None
        self.master = None
        self.slave = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.logs = {}
        self.open_readers = {}
        self.capture_expected = set()
        self.capture_eof = set()
        self.capture_terminal = None
        self.output = {"stdout": bytearray(), "stderr": bytearray()}
        self.stdin_cursor = 0
        self.expected = None
        self.allow_exit = False
        self.finalized = False
        self.row = {"id": serial, "name": name, "role": role, "argv": list(argv),
                    "pid": None, "spawned": False, "reaped": False,
                    "exit_code": None, "signals": [], "stdin_events": [],
                    "stdout_bytes": 0, "stderr_bytes": 0,
                    "stdout_sha256": None, "stderr_sha256": None,
                    "cleanup": [], "deferred_signals": []}


class Controller:
    def __init__(self, evidence, seconds=120, output_bytes=4 << 20,
                 total_output_bytes=128 << 20, maximum_children=128):
        self.evidence = Path(evidence)
        self.deadline = Deadline(seconds)
        if not 65536 <= output_bytes <= 16 << 20:
            raise Blocked("per-stream output bound is invalid")
        if not output_bytes <= total_output_bytes <= 256 << 20:
            raise Blocked("total output bound is invalid")
        if not 1 <= maximum_children <= 256:
            raise Blocked("owned child count bound is invalid")
        self.stream_limit = output_bytes
        self.total_limit = total_output_bytes
        self.maximum_children = maximum_children
        self.total_read = 0
        self.children = []
        self.serial = 0
        self.cleanup_errors = []
        self.cleanup_overflow = False
        self.phase = "running"
        self.cleanup_started = None
        self.cleanup_soft = None
        self.cleanup_hard = None
        self.cleanup_finished = None
        self.cleanup_term_finished = None
        self.cleanup_kill_started = None
        self.cleanup_finalize_started = None
        self._cleanup_in_progress = False
        self.read_cursor = 0
        # Allocated before the first participant. The actual main handler only
        # updates these two rows during cleanup; it never interrupts physical
        # retirement or turns a second signal into a fresh business action.
        self.cleanup_signal_rows = {
            int(signum): {"owner": None, "stage": "cleanup-signal",
                          "signal": int(signum), "count": 0, "saturated": False,
                          "error": {"type": "InterruptedError",
                                    "message": "handled signal observed during original cleanup: " + str(int(signum))}}
            for signum in (signal.SIGINT, signal.SIGTERM)
        }

    @property
    def active(self):
        return self.phase == "running"

    @active.setter
    def active(self, value):
        # Existing callers arm their cleanup signal handler before invoking
        # cleanup. That transition cannot reopen a retired controller.
        if value:
            self.require_running()
        elif self.phase == "running":
            self.phase = "cleaning"

    def require_running(self):
        if self.phase != "running":
            raise ObservationError("original controller no longer accepts business actions")

    def cleanup_report(self):
        return {"phase": self.phase, "started_monotonic": self.cleanup_started,
                "soft_monotonic": self.cleanup_soft, "hard_monotonic": self.cleanup_hard,
                "finished_monotonic": self.cleanup_finished,
                "term_finished_monotonic": self.cleanup_term_finished,
                "kill_started_monotonic": self.cleanup_kill_started,
                "finalize_started_monotonic": self.cleanup_finalize_started}

    def cleanup_signal(self, signum):
        row = self.cleanup_signal_rows[int(signum)]
        if row["count"] == 0:
            if len(self.cleanup_errors) < 256:
                self.cleanup_errors.append(row)
            else:
                self.cleanup_overflow = True
        if row["count"] < 65535:
            row["count"] += 1
        else:
            row["saturated"] = True

    def cleanup_error(self, owner, stage, error):
        row = {"owner": owner.row["id"] if owner else None,
               "stage": stage, "error": described(error)}
        if len(self.cleanup_errors) < 256:
            self.cleanup_errors.append(row)
        else:
            self.cleanup_overflow = True
        if owner is not None and len(owner.row["cleanup"]) < 32:
            owner.row["cleanup"].append(row)

    def acquire(self, row, operation):
        """Defer only handled INT/TERM through actual return->registration.

        No signal mask/preexec_fn is inherited by a child. Default/ignored
        handlers are untouched. Restore failures prevent new business actions.
        Uncatchable termination is not claimed to be cleanup safe.
        """
        self.require_running()
        previous, pending = {}, {}
        original = None

        def defer(signum, frame):
            pending.setdefault(signum, frame)  # only two possible entries

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                handler = signal.getsignal(signum)
                if callable(handler):
                    previous[signum] = handler
                    signal.signal(signum, defer)
            operation()
        except BaseException as error:
            original = error
            row.row["acquisition_error"] = described(error)
        finally:
            row.row["deferred_signals"] = list(pending)
            for signum, handler in previous.items():
                try:
                    signal.signal(signum, handler)
                except BaseException as error:
                    self.cleanup_error(row, "restore-handler-" + str(signum), error)
                    if original is None:
                        original = error
        if original is not None:
            raise original
        for signum, frame in pending.items():
            previous[signum](signum, frame)

    def start(self, name, argv, env, role="command", interactive=False,
              pty_mode=False, stdin_data=None, expected=None, deadline=None):
        self.require_running()
        self.deadline.check()
        deadline = deadline or self.deadline
        deadline.check()
        if len(self.children) >= self.maximum_children:
            raise ObservationError("bounded owned child table exhausted")
        if not argv or not Path(argv[0]).is_absolute() or any("\0" in a for a in argv):
            raise Blocked("normal argv must use an absolute executable and no NUL")
        self.serial += 1
        owner = Owner(self.serial, name, role, argv)
        owner.expected = expected
        self.children.append(owner)
        stem = f"{owner.row['id']:03d}-{name}"
        owner.row["stdout_file"] = stem + ".stdout"
        owner.row["stderr_file"] = stem + ".stderr"
        owner.row["environment"] = dict(env)
        owner.row["started_monotonic"] = time.monotonic()
        owner.row["interactive"] = interactive
        owner.row["pty"] = pty_mode
        owner.row["deadline_monotonic"] = deadline.hard

        def launch():
            owner.logs["stdout"] = (self.evidence / owner.row["stdout_file"]).open("xb", buffering=0)
            owner.logs["stderr"] = (self.evidence / owner.row["stderr_file"]).open("xb", buffering=0)
            if pty_mode:
                owner.master, owner.slave = pty.openpty()
                attrs = termios.tcgetattr(owner.slave)
                attrs[3] &= ~termios.ECHO
                termios.tcsetattr(owner.slave, termios.TCSANOW, attrs)
                os.set_blocking(owner.master, False)
            # Synchronous acquisition cannot be preempted, but never begin the
            # next native action after the same original target elapsed.
            deadline.check()
            self.deadline.check()
            owner.process = subprocess.Popen(
                argv, env=env, stdin=owner.slave if pty_mode else
                (subprocess.PIPE if interactive or stdin_data is not None else subprocess.DEVNULL),
                stdout=owner.slave if pty_mode else subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(),
                start_new_session=True, shell=False)
            # Actual child handle is registered before any subsequent syscall.
            owner.row["pid"] = owner.process.pid
            owner.row["spawned"] = True
            owner.capture_expected.update(("stdout", "stderr"))
            owner.stdin = owner.process.stdin
            owner.stdout = owner.process.stdout
            owner.stderr = owner.process.stderr
            if owner.slave is not None:
                os.close(owner.slave)
                owner.slave = None
            if owner.stdin is not None:
                os.set_blocking(owner.stdin.fileno(), False)
            if owner.master is not None:
                owner.open_readers[owner.master] = "stdout"
            if owner.stdout is not None:
                os.set_blocking(owner.stdout.fileno(), False)
                owner.open_readers[owner.stdout.fileno()] = "stdout"
            if owner.stderr is not None:
                os.set_blocking(owner.stderr.fileno(), False)
                owner.open_readers[owner.stderr.fileno()] = "stderr"
        self.acquire(owner, launch)
        if stdin_data is not None:
            self.send(owner, stdin_data, deadline, ordinary=False)
            self.close_stdin(owner)
        return owner

    def _log(self, owner, label, data):
        total = len(owner.output[label]) + len(data)
        aggregate = self.total_read + len(data)
        if total > self.stream_limit or aggregate > self.total_limit:
            owner.row["output_overflow"] = {"stream": label, "observed_prefix": total}
            raise ObservationError("bounded original normal stdout/stderr exceeded its cap")
        # Write original bytes without terminal decoding or secret/private file reads.
        written = owner.logs[label].write(data)
        if written != len(data):
            raise ObservationError("evidence output write did not retain its complete original prefix")
        owner.output[label].extend(data)
        owner.row[label + "_bytes"] += len(data)
        self.total_read = aggregate

    def pump(self, timeout=0.1, cleanup=False):
        if not cleanup:
            self.require_running()
            self.deadline.check()
        readers = [(owner, fd, label) for owner in self.children
                   for fd, label in list(owner.open_readers.items())]
        if readers:
            ready = set(select.select([fd for _, fd, _ in readers], [], [], timeout)[0])
            count = len(readers)
            for offset in range(count):
                owner, fd, label = readers[(self.read_cursor + offset) % count]
                if fd not in ready:
                    continue
                try:
                    data = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if owner.master == fd and error.errno == errno.EIO:
                        data = b""
                    else:
                        raise
                if not data:
                    owner.capture_eof.add(label)
                    owner.open_readers.pop(fd, None)
                else:
                    self._log(owner, label, data)
            self.read_cursor = (self.read_cursor + 1) % count
        elif timeout:
            # select([],...) is a bounded interruptible wait, not a hidden thread.
            select.select([], [], [], timeout)
        for owner in self.children:
            if owner.process is None:
                continue
            try:
                code = owner.process.poll()  # actual waitpid/reap of this exact child
            except BaseException as error:
                if not cleanup:
                    raise
                self.cleanup_error(owner, "capture-owner-poll", error)
                continue
            if code is not None:
                owner.row["exit_code"] = code
                owner.row["reaped"] = True
                if not cleanup and not owner.allow_exit and owner.row["role"] != "command":
                    raise ObservationError(f"original owned {owner.row['name']} unexpectedly exited {code}")

    def wait(self, predicate, deadline, label):
        self.require_running()
        while True:
            deadline.check()
            self.deadline.check()
            value = predicate()
            if value is not None:
                return value
            self.pump(min(0.1, deadline.remaining(), self.deadline.remaining()))

    def observed(self, owner, needle, deadline, since=0, stream="stdout"):
        import re
        def find():
            data = bytes(owner.output[stream][since:]).replace(b"\r", b"")
            match = re.search(needle, data)
            if match is not None:
                return {"match": match.group(0).decode("utf-8", "backslashreplace"),
                        "groups": [g.decode("ascii") if g is not None else None for g in match.groups()],
                        "stream": stream, "from_offset": since,
                        "observed_monotonic": time.monotonic()}
            if owner.process.poll() is not None:
                raise ObservationError("original source exited before required normal observation: " + owner.row["name"])
            return None
        return self.wait(find, deadline, "normal observation")

    def send(self, owner, data, deadline, ordinary=True):
        self.require_running()
        if isinstance(data, str):
            data = data.encode("utf-8")
        if len(data) > 65535:
            raise ObservationError("normal input exceeds its bounded command extent")
        if ordinary:
            # The no-device controller has no accept/resume/audio command path.
            text = data.decode("utf-8")
            verb = text.split(maxsplit=1)[0] if text.strip() else ""
            if verb not in ("/address", "/call", "/cancel", "/status", "/quit", "/help"):
                raise Blocked("command is outside the no-device normal profile")
            if text.count("\n") != 1 or not text.endswith("\n"):
                raise Blocked("one original interactive command per input intent")
        row = {"bytes": len(data), "written": 0, "whole": False,
               "sha256": hashlib.sha256(data).hexdigest(),
               "deadline_monotonic": deadline.hard}
        owner.row["stdin_events"].append(row)
        while row["written"] < len(data):
            deadline.check()
            self.deadline.check()
            if owner.process.poll() is not None:
                raise ObservationError("original frontend closed before its input was wholly written")
            fd = owner.master if owner.master is not None else owner.stdin.fileno()
            try:
                n = os.write(fd, data[row["written"]:])
            except BlockingIOError:
                n = 0
            if n:
                row["written"] += n
            self.pump(0 if n else min(0.05, deadline.remaining()))
        row["whole"] = True  # local write only; no application/peer ACK

    def close_stdin(self, owner):
        self.require_running()
        if owner.master is not None:
            raise Blocked("PTY EOT/close is not used as proof of a real pipe-stdin EOF")
        if owner.stdin is not None:
            owner.stdin.close()
            owner.stdin = None
        owner.row["stdin_closed"] = True

    def command(self, name, argv, env, seconds=20, stdin_data=None):
        self.require_running()
        deadline = Deadline(seconds, self.deadline)  # before launch/acquisition
        owner = self.start(name, argv, env, stdin_data=stdin_data, deadline=deadline)
        owner.allow_exit = True
        self.wait(lambda: owner.process.poll() if owner.process.poll() is not None else None,
                  deadline, "normal command exit")
        # A process may exit just before the final pipe chunks are observed.
        while owner.open_readers:
            deadline.check()
            self.pump(min(0.05, deadline.remaining()))
        code = owner.process.wait(timeout=0)
        owner.row.update(exit_code=code, reaped=True)
        if code != 0:
            raise ObservationError(f"normal command {name} exited {code}")
        self.finalize(owner)
        return bytes(owner.output["stdout"])

    def stop_frontend(self, owner, method="quit", expected=(0,)):
        self.require_running()
        deadline = Deadline(10, self.deadline)
        owner.allow_exit = True
        if method == "quit":
            self.send(owner, "/quit\n", deadline)
        elif method == "eof":
            self.close_stdin(owner)
        elif method == "sigint":
            self.signal(owner, signal.SIGINT)
        else:
            raise Blocked("unknown original frontend stop action")
        self.wait(lambda: owner.process.poll() if owner.process.poll() is not None else None,
                  deadline, "original frontend exit")
        while owner.open_readers:
            deadline.check()
            self.pump(min(0.05, deadline.remaining()))
        code = owner.process.wait(timeout=0)
        owner.row.update(exit_code=code, reaped=True, intentional_stop=method)
        if code not in expected:
            raise ObservationError(f"original frontend exited {code}, expected {expected}")
        self.finalize(owner)

    def signal(self, owner, signum):
        if owner.process is None or owner.process.poll() is not None:
            return
        row = {"signal": int(signum), "native_returned": False}
        owner.row["signals"].append(row)
        try:
            owner.process.send_signal(signum)  # exact unreaped Popen, no PID/name/group scan
            row["native_returned"] = True
        except ProcessLookupError as error:
            row["race"] = described(error)
        # Even a returned kill is not proof of exit; consuming wait is separate.

    def finalize(self, owner, require_reaped=True):
        if require_reaped and owner.process is not None and not owner.row["reaped"]:
            raise ObservationError("cannot finalize an unreaped original child")
        if owner.finalized:
            return
        failures = []
        # Freeze capture before any forced descriptor closure. Only a real
        # EOF in pump can discharge an expected stream; emptying open_readers
        # while closing the parent is never evidence of a complete capture.
        if owner.capture_terminal is None:
            owner.capture_terminal = (not owner.open_readers and
                                      owner.capture_expected <= owner.capture_eof)
            owner.row["capture_drained"] = owner.capture_terminal
            owner.row["capture_eof"] = sorted(owner.capture_eof)
            if not owner.capture_terminal:
                owner.row["capture_truncated"] = sorted(
                    owner.capture_expected - owner.capture_eof |
                    set(owner.open_readers.values()))
                failures.append(("capture-drain", ObservationError("original output has undrained pipe/PTY debt")))
        for fd_name in ("master", "slave"):
            fd = getattr(owner, fd_name)
            if fd is not None:
                try:
                    os.close(fd)
                    setattr(owner, fd_name, None)
                    owner.open_readers.pop(fd, None)
                except BaseException as error:
                    failures.append((fd_name + "-close", error))
        for label in ("stdin", "stdout", "stderr"):
            stream = getattr(owner, label)
            if stream is not None:
                try:
                    fd = stream.fileno()
                    stream.close()
                    setattr(owner, label, None)
                    owner.open_readers.pop(fd, None)
                except BaseException as error:
                    failures.append((label + "-close", error))
        for label, stream in list(owner.logs.items()):
            try:
                stream.close()
            except BaseException as error:
                failures.append((label + "-log-close", error))
            if owner.row[label + "_sha256"] is None:
                try:
                    value, size = file_hash(self.evidence / owner.row[label + "_file"], self.stream_limit)
                    owner.row[label + "_sha256"] = value
                    owner.row[label + "_file_bytes"] = size
                except BaseException as error:
                    failures.append((label + "-log-hash", error))
        # Descriptor ownership, output completeness and child reaping are
        # independent facts. Hash failures likewise do not reopen descriptors.
        closed = (all(getattr(owner, name) is None
                      for name in ("master", "slave", "stdin", "stdout", "stderr")) and
                  all(stream.closed for stream in owner.logs.values()))
        owner.row["parent_resources_closed"] = closed
        owner.finalized = closed and all(owner.row[label + "_sha256"] is not None
                                         for label in owner.logs)
        for phase, error in failures:
            self.cleanup_error(owner, phase, error)
        if failures:
            raise ObservationError("independent original owner finalization incomplete")

    def cleanup(self, seconds=10):
        """Retire original resources once, under the first common hard target."""
        if self.phase == "closed" or self._cleanup_in_progress:
            return
        if not 0 <= seconds <= 1800:
            raise Blocked("cleanup deadline must be finite and at most1800s")
        self.phase = "cleaning"
        if self.cleanup_hard is None:
            self.cleanup_started = time.monotonic()
            self.cleanup_hard = self.cleanup_started + seconds
            self.cleanup_soft = min(self.cleanup_hard, self.cleanup_started + seconds / 2)
        self._cleanup_in_progress = True
        completed = False
        try:
            self._cleanup_owned(self.cleanup_hard)
            completed = True
        finally:
            self._cleanup_in_progress = False
            if completed:
                self.cleanup_finished = time.monotonic()
                # Closed ends this supervisor lifecycle. Reaping/capture/FD
                # outcomes remain independent and can still record failure.
                self.phase = "closed"

    def _cleanup_owned(self, hard):
        """Attempt every original resource even after another attempt fails."""
        for owner in reversed(self.children):
            owner.allow_exit = True
            if owner.process is None:
                continue
            try:
                if owner.stdin is not None:
                    owner.stdin.close()
                    owner.stdin = None
            except BaseException as error:
                self.cleanup_error(owner, "stdin-close", error)
            try:
                self.signal(owner, signal.SIGTERM)
            except BaseException as error:
                self.cleanup_error(owner, "term", error)
        if self.cleanup_term_finished is None:
            self.cleanup_term_finished = time.monotonic()
        # One common original grace for all children, not N renewed full waits.
        soft = self.cleanup_soft
        for end, signum in ((soft, None), (hard, signal.SIGKILL)):
            if signum is not None:
                if self.cleanup_kill_started is None:
                    self.cleanup_kill_started = time.monotonic()
                for owner in reversed(self.children):
                    try:
                        self.signal(owner, signum)
                    except BaseException as error:
                        self.cleanup_error(owner, "kill", error)
            while time.monotonic() < end:
                pending = False
                for owner in self.children:
                    if owner.process is None:
                        continue
                    try:
                        code = owner.process.poll()
                        if code is None:
                            pending = True
                        else:
                            owner.row.update(exit_code=code, reaped=True)
                    except BaseException as error:
                        # Unknown is not a guessed exit/reap. Preserve this
                        # cause, then continue every other original handle.
                        self.cleanup_error(owner, "cleanup-owner-poll", error)
                        pending = True
                readers = any(o.open_readers for o in self.children)
                if not pending and not readers:
                    break
                try:
                    self.pump(min(0.05, max(0, end - time.monotonic())), cleanup=True)
                except BaseException as error:
                    self.cleanup_error(None, "cleanup-pump", error)
                    # Continue physical signalling/reap paths even if output/log
                    # capture failed. A short bounded native wait avoids a spin.
                    try:
                        select.select([], [], [], min(0.01, max(0, end - time.monotonic())))
                    except BaseException as wait_error:
                        self.cleanup_error(None, "cleanup-native-wait", wait_error)
        if self.cleanup_finalize_started is None:
            self.cleanup_finalize_started = time.monotonic()
        for owner in reversed(self.children):
            process = owner.process
            if process is not None:
                try:
                    # Attempt the real consuming wait even if an earlier poll
                    # failed. This is inside the original common hard target;
                    # it neither waits a fresh grace nor fabricates an exit.
                    owner.row["exit_code"] = process.wait(timeout=0)
                    owner.row["reaped"] = True
                except subprocess.TimeoutExpired as error:
                    owner.row["unreaped"] = True
                    self.cleanup_error(owner, "reap-deadline", error)
                except BaseException as error:
                    self.cleanup_error(owner, "wait", error)
            # The common native cleanup target above also covers full output
            # EOF. A lingering descendant/pipe is retained as a real failure;
            # never close a nonempty reader table and claim a complete capture.
            try:
                # Even a failed/unknown child wait cannot skip this parent's
                # independent FD/log closure. The original unreaped fact stays
                # false and prevents a pass/removal; closing a pipe is no reap.
                self.finalize(owner, require_reaped=False)
            except BaseException as error:
                self.cleanup_error(owner, "finalize", error)

    def reports(self):
        return [owner.row for owner in self.children]
