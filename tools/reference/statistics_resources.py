"""Bounded, direct resource observations for one original unreaped child.

Calling this module is a runtime operation and needs the controller's current
runtime authorization/guard. Import alone does not read procfs or load libproc.
The caller retains the exact Popen returned by its owned launcher and guarantees
one controller thread, no concurrent poll/wait/reap, no PID/returncode mutation,
and ordinary waitable children (no SIGCHLD=SIG_IGN/SA_NOCLDWAIT). This module never
polls, waits, signals, reaps, discovers another PID, or executes a subprocess.

Counters exclude child CPU. Samples are sequential kernel observations, not an
atomic cross-field snapshot, allocator measurements, or full-lifetime receipts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import subprocess
import sys
import time
from typing import Any

_U64 = (1 << 64) - 1
_READ_LIMIT = 64 * 1024
_PID_MAX = (1 << 31) - 1
_METRICS = (
    "cpu_user_ns", "cpu_system_ns", "rss_current_bytes", "rss_peak_bytes",
    "physical_footprint_current_bytes",
)


@dataclass(frozen=True)
class Reason:
    scope: str
    code: str
    errno: int | None = None
    detail: str | None = None


class SamplingRefused(ValueError):
    """A local owner precondition failed; no replacement PID is sampled."""

    def __init__(self, reason: Reason):
        self.reason = reason
        super().__init__(f"{reason.scope}: {reason.code}")


@dataclass(frozen=True)
class Sample:
    pid: int
    platform: str
    source: str
    observed_monotonic_ns: int
    completed_monotonic_ns: int
    cpu_user_ns: int | None
    cpu_system_ns: int | None
    rss_current_bytes: int | None
    rss_peak_bytes: int | None
    physical_footprint_current_bytes: int | None
    process_start_marker: int | None
    process_start_marker_unit: str | None
    process_exited_observed: bool | None
    status: str
    reasons: tuple[Reason, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _owned(process: subprocess.Popen[bytes], pid: int | None = None) -> int:
    if not isinstance(process, subprocess.Popen):
        raise SamplingRefused(Reason("owner", "original-popen-required"))
    if process.returncode is not None:
        raise SamplingRefused(Reason("owner", "already-reaped-or-observed-exited"))
    actual = process.pid
    if type(actual) is not int or not 0 < actual <= _PID_MAX:
        raise SamplingRefused(Reason("owner", "invalid-owned-pid"))
    if pid is not None and actual != pid:
        raise SamplingRefused(Reason("owner", "original-pid-changed"))
    return actual


def _number(raw: bytes) -> int:
    if not raw or len(raw) > 20 or any(c < 48 or c > 57 for c in raw):
        raise ValueError("invalid bounded unsigned decimal")
    value = int(raw)
    if value > _U64:
        raise ValueError("unsigned counter out of range")
    return value


def _scaled(value: int, numerator: int, denominator: int) -> int:
    if not 0 <= value <= _U64 or numerator <= 0 or denominator <= 0:
        raise ValueError("invalid counter scale")
    # Python's intermediate does not overflow; the published integer is bounded.
    result = value * numerator // denominator
    if result > _U64:
        raise ValueError("scaled counter out of range")
    return result


def _read(path: str) -> bytes:
    with open(path, "rb", buffering=0) as source:
        output = bytearray()
        while len(output) <= _READ_LIMIT:
            chunk = source.read(min(4096, _READ_LIMIT + 1 - len(output)))
            if not chunk:
                return bytes(output)
            output.extend(chunk)
        raise ValueError("proc source exceeds fixed 64KiB limit")


def _failure(scope: str, error: OSError | ValueError) -> Reason:
    return Reason(scope, "os-error" if isinstance(error, OSError) else "invalid-source",
                  error.errno if isinstance(error, OSError) else None,
                  str(error)[:256])


def _linux(pid: int) -> tuple[dict[str, Any], list[Reason]]:
    values: dict[str, Any] = {}
    reasons: list[Reason] = []
    try:
        raw = _read(f"/proc/{pid}/stat")
        # comm is enclosed in parentheses but may itself contain spaces and ')'.
        left, right = raw.find(b"("), raw.rfind(b")")
        if left < 1 or right <= left or raw[:left].strip() != str(pid).encode("ascii"):
            raise ValueError("stat PID/comm boundary does not match original child")
        fields = raw[right + 1:].split()
        if not 22 <= len(fields) <= 128 or len(fields[0]) != 1:
            raise ValueError("stat field count/state invalid")
        # fields[0] is public field 3 (state), not field 1 (pid).
        user, system, started = (_number(fields[i]) for i in (11, 12, 19))
        ticks = os.sysconf("SC_CLK_TCK")
        if type(ticks) is not int or not 0 < ticks <= (1 << 31) - 1:
            raise ValueError("SC_CLK_TCK is not a positive bounded rate")
        values.update(cpu_user_ns=_scaled(user, 1_000_000_000, ticks),
                      cpu_system_ns=_scaled(system, 1_000_000_000, ticks),
                      process_start_marker=started,
                      process_start_marker_unit="linux-starttime-clock-ticks",
                      process_exited_observed=fields[0] in (b"Z", b"X", b"x"))
    except (OSError, ValueError) as error:
        reasons.append(_failure("linux-stat", error))
    try:
        raw = _read(f"/proc/{pid}/status")
        selected: dict[bytes, bytes] = {}
        for line in raw.splitlines():
            key, colon, value = line.partition(b":")
            if colon and key in (b"Pid", b"VmRSS", b"VmHWM"):
                if key in selected:
                    raise ValueError("duplicate selected status field")
                selected[key] = value.strip()
        if _number(selected.get(b"Pid", b"")) != pid:
            raise ValueError("status PID does not match original child")
        for key, metric in ((b"VmRSS", "rss_current_bytes"),
                            (b"VmHWM", "rss_peak_bytes")):
            if key not in selected:
                reasons.append(Reason(metric, "kernel-field-unavailable"))
                continue
            parts = selected[key].split()
            if len(parts) != 2 or parts[1] != b"kB":
                raise ValueError("status memory field has unexpected unit")
            values[metric] = _scaled(_number(parts[0]), 1024, 1)
    except (OSError, ValueError) as error:
        reasons.append(_failure("linux-status", error))
    reasons.extend((Reason("rss", "kernel-asynchronous-accounting",
                           detail="VmRSS/VmHWM are kernel-reported approximate values; VmHWM covers process history, not this benchmark interval."),
                    Reason("physical_footprint_current_bytes", "not-provided-by-selected-linux-api")))
    return values, reasons


def _darwin(pid: int) -> tuple[dict[str, Any], list[Reason]]:
    # All native binding and construction occurs after sample's original-owner
    # gate. These are fixed standard system libraries, never a searched plugin.
    import ctypes

    class RUsageInfoV0(ctypes.Structure):
        _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
            (field, ctypes.c_uint64) for field in (
                "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups",
                "ri_interrupt_wkups", "ri_pageins", "ri_wired_size",
                "ri_resident_size", "ri_phys_footprint",
                "ri_proc_start_abstime", "ri_proc_exit_abstime")]

    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

    values: dict[str, Any] = {}
    reasons = [Reason("rss_peak_bytes", "not-provided-by-rusage-info-v0",
                      detail="Physical-footprint high water is not peak RSS and is not substituted.")]
    try:
        if ctypes.sizeof(RUsageInfoV0) != 96 or ctypes.sizeof(Timebase) != 8:
            raise ValueError("selected public ABI size mismatch")
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        usage_fn = libproc.proc_pid_rusage
        usage_fn.argtypes = [ctypes.c_int, ctypes.c_int,
                             ctypes.POINTER(ctypes.c_void_p)]
        usage_fn.restype = ctypes.c_int
        usage = RUsageInfoV0()
        ctypes.set_errno(0)
        # Public typedef rusage_info_t is void*: this is the documented
        # (rusage_info_t *)&usage call shape, not a separately allocated void*.
        result = usage_fn(pid, 0, ctypes.cast(ctypes.byref(usage),
                                             ctypes.POINTER(ctypes.c_void_p)))
        error_number = ctypes.get_errno()
        if result != 0:
            reasons.append(Reason("darwin-rusage", "proc-pid-rusage-failed",
                                  error_number, "No replacement process or weaker source was sampled."))
            return values, reasons
        values.update(rss_current_bytes=int(usage.ri_resident_size),
                      physical_footprint_current_bytes=int(usage.ri_phys_footprint),
                      process_start_marker=int(usage.ri_proc_start_abstime),
                      process_start_marker_unit="darwin-mach-absolute-time",
                      process_exited_observed=usage.ri_proc_exit_abstime != 0)
        try:
            system = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            timebase_fn = system.mach_timebase_info
            timebase_fn.argtypes = [ctypes.POINTER(Timebase)]
            timebase_fn.restype = ctypes.c_int
            scale = Timebase()
            result = timebase_fn(ctypes.byref(scale))
            if result != 0:
                reasons.append(Reason("darwin-cpu", "mach-timebase-failed",
                                      detail=f"kern_return_t={result}"))
            elif scale.numer == 0 or scale.denom == 0:
                reasons.append(Reason("darwin-cpu", "invalid-mach-timebase"))
            else:
                # XNU fills these from recount/task_power Mach-time counters;
                # unlike commonly 1:1 Intel, Apple Silicon need not use ns.
                values["cpu_user_ns"] = _scaled(int(usage.ri_user_time),
                                                int(scale.numer), int(scale.denom))
                values["cpu_system_ns"] = _scaled(int(usage.ri_system_time),
                                                  int(scale.numer), int(scale.denom))
        except (OSError, AttributeError, ValueError) as error:
            reasons.append(Reason("darwin-cpu", "binding-or-value-unavailable",
                                  getattr(error, "errno", None), str(error)[:256]))
    except (OSError, AttributeError, ValueError) as error:
        reasons.append(Reason("darwin-rusage", "binding-or-value-unavailable",
                              getattr(error, "errno", None), str(error)[:256]))
    return values, reasons


def sample(process: subprocess.Popen[bytes]) -> Sample:
    """Observe only this original unreaped child, never consuming its wait.

    Caller first applies its real controller authorization/deadline/cancel gate
    and guarantees no concurrent reap or mutation during this synchronous call.
    SamplingRefused is a local precondition failure; OS/provider unavailability
    instead returns typed reasons and None fields. Zero is retained only when
    the selected OS field actually reported zero. No automatic retry is made.
    """
    pid = _owned(process)
    started = time.monotonic_ns()
    _owned(process, pid)
    if sys.platform == "linux":
        source = "linux-proc-stat-status-v1"
        values, reasons = _linux(pid)
    elif sys.platform == "darwin":
        source = "darwin-rusage-info-v0-mach-time-v1"
        values, reasons = _darwin(pid)
    else:
        source = "unsupported-platform"
        values, reasons = {}, [Reason("platform", "unsupported-platform")]
    _owned(process, pid)
    completed = time.monotonic_ns()
    for field in _METRICS:
        if field not in values and not any(r.scope == field for r in reasons):
            reasons.append(Reason(field, "selected-observation-unavailable"))
    core = ("cpu_user_ns", "cpu_system_ns", "rss_current_bytes")
    present = sum(values.get(field) is not None for field in core)
    status = "ok" if present == len(core) else "partial" if present else "unavailable"
    return Sample(pid=pid, platform=sys.platform, source=source,
                  observed_monotonic_ns=started, completed_monotonic_ns=completed,
                  cpu_user_ns=values.get("cpu_user_ns"),
                  cpu_system_ns=values.get("cpu_system_ns"),
                  rss_current_bytes=values.get("rss_current_bytes"),
                  rss_peak_bytes=values.get("rss_peak_bytes"),
                  physical_footprint_current_bytes=values.get("physical_footprint_current_bytes"),
                  process_start_marker=values.get("process_start_marker"),
                  process_start_marker_unit=values.get("process_start_marker_unit"),
                  process_exited_observed=values.get("process_exited_observed"),
                  status=status, reasons=tuple(reasons))
