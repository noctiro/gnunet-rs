"""Require an aggregate resource budget before starting a peer topology."""

import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


MAX_CPU_CORES = 2
MAX_MEMORY = 2 << 30
MAX_TASKS = 128
MAX_RUNTIME_US = 260_000_000
MAX_STOP_US = 8_000_000
UNIT_PREFIX = "gnunet-reference-"


class MissingPeerBudget(RuntimeError):
    """No effective resource boundary for a multi-node reference run."""


def peer_unit(membership):
    for line in membership.splitlines():
        if not line.startswith("0::"):
            continue
        path = PurePosixPath(line[3:])
        if (path.is_absolute() and ".." not in path.parts and
                re.fullmatch(rf"{UNIT_PREFIX}[a-zA-Z0-9-]+\.service", path.name)):
            return path.relative_to("/")
    raise MissingPeerBudget("run in a dedicated gnunet-reference-*.service cgroup")


def require_peer_budget(proc=Path("/proc/self/cgroup"), root=Path("/sys/fs/cgroup")):
    """Check the kernel's limits on the service cgroup inherited by its children."""
    if sys.platform != "linux":
        raise MissingPeerBudget("run this peer topology in a disposable Linux guest")
    try:
        group = root / peer_unit(proc.read_text(encoding="ascii"))
        quota, period = (int(value) for value in (group / "cpu.max").read_text().split())
        memory = int((group / "memory.max").read_text())
        swap = int((group / "memory.swap.max").read_text())
        tasks = int((group / "pids.max").read_text())
    except (OSError, ValueError) as error:
        raise MissingPeerBudget("peer cgroup limits are unavailable or unlimited") from error
    if not (period > 0 and 0 < quota <= MAX_CPU_CORES * period):
        raise MissingPeerBudget("peer cgroup must limit CPU to at most two cores")
    if not (0 < memory <= MAX_MEMORY and swap == 0):
        raise MissingPeerBudget("peer cgroup must limit memory to 2 GiB with no swap")
    if not 0 < tasks <= MAX_TASKS:
        raise MissingPeerBudget("peer cgroup must limit the topology to at most 128 tasks")
    require_service_policy(group.name)


def require_service_policy(unit):
    # systemd's D-Bus object path escapes each nonalphanumeric byte as _xx.
    label = re.sub(r"[^a-zA-Z0-9]", lambda m: f"_{ord(m[0]):02x}", unit)
    hooks = ("ExecStartPost", "ExecStop", "ExecStopPost")
    properties = (
        "RuntimeMaxUSec", "TimeoutStopUSec", "MainPID", "RuntimeRandomizedExtraUSec",
        "Restart", "TimeoutStopFailureMode", "ExitType", "KillMode", "SendSIGKILL",
        "Type", "RemainAfterExit", *hooks,
    )
    try:
        reply = subprocess.check_output(
            [
                "busctl", "--user", "get-property", "org.freedesktop.systemd1",
                f"/org/freedesktop/systemd1/unit/{label}",
                "org.freedesktop.systemd1.Service", *properties,
            ],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        ).splitlines()
        if len(reply) != len(properties):
            raise ValueError("incomplete service policy")
        values = dict(zip(properties, reply))
        lifetime = int(values["RuntimeMaxUSec"].removeprefix("t "))
        grace = int(values["TimeoutStopUSec"].removeprefix("t "))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise MissingPeerBudget("cannot verify the transient service lifetime and cleanup") from error
    if values["MainPID"] != f"u {os.getpid()}":
        raise MissingPeerBudget("launch the topology controller directly as the service's main process")
    required = {
        "RuntimeRandomizedExtraUSec": "t 0",
        "Restart": 's "no"',
        "TimeoutStopFailureMode": 's "terminate"',
        "ExitType": 's "main"',
        "KillMode": 's "control-group"',
        "SendSIGKILL": "b true",
        "Type": 's "exec"',
        "RemainAfterExit": "b false",
    }
    if (not 0 < lifetime <= MAX_RUNTIME_US or not 0 < grace <= MAX_STOP_US
            or any(values[key] != value for key, value in required.items())
            or any(not re.fullmatch(r"a\([a-z]+\) 0", values[key]) for key in hooks)):
        raise MissingPeerBudget("the service must bound its lifetime and stop the entire cgroup")
