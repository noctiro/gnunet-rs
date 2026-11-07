#!/usr/bin/env python3
"""Run local Python tool controls; no external C checkout or services required."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ROOTS = ("tools", "apps", "adapters", "crates", "tests")
EXCLUDED = {"target", ".git", "__pycache__"}
SELF_TESTS = (
    "tools/api_inventory/check.py",
    "tools/interop/run_reference.py",
    "tools/reference/hello_owner.py",
)


def scripts(root):
    """Find maintained Python sources without traversing build output or links."""
    for directory in ROOTS:
        for base, directories, files in os.walk(root / directory, followlinks=False):
            directories[:] = sorted(
                name for name in directories
                if name not in EXCLUDED and not (Path(base) / name).is_symlink()
            )
            for name in sorted(files):
                if name.endswith(".py"):
                    path = Path(base) / name
                    if path.is_symlink():
                        raise ValueError(f"Python source must not be a symlink: {path}")
                    yield path


def discover(root):
    """Discover conventional test scripts and explicit self-test entry points."""
    suites = []
    for path in scripts(root):
        name = path.name
        if name.startswith("test_") or name.endswith("_tests.py") or name in {"tests.py", "selftest.py"}:
            suites.append((path.relative_to(root).as_posix(),))
    for path in SELF_TESTS:
        if (root / path).is_symlink() or not (root / path).is_file():
            raise ValueError(f"required self-test entry point missing: {path}")
        suites.append((path, "--self-test"))
    return sorted(suites)


def check_syntax(root):
    """Compile without importing tools, starting services or creating bytecode."""
    failures = []
    count = 0
    for path in scripts(root):
        count += 1
        try:
            compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
        except SyntaxError as error:
            failures.append(f"{path.relative_to(root)}:{error.lineno}: {error.msg}")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"Python syntax: {count - len(failures)}/{count} passed", flush=True)
    return 1 if failures else 0


def stop(process):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def run(suites, root, timeout, output=None):
    failures = []
    results = []
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
    for index, suite in enumerate(suites):
        started = time.monotonic()
        reason = None
        log_path = output / f"{index:02d}-{Path(suite[0]).stem}.log" if output else None
        # Separate interpreters keep packages' identically named helper modules
        # isolated. Logs use files so verbose suites cannot fill the runner's RAM.
        with (log_path.open("w+b") if log_path else tempfile.TemporaryFile()) as log, subprocess.Popen(
            [sys.executable, "-B", *suite], cwd=root,
            start_new_session=os.name == "posix",
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONOPTIMIZE": ""},
            stdout=log, stderr=subprocess.STDOUT,
        ) as process:
            try:
                status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop(process)
                status = process.returncode
                reason = f"timeout after {timeout:g}s"
            except BaseException:
                stop(process)
                raise
            if status and reason is None:
                reason = f"exit {status}"
            if reason:
                failures.append((suite[0], reason))
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 8192))
                print(log.read().decode("utf-8", errors="replace"), file=sys.stderr)
        result = {
            "argv": list(suite), "exit_code": status, "failure": reason,
            "seconds": round(time.monotonic() - started, 3),
            "log": log_path.name if log_path else None,
        }
        results.append(result)
        print(f"{'FAIL' if reason else 'PASS'} {' '.join(suite)} ({result['seconds']:.2f}s)", flush=True)
    print(f"\nTool suites: {len(suites) - len(failures)}/{len(suites)} passed", flush=True)
    for path, reason in failures:
        print(f"FAILED {path}: {reason}", file=sys.stderr)
    if output is not None:
        (output / "result.json").write_text(json.dumps({"suites": results}, indent=2) + "\n")
        print(f"Tool logs: {output}", flush=True)
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list suites without running them")
    parser.add_argument("--timeout", type=float, default=120, help="seconds per suite (default: 120)")
    args = parser.parse_args()
    if not 0 < args.timeout < float("inf"):
        parser.error("timeout must be finite and positive")
    suites = discover(ROOT)
    if args.list:
        for suite in suites:
            print(" ".join(suite))
        return 0
    syntax_status = check_syntax(ROOT)
    output = ROOT / "target/tool-controls" / f"{time.time_ns()}-{os.getpid()}"
    return run(suites, ROOT, args.timeout, output) or syntax_status


if __name__ == "__main__":
    raise SystemExit(main())
