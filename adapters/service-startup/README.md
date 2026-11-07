# Generic service startup primitives

This std-only workspace adapter implements early inherited FD capture,
CLOSE_LSOCKS ownership, daemon-status writer and process-local USERNAME primitives. Pinned upstream revision, source behavior, pending full startup work and unsafe
preconditions are in `DESIGN.md`, `API.rs.txt`, `inventory.json`, and `FINDINGS.md`. Production unsafe boundaries transfer exclusive early-child fd ownership,
consume early-child environment hints, inspect integer F_GETFD, call the Darwin
initgroups ABI omitted by nix, and implement the explicitly separated fresh-child
fork/setsid/stdio boundary described below. Protocol/crypto cores remain unchanged.

`capture_from_environment` replaces, rather than follows, the existing activation
capture at the very beginning of a new exec. The service's option selects either
listener adoption or close-after-configured-bind ownership. The control
stream is captured in that same call to detect identical raw-fd aliases before
ownership. On an error after adoption startup must exit without retry or logging
through a declared foreign stdio descriptor. Before any runtime/thread is created,
apply the configured user only after privileged listener preparation; any partial
switch failure must exit. A successful fallback is not a supplementary-group guarantee.

General async service/library embedding never forks or changes process identity. Only the explicit unsafe fresh-process `daemon::split` can fork; only the explicit
process-startup privilege API can change the invoking service child's identity. No private wire/config key is introduced. CORE/NSE standard entries compose
SERVICE options/logging, parent control, prepared listeners, selected user,
once-only daemon status and their host readiness. Other service entries
and complete platform/runtime acceptance retain their own implementation scope;
these two integrations do not declare whole-project startup completion.

Run pure checks with Cargo 1.99.1 in this directory and an explicit external target:

```
cargo +1.99.1 test --offline --target-dir /your/output/cargo-target
cargo +1.99.1 clippy --offline --all-targets --target-dir /your/output/cargo-target -- -D warnings
```

Fresh native verification needs an existing unchanged normal GNUnet Darwin util
build receipt whose `build`, runtime library environment and compile commands are
available, plus the matching official source checkout. Outputs must be new and
outside the source/candidate trees:

```
python3 -B tools/verify.py --package /path/to/adapters/service-startup \
  --source /path/to/gnunet --build-receipt /path/to/build-result.json \
  --output /path/to/new-proof
```

The test runner creates only its own child-process descriptors/private sockets;
credential probes apply only the current UID/GID in a newly exec'd child. The full
original C function extraction has a separately declared account-name fixture
port. Exact normal configuration refusal remains an independently paired check. Existing normal C libraries are never rebuilt or edited. Test receipts bind named
Rust execution, source/helper hashes, process observations and binaries.

`daemon::split` is an explicitly unsafe fresh-single-threaded-exec boundary,
never an async embedding convenience. After early descriptor capture and flushed
option/logfile setup, but before account lookup, runtime, threads, children or
listener path guards, it performs one fork and child setsid. The child
redirects only stdin/stdout to /dev/null, retaining its captured listener/control
and selected log descriptors. Newly opened helper/status FDs are lifted above
stdio before replacement, with close-on-exec status ends. No inherited FD number
is reopened or searched for later. The original parent drops its captured copies
and blocks only on the one original status-pipe byte; it does not wait for the
live daemon to exit. When that parent exits, the kernel reparents the child;
its new parent owns later reaping. No child-exit/reaping receipt is invented. There is no double-fork intermediate process.

`ChildReady::ready` is called by the CORE/NSE Host-ready callback. It sends
`ReadyStatus` byte '.' once; later identity-ready callbacks are no-ops. Errors
before ready report 'I', normal stop before ready reports 'S', and EOF/read errors
are always startup failure. Abandon/drop never reports ready. Explicit `finish`
keeps the original service error and any independent status-write failure. A
post-ready failure cannot retract the initial readiness fact. The blocking
OS pipe wait is not represented as cancelable by a socket/native deadline.

CORE/NSE standard binaries actually consume this boundary. Their selected Logger
refreshes the child PID and drops inherited callsite/bulk metadata, retaining
its already owned file. Filename PID expansion remains bound to that original
selection until another explicit setup; daemonization itself does not reopen it. The same child clock owner is preserved. No new wire/config option or
external dependency is introduced.
