# GNUnet ARM client host

This std adapter drives the existing borrowed official ARM client and monitor
cores through persistent Unix/TCP streams. It uses the public CLIENT
transport facade, preserves partial RX/TX and connection futures when a drive
future is canceled, and retires original callback authority without replaying
already queued wire requests. All eight public ARM operations have Rust
entry points; `inventory.json` records concrete branch witnesses and remaining
validation, rather than treating this as complete ARM daemon/CLI/testing support.

`ClientHost` owns its stream, RX/TX cursor and startup-signal read ends. `LocalLauncher` borrows a caller-owned `ChildRegistry`. Drop/cancel/disconnect of
the host closes its own I/O and read ends while leaving that same registry and
original PID wait authority with the caller. Callers must retain and drain the
registry, and consume `take_reaped()` observations to release bounded metadata
credits. No daemon is implicitly killed, no unbounded wait runs in Drop, and no
background reaper or production `waitpid(-1)` exists.

Local start is explicit asynchronous Rust decomposition: request admission
returns an ID, drive performs original pipe/config/command/spawn work, and
callbacks use the core's original readability/EOF/60-second semantics. Actual
helper creation is distinct from target exec success and service readiness. A
missing helper yields setup failure; a created helper whose target has a
missing interpreter exits 1 while the original public result remains Starting. The dedicated helper calls native execvp after restoring sampled SIGPIPE and
closed/CLOEXEC stdio, without libgnunet FFI or private network protocol.

All private spawn source and destination descriptors are distinct live owners
above fd 2. Per-call POSIX return codes are checked as 0 versus positive errno;
only initialized file actions are destroyed. Original stdio and parent process
environment/cwd/signal dispositions are not mutated by production launch. The
small unsafe boundaries are scoped and document native ownership/ABI premises. The helper entrypoint is unsafe because its early fresh-exec stdio ownership
contract cannot be established by a normal library call.

`API.md` describes the current interface. Tools use an
unchanged official v0.29.1 C source/build receipt and private peers/children. No
system accounts, host configuration files, system service or public network are
modified. These proofs are supporting client-host observations; global owner
and daemon/testing completion remain pending.

The low-stdio matrix explicitly records a defined official C defect: unsigned
`max_fd` combined with signed `target_fd=-1` wraps the source-relocation start to
0; subsequent stdio mapping can replace readiness with /dev/null. Rust retains a
nonblocking FIFO and restores inherited closed slots. The observed 62
matches and 18 differences in 80 profiles are distinct assertions. See the
source-bound final report for exact receipts and input versions.

Build/test through this workspace's pinned toolchain and lock. The standalone
verifier uses a fresh external target and at most 2 jobs:

```sh
python3 -B adapters/arm-std/tools/verify.py \
  --source /absolute/pinned-gnunet \
  --reference /absolute/normal-arm-build/build-result.json \
  --output /absolute/fresh-proof-output
```

The ignored test is a real 65-second owned-child lifecycle test, rather than an
accelerated clock. The caller supplies helper installation/discovery and
retains the registry after dropping the host. ECHILD immediately revokes a lost
numeric PID entry and returns the error, without inventing a reap result
or retrying that old PID. Full service/CLI/testing acceptance remains pending.

## Shared process and live configuration

The launcher delegates to the single std process owner documented in
[PROCESS.md](PROCESS.md). It retains independently bounded original-child
wait/control authority and supports a filename distinct from argv0. The shared
runtime owns readiness and native spawn; ARM contains no second implementation. `adapters/service-runtime/tools/process_verify.py` stages the complete workspace
source and runs the original client matrix, generic native process pairs, finite
source write seams and a deliberately broken descriptor-staging runtime control.

`connect_live` and `start_live` borrow a shared `LiveConfiguration`: new MQ creation
samples TCP settings, each new Unix attempt samples its current Unix path, and
local start samples configuration when the original effect begins. Replacing configuration leaves an active connection, retained attempt, queued
bytes and admitted child unchanged. The additional source-bound verifier is
`tools/live_verify.py`. The complete shared resolver broker and PROGRAM/daemon/
testing/native utility obligations remain pending.
