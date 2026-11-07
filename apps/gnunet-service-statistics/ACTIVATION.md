# Official inherited listeners and private Unix binding

The native application boundary follows GNUnet v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, primarily
`src/lib/util/service.c:setup_service`, `src/lib/util/os_process.c` and
`src/lib/util/network.c`. No libgnunet FFI or private activation envelope is used.
The pinned native dependencies are socket2 0.6.5 and libc 0.2.191; protocol, core,
crypto, storage and IPC crates retain their prohibition on unsafe code.

The launcher supplies `LISTEN_FDS` and numeric colon-separated `LISTEN_FDNAMES`.
The service does not check `LISTEN_PID`. The source launcher uses dup-assigned
numbers and writes those numbers into names; it does not promise consecutive fds
starting at 3. Systemd descriptive names or a descriptor-3 fallback would therefore
change the official protocol. Neither is introduced here.

Both variables must be present. The C outer predicate ignores nonnumeric, zero
and out-of-FD_SETSIZE advertised counts; Rust does the same without undefined
integer overflow. Defined C unsigned decimal syntax, including leading whitespace
and a sign, is preserved. As with `strtok`, empty colon components are skipped.
A complete positive declaration must identify a unique set of open descriptors
below FD_SETSIZE, with original FD_CLOEXEC clear. Rust additionally requires exact
count agreement, SOCK_STREAM, SO_ACCEPTCONN and AF_UNIX/AF_INET/AF_INET6.

C accepts a valid prefix if a later token fails, can wrap the same fd twice, and
`socket_box_native` only checks F_GETFD despite its socket-check documentation.
Rust rejects these malformed declarations before acquiring ownership. It never
silently discards valid trailing listeners or closes somebody else's fd while
validating an invalid type. Separate descriptor numbers referring to the same
underlying socket remain valid separate owned descriptors.

`unsafe capture()` is called once as the first host initialization operation:
no runtime, configuration/log file or other Rust fd owner may exist for a named
handle, and no thread may race close/reuse/exec or environment access. It first
validates the entire unique set using borrowed native descriptors, then creates
one OwnedFd for each descriptor >=3. Valid listeners occupying stdin/stdout/stderr
first move through F_DUPFD_CLOEXEC(minimum3) to fresh exclusive descriptors. Only
after reserving all moved copies does capture open /dev/null and synchronously
dup2 it into the original standard slots. This preserves queued socket connections
and leaves libstd diagnostics, help and NoDB warnings with usable standard streams.
The moved listeners, rather than the null standard slots, belong to Activation.
A process-local one-shot guard rejects repeat calls before reading environment or
touching any descriptor. On success, all listeners become nonblocking and
FD_CLOEXEC is set; LISTEN_FDS alone is removed. LISTEN_FDNAMES and LISTEN_PID remain
as in C. Dropping a returned listener closes its unique socket descriptor;
restored standard slots remain valid null devices for libstd until process exit.
Inherited Unix paths belong to their creator and must never be unlinked by this
capture module or by the host's newly-created-path cleanup.

If validation fails, no raw descriptor was consumed or closed. If a later OS flag
operation fails during adoption, already-owned handles close through Rust drop;
the early-main caller must treat the error as fatal, so the OS also closes any
unconsumed inherited descriptors on process exit. There is no successful partial
activation, duplicate ownership, descriptor leak claimed as successful adoption,
or reassignment to a fresh unrelated socket.

The narrowly scoped unsafe operations are:

* BorrowedFd validation and OwnedFd adoption, only after validation and under the
  documented exclusive early-process ownership contract;
* F_DUPFD_CLOEXEC for fresh low-stdio listener owners and synchronous dup2 of a
  live /dev/null file into the still-foreign original standard slots;
* integer-only fcntl F_GETFD/F_SETFD;
* getsockopt SO_ACCEPTCONN into a checked initialized c_int/socklen buffer on
  platforms exposing that query; macOS instead reads its own socket-info option
  bits through native libproc into a bounded initialized byte buffer;
* single-threaded removal of the consumed environment hint;
* a paired umask call and restoration in a synchronous guard.

macOS defines SO_ACCEPTCONN but querying it through getsockopt returns
ENOPROTOOPT. Its read-only `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` path checks the
returned byte count and reads only `soi_options` at the public SDK prefix offset.
The C ABI-only oracle compiles against sys/proc_info.h and checks the Rust offset
and full native socket-info size against its 4096-byte query capacity. It neither
calls listen (which could turn an invalid socket into a listener) nor accepts and
discards a queued connection. The real-process test queues a client before capture
to verify this boundary. TCP classification also requires a successful read-only
TCP_NODELAY query, excluding unrelated IP stream protocols.

All carry exact `#[expect(unsafe_code, reason=...)]` and safety comments. No crate
or workspace unsafe lint is globally relaxed. Safe socket2/std operations handle
socket type/address inspection, nonblocking mode and listener conversion.

`bind_unix_private(&Path)` temporarily sets umask077 while the Unix bind
creates the socket, matching GNUNET_NETWORK_socket_bind's atomic 0700 creation.
It restores the exact previous umask on success or failure, and its RAII drop also
runs on Rust unwinding. A private mutex serializes this module's binds. Because
umask is process-wide, the host must perform this synchronous startup section
without unrelated concurrent file creators or foreign umask users; the helper
contains no await or caller callback. Inherited sockets are not rebound/chmodded.

`examples/activation_probe.rs` is an isolated, single-threaded subprocess fixture;
its native setup only creates the deliberately invalid original-CLOEXEC test or
sets its own test umask. It validates original fd closure before any subsequent
operation can allocate replacement descriptor numbers. The Python oracle starts
parent-owned Unix, IPv4 and IPv6 listeners, passes arbitrary nonconsecutive
numbers through exec, exchanges data through every adopted listener, tests all
three low standard slots individually and together with prequeued connections,
original CLOEXEC rejection, one-shot capture, non-sockets, connected non-listening
streams, duplicates and malformed/range/count cases, and verifies 0700 creation
plus umask restoration on both bind success and bind failure.

It also launches the hash-checked unmodified C STATISTICS daemon on those inherited
listeners. That comparison sets the parent sockets nonblocking, as official
GNUNET_NETWORK initialization does before its launcher passes descriptors: the C
accept loop otherwise blocks while draining new connections. The earlier Rust
probe deliberately starts with ordinary blocking Python listeners and verifies
that capture normalizes them. The daemon comparison ignores a deliberately wrong LISTEN_PID, sends official GETs to
every endpoint, confirms inherited-only service operation and graceful shutdown,
and checks that parent-owned Unix paths remain. Supplying `--rust-service` runs
the same official IPC checks against the assembled Rust host, plus NoDB
startup/GET/graceful-exit through fd0, fd1 and fd2 and successful --help when stdout
was offered as a listener. The probe checks the moved socket fds really close and
the original standard slots remain the same null character device; it does not
claim that a stdio slot was closed after restoring it.

```sh
cargo build -p gnunet-service-statistics --example activation_probe --locked --offline
python3 apps/gnunet-service-statistics/tests/activation_process.py \
  --probe target/debug/examples/activation_probe \
  --reference /path/to/normal-C-build-result.json \
  --rust-service target/debug/gnunet-service-statistics \
  --output /path/to/new/proof-directory
```

The helper is a native ownership/OS-boundary test, not a substitute for the
STATISTICS client lifecycle, transport ACL or whole-GNUnet conformance evidence.

The process captures descriptors through `gnunet-service-runtime`. Its
shared listener and path guards replace the former application copies; the
reviewed native-body baseline lives in
`adapters/service-runtime/tools/migration-baseline.json`. The process
fixture still exercises this application’s early-main call and normal C daemon.

The application process fixture performs a fresh locked/offline Cargo build of
the service and example, and compares supplied executable hashes with
those artifacts before snapshotting. Its source binding includes main/host,
shared modules, both manifests and the workspace lock.

The standard SERVICE entry performs once-only capture through
`gnunet-service-startup::capture_from_environment(AdoptListeners)`, retaining
parent control separately. Shared daemon startup, target USER and selected
Logger run before the host publishes Ready. Deferred Unix creation uses
`finish_with_access`; owner-only `finish`/private binding remain available to
existing callers. The normal service applies independent kernel UID/GID checks.
The centrally compiled entry revision removes private file-control flags
from existing process fixtures. No process/activation test was executed for this
revision; the earlier recorded native evidence does not qualify new daemon or
privilege paths.
