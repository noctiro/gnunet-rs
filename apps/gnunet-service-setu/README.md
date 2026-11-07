# Rust SETU foreground

Run `gnunet-service-setu -c official.conf`. This binary composes the independent
Rust SETU core/native server and the existing Rust CADET CLIENT adapter. Its
production path does not launch a C daemon, subprocess, storage worker or detached
network task. Sets are bounded in-memory data, lost when their owning application
MQ or process is retired. All application operations use the official active
GNUnet v0.29.1 IPC and CADET union frames.

Startup uses the shared standard SERVICE `-c/-d/-h/-L/-l/-v` selection and
configuration loader, including its default-file and logging environment
policy. Early startup uniquely adopts original listeners and parent-control FDs. The daemon split happens while single-threaded, before account lookup, Tokio,
listener path guards or any SETU/CADET owner. The parent releases its FD
copies and waits on its original status pipe; the child refreshes the selected
Logger PID and never fabricates a successful daemon startup.

Original inherited/TCP listeners are prepared before configured `USERNAME` is
applied. Newly created Unix endpoints are finished under the target identity with
the configured UID/GID filesystem policy; existing parents/inodes are not
reassigned. Actual accepted Unix credentials are still checked by the existing
server. This preserves privileged prebinding without opening a duplicate listener.

The fixed official C SERVICE_MAIN uses the internal service name `set` with
OPTION_NONE, while its installed `setu.conf.in` exposes `[setu]` listeners and the
`gnunet-service-setu` binary. This entry retains that real `[setu]` endpoint,
username and IPC configuration. No protocol or endpoint alias is invented from
the internal C name.

`[setu]` uses the existing official listener and service options, including
`UNIXPATH`, `HOSTNAME`, `PORT`, `ACCEPT_FROM`, `ACCEPT_FROM6`, `UNIX_MATCH_UID`,
`UNIX_MATCH_GID` and `USERNAME`. `[cadet]` selects the single CADET MQ;
`[resolver]` selects the process-shared official Resolver MQ when endpoint
selection requires it. The frontend constructs one explicit Resolver context and
drives its unique owner alongside the SETU server. Each turn fairly polls the same Resolver and server, including continuously
ready service traffic. The permanent Reporter-failure latch gates each live class
even when a preceding diagnostic callback returned Pending. No host DNS
substitute or per-operation Resolver is constructed. One canonical source clock
is retained by that context, CADET client and SETU server.

## Rust resource policy

`[setu-rust]` has these numeric or byte-size keys:

| Keys | Meaning |
| --- | --- |
| `MAX_CLIENTS`, `MAX_OPERATIONS` | Application MQ and live operation metadata |
| `MAX_SET_ELEMENTS`, `MAX_SET_BYTES` | Per-set immutable element resources |
| `MAX_UNION_ELEMENTS`, `MAX_RECEIVED_BYTES`, `MAX_RECEIVED_RECORDS` | Per-operation content and input bounds |
| `MAX_IBF_BUCKETS`, `MAX_ROUNDS`, `MAX_RESULTS` | Reconciliation work/report bounds |
| `MAX_UNION_OUTPUT_FRAMES`, `MAX_UNION_OUTPUT_BYTES` | Per-operation retained protocol output |
| `MAX_CADET_PORTS`, `MAX_CADET_CHANNELS` | Slot vectors borrowed by the single CADET client |
| `FRAME_BYTES`, `IO_SLICE_BYTES` | Application framing and native syscall byte bounds |
| `MAX_CLIENT_OUTPUT_FRAMES`, `MAX_CLIENT_OUTPUT_BYTES` | Per-application immutable output budget |
| `CADET_FRAME_BYTES`, `CADET_IO_SLICE_BYTES`, `CADET_PAYLOAD_BYTES`, `CADET_SEND_CREDIT` | Explicit native CADET client resources |
| `RESOLVER_FRAME_BYTES`, `RESOLVER_IO_SLICE_BYTES`, `RESOLVER_OUTPUT_FRAMES` | Process Resolver framing/output resources |

The compiled process Resolver has 128 total request slots (including its reserved
internal lookup) and 256-byte forward-name storage. Port/channel capacities must
cover the admitted client/operation limits. Defaults come from the core/native
adapters rather than an alternate wire protocol.

`OPERATION_LIFETIME` defaults to 300 seconds, `RETIREMENT_GRACE` to 5 seconds and
`SHUTDOWN_GRACE` to 10 seconds. These use official duration parsing and must be
finite, nonzero and representable. Native and pure engines enforce the declared
resource capacities before admitting work; an exhausted local bound does not
become fabricated peer success.

`NATIVE_BYTE_ORDER` may be `little` or `big`; `NATIVE_ALIGN64` may be `4` or `8`. Both default to the target's native ABI. This profile selects the active C
protocol's native-order fields, element fingerprints and un-packed u64
layout. It is explicit configuration, never byte sniffing or protocol negotiation.

SIGINT, SIGTERM or the corresponding inherited parent-control signal initiates
the configured service shutdown. Soft mode stops admissions and uses one original
finite native grace for existing work. A second signal, Logger/provider failure
or the original grace forces the existing physical shutdown. The grace timer is
checked before canonical/provider polling and is never renewed by partial IO,
clock revision, retry or another turn. Original operation and retirement bounds
remain inside the unchanged Server.

After Server construction, every readiness, business, signal, clock, Resolver or
Logger failure runs that same Server's synchronous clock-free `shutdown` before
returning. This closes application/CADET MQs before retirement callbacks;
there is no disk worker or detached task to join. The same Resolver is actually
disconnected and physically dropped even when its disconnect reports an error. Original business/server-cleanup/Resolver/status-output/Logger causes remain
separate; early constructor errors also run the original Resolver's RAII cleanup. No queued frame, timeout or Drop is treated as a peer result or shutdown receipt.

`READY setu wire=0.29.1 listeners=bound sets=memory` is flushed after the actual
local listeners and Server exist, then the original daemon `ChildReady` is
notified once. It asserts no remote CADET attachment, peer identity, completed
union or application receipt. `STOPPED setu local=...` contains the local
post-close counters; independent errors and bounded original diagnostics use the
selected Logger. A failed selected Logger wakes the original task, fences further
live work, and does not authorize a new fd2 fallback or replacement source.
