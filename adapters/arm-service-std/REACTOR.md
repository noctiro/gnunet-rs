# Actual ARM daemon reactor development

This workspace reactor reuses the single `gnunet-service-runtime::process` backend and the one published `gnunet-arm-spawn-helper`. Its native implementation and readiness owner are not copied into the service host. The complete121-obligation/22-source projection remains explicit, and component integration promotes no whole ARM or GNUnet owner.

The caller owns immutable Registry, its borrowed ServiceSpec vector, OwnerScope, service/client/listener metadata, frame bytes/slots, LIST scratch, formal Owner and external ChildRegistry. A separate caller-owned ReactorState holds stream/TX/RX owners, pending native/timer leases, OriginalChild mappings and pending consuming wait observations. Driver borrows these owners; no unsafe self-reference is constructed. Canceling drive or dropping a Driver borrow cannot drop that state or its original native authority. Final source lifecycle remains explicit: retain/drain the external child registry even if a view is dropped.

Startup binds the ARM IPC listener separately from managed readiness-only listeners, attaches only successfully bound managed listeners, prepares child observation, applies pending listener operations and starts each forced entry through process admission before enabling service client admission. Generic early CLOSE_LSOCKS owns ARM-self's incoming WRITE pipe and closes it only after configured bind/startup stage. It never tries to adopt that pipe as a listening socket or claims privilege/application readiness from binding alone. Initial generic startup and final shutdown are typed explicit ports until their full app frontend is wired; no success default is inserted.

Every take_native lease is retained in state before fallible preparation. The prepared recipe follows the GNUNET parser or SIMPLE filename/argv0/whole-options branch. Source listeners remain bound in parent and are merely disarmed before inherited mappings. An admitted OriginalChild/control capability is installed in the service+CoreChildId map before core.spawned acknowledgment, so a fallible acknowledgment cannot orphan it. Actual refusal with no PID maps to Failed; resource refusal stays an explicit error/retained lease. TERM validates both original mapping and native ticket, performs pipe/native policy and acknowledges only the attempt. Real wait/ECHILD observations remain retained across UTC/output admission failure; no planned task or lost numeric PID is interpreted as reap.

Unix/TCP client RX keeps exact partial header/body state across cancellation and validates the full official u16 size before core.receive. Valid unknown types follow core/MQ policy. LIST scratch is caller-owned and output snapshots are immutable. Borrowed core output is copied into a bounded persistent per-client TX owner before its ticket is released; partial writes retain offsets and FIFO. EOF and explicit resource-closure lanes run even when another TX is full, revoking the original client/monitor/requester generation. No optional notification <=1024 is silently declared an official drop because local storage is missing; any stricter capacity action is a visible host resource profile.

All ARM restart tasks are source IDLE priority, including delayed ones (gnunet-service-arm.c1634/1843). An expired timer is dispatched only after the current poll has no ready ordinary client/native work, preserving that source ordering. A timer effect owns one exact registration until fired/canceled. Finite UTC absolute targets are converted to wake hints and UTC is rechecked on callback; FOREVER is an retained never-ready registration with cancellation identity. Expired/backward clocks cannot create a new deadline. Driver cancellation retains pin/sleep state and lease. On self-stop, source status/result queueing is followed by the generic shutdown task; it does not force STOPPING to physically flush or fabricate a client Stopped result before EOF. Shutdown cancels timer, applies all parent listener closes, then attempts every child TERM and consumes every reap before final generic runtime acknowledgment. Slow clients do not block these cleanup lanes.

tests will use only empty owned BASE/user-only config, explicit finite fixture BINARY and owned Unix/127.0.0.1 resources. Compare normal C public client→Rust daemon and Rust public client→normal C daemon separately; literal byte peers supplement rather than replace those. Unknown/malformed/fragmented traffic, queued multiple listeners, SIMPLE, control pipe/fallback, restarted native children, retained partial TX and canceled drive are independent witnesses. CLI/testing/global OS completion and Linux runtime execution remain explicitly pending until implemented and observed.

The complete generic startup/RESOURCE_DIAGNOSTICS/wait4 path remains a separate obligation: the initial frontend must prepare native child/shutdown observation before service enumeration. If resource diagnostics is selected, it requires open-w plus consuming usage data; an empty created file is not support. This first reactor increment does not certify that path.

service.c do_send semantics drive MQ counting: after a positive send or an EAGAIN/EINTR return at offset0, the first envelope is in-flight and MQ_get_length excludes it; zero/fatal errors retire the socket before in-flight. poll_write readiness alone is not this attempt. The transport retains an explicit first-attempt flag independently from its original byte offset.

## Source corrections found by integration

During TERM-child drain, ARM can still admit control requests. `shutdown_task`
closes managed service listeners; `do_shutdown` later closes the generic ARM
service. The host retains self-stop requester transport until external State
drop and tests the corresponding socket lifecycle.

Clock regression tests retain the original restart target while UTC moves backward.
The host settles initial, restart and TERM scans before child-death callbacks;
clock changes do not authorize an extra child or reset the original backoff.

## Ordinary progress and retained cursors

`service.c` queues a receive continuation per processed message; `scheduler.c`
appends ready work to its FIFO and processes the existing-priority pass before
new continuations. The initial integrated candidate always started at session0
and RX, which actually delayed a ready second client behind an earlier legal
backlog. Current State retains ordinary-source/session/direction cursors, rotates
after work, and preserves those cursors across Driver cancellation. The
existing all-close-before-TERM and uninterrupted initial/restart/shutdown scan
rules remain in effect. A request/demand native effect is settled before an
unrelated consuming reap callback. Busy without any new input bytes is not
reported as progress. Exact global callback ordering, cached-reactor refresh
under continuous external activity and the full SCHEDULER interface remain part
of the complete goal.

A persisted ARM self-stop requester can lose its logical MQ session during child
Drain (for example after an invalid registered message) without releasing its
physical descriptor. `State` retains that original socket until its external
process owner is dropped. This retirement neither resumes EMFILE acceptance nor
increments the actual-close counter. Active and persisted sockets share the
same finite physical admission bound. The real-child regression confirms
STOPPING, malformed-message retirement, no early EOF, two-slot capacity refusal,
final child reap and EOF only after external State Drop. This is a component
witness; it does not complete generic SERVICE or the ARM process frontend.
