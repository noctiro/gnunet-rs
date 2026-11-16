# ARM reactor ownership

The reactor connects `gnunet-arm-service-core` to actual control streams, managed
listeners, native child processes and absolute restart targets. Protocol messages
follow the [central contract](../../spec/gnunet/README.md). The
[package interface](README.md) describes configuration and platform entry points.

## Source layers

`reactor.rs` defines the public borrowed driver, retained state and finite limits.
`reactor/children.rs` settles process effects and consuming exits;
`reactor/clients.rs` owns accepted connections and frame handoff;
`reactor/timers.rs` retains restart targets; `reactor/drive.rs` orders work.

The [process port](src/process.rs) uses the shared runtime's original-child
registry. Unix policy selects the configured executable and exec helper. Windows
policy separates [image selection](../service-runtime/src/process/executable.rs),
[creation](src/process/windows.rs) and [control state](src/process/windows/control.rs).
Neither backend reconstructs process authority from a numeric PID.

## External owners and cancellation

The caller owns registry/spec views, core scope and slots, frame storage, managed
listeners, native child registry, `State`, LIST scratch and `LaunchContext`.
`Driver` borrows these owners. Dropping a drive future or its complete driver
borrow preserves native processes, bootstrap/control state, partial frames,
leased effects, pending exits and restart timers.

Owner identity and the immutable service registry are checked when reborrowing.
A foreign live child is refused before consuming a wait. An unexpected completed
receipt is returned through `Error::ForeignCompletion`; it is never acknowledged
as a configured service's successful reap. Final callers explicitly drain the
original native registry. Dropping local I/O does not prove child death.

## Admission, startup and stopping

Native creation is distinct from executable initialization and service readiness.
Every admitted child is mapped before a fallible clock/core acknowledgment.
Windows post-admission preparation failures retain the original child and provider
failure until consuming retirement; cleanup requests termination through its
original handle. A no-child refusal never reports admission.

Windows bootstrap qualification and actual startup bytes are ordinary rotating
sources. Only a qualified `.` increments `startup_ready`; formal STARTED remains
a native-admission observation. Failure bytes, EOF and process exit cannot create
a readiness receipt. Original sources remain alive through listener import.

A stop effect retains its original ticket until the native attempt settles.
Unix follows the shared pipe-then-signal route. Windows uses the qualified control
outbox when selected. An admitted byte and pending write survive cancellation;
resumption does not enqueue it again. A read-only original-process wait wakes a
pending write if the child exits. Missing or failed cooperative control falls
back to original-handle termination. Control/wait and fallback errors remain
separate diagnostics. Neither write submission nor accepted termination is a
consuming exit receipt.

Forced cleanup bypasses cooperative control: SIGKILL on Unix and TerminateProcess
on Windows. Windows exits retain their native unsigned code and are never
reported as POSIX signal deaths. Resource events carry consuming wait4 data on Unix and independent native
counter/query-error observations on Windows. Callers take an event before another
resource receipt is consumed.

## Listener and stream leases

Managed readiness observes the original listener without accepting or reading
its queued streams. Each readiness lease is delivered once to the core and is
parked while its child runs. The child receives the original endpoint and backlog;
recipient registration grants no creator-path cleanup authority. Windows transfer
uses the [native provider contract](../native-std/SOCKET-ACTIVATION.md). It
publishes private source descriptors retained in the child's control owner until
qualified readiness or consuming retirement. Closing the managed listener does
not discard a publisher still required by a starting child. Terminal SERVICE
failure transfers these owners into `Recovery` with the original registry.

Accepted control streams are separate owners. Partial RX/TX cursors and FIFO
admission survive cancellation. Active and persisted sockets share one physical
capacity bound. An ARM self-stop requester can retire logically while its original
socket remains in external `State`; EOF follows physical owner retirement.

## Scheduling and bounded progress

Settlements finish leased effects before unrelated callbacks. Shutdown closes
managed listeners, settles the complete stop pass, consumes child exits, then
acknowledges generic runtime cleanup. Pending native writes keep this ordering
without spinning or running unrelated callbacks inside the effect.

Ordinary source, child-control, session and stream-direction cursors rotate after
actual work. Removing an entry adjusts its cursor. A pending poll alone is not
progress. Bounded settlements yield with a registered source wake or an explicit
cooperative wake. IDLE restart callbacks follow ordinary ready work; UTC changes
preserve the original absolute restart target until actual core settlement.
