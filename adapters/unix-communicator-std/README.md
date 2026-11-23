# Actual UNIX testing communicator runtime

`Runtime::bind(&Instance, &mut pils::client::Instance, Sources, path, Limits)` composes the standard TRANSPORT communicator MQ, public PILS observer and original `native::OwnedDatagram`. `poll`/`drive` retain all connection/framing/datagram cursors across canceled futures. Caller supplies the process Resolver/clock through Sources, which are snapshotted together before admission. No task, hidden Resolver, private-key file, TCP/UDP session, hash/entropy provider or production C FFI is created by this layer. The PILS client actually validates the current public HELLO under its explicit profile; normal official metadata coverage does not authenticate addresses. The UNIX datagram's claimed sender is completely unauthenticated.

## Embedded foreground

`embedded::serve` runs one communicator on the application's Tokio reactor.
With `embedded-config`, `Configured::read` and `serve_configured` use the
standard UNIX section and resource bounds. The caller supplies original
TRANSPORT and PILS selectors with the same clock. Configure this testing
communicator only for a local deployment. Readiness follows whole TRANSPORT
registration and address writes under the verified local PILS identity.
Complete the stop future and await physical retirement.

## Wire format and platform constraints

Outgoing packets carry a four-byte header with type zero, a 32-byte PILS peer
and one frame. The receiver ignores the type and trailing bytes as C does and
rejects kernel truncation. The inner MTU defaults to 65,447 bytes on Linux,
Android, OpenHarmony standard and FreeBSD, and 2,012 on macOS and iOS.
Native `EMSGSIZE` remains a send error. Linux, Android and OpenHarmony standard
support filesystem endpoints and 107-byte zero-padded abstract names. Darwin
and FreeBSD use filesystem endpoints. The socket API retains native path bytes.
Application deployments place filesystem endpoints in accessible private storage.

## Queue and callback ownership

Each live native-address/claimed-peer queue has one original SEND slot and one service credit. Whole `sendto` produces success status 1. A permanent negative result produces −1, and a SEND racing an expired queue receives official NO (0) without a network write. The result ACK precedes its replenished-credit frame in the same MQ FIFO. The local gate opens when that credit frame is wholly written. EAGAIN, ENOBUFS and EINTR schedule a retry for the original destination and packet, at most once per fair turn. The delay starts at the configured `ENOBUFS_RETRY` and doubles up to 64 ms or the configured delay if larger. Every retry retains the original deadline. Positive short datagrams close the original source, retain OutcomeUnknown and never resend a suffix. The service's opaque message id is never regenerated.

Incoming frames get original flow ids and bounded callback rows. Whole original INCOMING IPC write is recorded separately from the matching service callback. Incoming peer is the claim and neighbour is the official zero-filled field. Native reads stop at callback capacity while existing TX/callback RX drains. One held native input and one held complete/partial MQ input retain their original source and hard target. Queue metadata is bounded, queue ids are never reused in this MQ, and duplicate CREATE does not renew idle time. Fair turn rotation covers PILS, connect, native send/receive and MQ read/write. The earliest retry, idle or operation deadline determines the next timer wake.

## Deadlines and public identity

All original source/startup, send, first-input, output and callback targets have logical plus immutable native bounds. Native expiry/alarm registration precedes clock sampling, including a revision race. Initial startup is enforced only until the first whole registration/address READY; a later TRANSPORT replacement does not revive or reapply that original startup deadline. The original daemon lifetime, queue idle and admitted operation targets never reset; public identity validity follows actual verified announcements.

The scheduler samples canonical time after TRANSPORT clock providers and checks
the original targets between I/O classes. A retained CLIENT connect gate repeats
the check after configuration, timers and resolution. Slow or failing providers
cannot authorize a late replacement socket or queued output prefix.

A verified PILS PID change keeps the same TRANSPORT MQ, bound socket,
queue IDs and incoming callback ownership. Registration/address messages and
flow-control callbacks do not carry a local PID. Every SEND captures its sender
in an immutable datagram when admitted: old packets keep the original sender,
bytes, deadlines and result-ACK exposure, while later SENDs capture the new PID. No payload is rewritten, replayed or requeued. Same-PID metadata observations
also preserve these owners.

PILS EOF or a connection I/O loss pauses business I/O while retaining the
original TRANSPORT MQ, Unix datagram socket, queues, immutable packets,
partial output cursors and callback debts. `peer()` returns None and `ready()`
is false while paused. Only the same native PILS client's signed, unexpired
observation on a strictly newer epoch with a newer revision resumes work.
An attached unsigned socket grants no authority. Repeated losses keep the
first source cause and native/canonical 30-second recovery bound, shortened
by the original startup or process bound. Admitted operation expiry still
closes the runtime; recovery cannot extend old work.

PILS driver guards recheck the earliest original work bound after clock
providers and before native connect/read/write. On successful source recovery,
old packets and ACK prefixes continue on their original socket/MQ. The runtime
neither resends REGISTER/address frames nor retags old callbacks into another
source. Later SENDs capture the new verified PID. Failed recovery reports its
first connection cause together with the independent terminal error and
physical cleanup result. Protocol, resource, clock and native socket errors
remain fatal.

## TRANSPORT replacement

TRANSPORT EOF or a classified native stream disconnection physically detaches only that MQ. Its input prefix/held head, immutable output prefixes, flow callbacks and original SEND outcomes retire with their original epoch/queue/message ids. An atomic nonblocking datagram send has no in-flight syscall after Pending: an unsubmitted old intent is cancelled, while an already observed Whole/Failed/Unknown result keeps that original fact. No old payload, result ACK, callback or held native packet is submitted on the replacement. The same bound Unix socket/path and SocketEpoch, queue address/peer/idle owners, PILS observer, source clock and process lifetime remain. Clock/Resolver port refusal, InvalidData/typed protocol errors, capacity failure and native socket loss remain fatal; they are not disguised as recoverable stream disconnects.

The retained Channel owns bounded reconnect backoff. A fresh attachment gets a fresh epoch, REGISTER and the same original unlimited native address claim with a fresh local address id. After whole REGISTER, live queues are reannounced one at a time with fresh ids and one-slot availability. Old unannounced expired rows drop locally; an already queued current SETUP wholly settles before DOWN. Queue credit and payload submission require the exact current SETUP whole-write. A held new native input waits under its original bound for that queue's publication. Restoration, stream read/write and native IO interleave fairly, so a full output budget cannot freeze required SEND/FC input. Restored reports the completed publication FIFO prefix, including SETUP/DOWN created during recovery; continuing unrelated traffic need not empty the FIFO.

## Native send failure and final cleanup

A permanent native send failure queues the original negative SEND result
followed by DOWN, rather than returning credit to a queue the service has
discarded. The send and its partial/whole result exposure remain owned
until DOWN finishes. A duplicate CREATE or matching native input waits under its
original bound for retirement; a stale SEND receives the ordinary unknown-queue
result. The next attempt gets a fresh QID and never replays the failed packet. MQ loss during this retirement also removes the failed queue, while preserving
the original send outcome and result exposure in SendRetired. Permanent send
errors and queue expiry reach normal program diagnostics. Transient send failures
contribute to the native failure counter.

Final close still physically stops all owners before retiring metadata. Actual fd/path cleanup errors are independent of the first cause; path cleanup checks the original observed dev/inode and leaves replacements alone. Shared Channel/PILS expose no separate close errno, so no fabricated errno receipt is claimed. Explicit cancellation calls close; there is no private CANCEL. The caller-owned Cell allocation domain permits bounded slot reuse without a hidden global/Atomic64 dependency.

## Program and configuration

The [normal program](../../apps/gnunet-communicator-unix/) supplies PROGRAM,
configuration, parent control and diagnostics. `Limits` selects finite resource
and operation bounds; `Limits.profile` selects the PILS interpretation independently
of the Unix packet format. Both endpoint selectors must use the same caller-owned
clock and Resolver context. Native AF_UNIX datagrams are required; this host is
built on Unix targets. Remaining platform and official-peer qualification is
tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).
