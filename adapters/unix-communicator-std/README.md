# Actual UNIX testing communicator runtime

`Runtime::bind(&Instance, &mut pils::client::Instance, Sources, path, Limits)` composes the standard TRANSPORT communicator MQ, public PILS observer and original `native::OwnedDatagram`. `poll`/`drive` retain all connection/framing/datagram cursors across canceled futures. Caller supplies the process Resolver/clock through Sources, which are snapshotted together before admission. No task, hidden Resolver, private-key file, TCP/UDP session, hash/entropy provider or production C FFI is created by this layer. The PILS client actually validates the current public HELLO under its explicit profile; normal official metadata coverage does not authenticate addresses. The UNIX datagram's claimed sender is completely unauthenticated.

The source says ONLY INTENDED FOR TESTING and Meson installs it unconditionally. This is that testing communicator, with the standard IPC and packets. Canonical outgoing packet is header4(type0)+PILS peer32+one frame. Incoming accepts the C ignored type/trailing bytes, but rejects MSG_TRUNC/CTRUNC. Advertised/enforced complete-inner MTU is min(OS datagram cap−36,65535−36,65535−88); defaults65447 on Linux/FreeBSD and2012 on Darwin. Kernel buffer observations are not a delivery guarantee; EMSGSIZE stays an failed send. Linux abstract names retain the official full107-byte zero-padded namespace. Non-UTF8 path bytes remain literal in the native/pure/common IPC layer; an external service may impose its own address validation.

Each live native-address/claimed-peer queue has exactly one original SEND slot and one service credit. Whole `sendto` produces success status1; permanent negative result produces−1; a SEND already racing an expired queue gets official NO0 without a network write. After a result ACK is wholly written, its replenished-credit frame follows in the same MQ FIFO; the local gate opens at that credit whole-write. EAGAIN registers reactor readiness; ENOBUFS/interrupted retries use a finite timer and preserve the original packet/deadline. Positive short datagrams close the original source, retain OutcomeUnknown and never resend a suffix. The service's opaque message id is never regenerated.

Incoming frames get original flow ids and bounded callback rows. Whole original INCOMING IPC write is recorded separately from the matching service callback. Incoming peer is the claim and neighbour is the official zero-filled field. Native reads stop at callback capacity while existing TX/callback RX drains. One held native input and one held complete/partial MQ input retain their original source and hard target; resource backpressure never transfers a partial frame. Queue metadata is bounded, queue ids never reused in this MQ, and duplicate CREATE does not renew idle time. Fair turn rotation covers PILS, connect, native send/receive and MQ read/write; ENOBUFS and idle queues have registered timers, with no permanent WouldBlock spin.

All original source/startup, send, first-input, output and callback targets have logical plus immutable native bounds. Native expiry/alarm registration precedes clock sampling, including a revision race. Initial startup is enforced only until the first whole registration/address READY; a later TRANSPORT replacement does not revive or reapply that original startup deadline. The original daemon lifetime, public identity validity, queue idle and admitted operation targets never reset.

A verified PILS PID change keeps the same TRANSPORT MQ, bound socket,
queue IDs and incoming callback ownership. Registration/address messages and
flow-control callbacks do not carry a local PID. Every SEND captures its sender
in an immutable datagram when admitted: old packets keep the original sender,
bytes, deadlines and result-ACK exposure, while later SENDs capture the new PID. No payload is rewritten, replayed or requeued. Same-PID metadata observations
also preserve these owners; PILS source loss or invalid input remains an
error.

TRANSPORT EOF or a classified native stream disconnection physically detaches only that MQ. Its input prefix/held head, immutable output prefixes, flow callbacks and original SEND outcomes retire with their original epoch/queue/message ids. An atomic nonblocking datagram send has no in-flight syscall after Pending: an unsubmitted old intent is cancelled, while an already observed Whole/Failed/Unknown result keeps that original fact. No old payload, result ACK, callback or held native packet is submitted on the replacement. The same bound Unix socket/path and SocketEpoch, queue address/peer/idle owners, PILS observer, source clock and process lifetime remain. Clock/Resolver port refusal, InvalidData/typed protocol errors, capacity failure, native socket loss and PILS loss remain fatal; they are not disguised as recoverable stream disconnects.

The retained Channel owns bounded reconnect backoff. A fresh attachment gets a fresh epoch, REGISTER and the same original unlimited native address claim with a fresh local address id. After whole REGISTER, live queues are reannounced one at a time with fresh ids and one-slot availability. Old unannounced expired rows drop locally; an already queued current SETUP wholly settles before DOWN. Queue credit and payload submission require the exact current SETUP whole-write. A held new native input waits under its original bound for that queue's publication. Restoration, stream read/write and native IO interleave fairly, so a full output budget cannot freeze required SEND/FC input. Restored reports the completed publication FIFO prefix, including SETUP/DOWN created during recovery; continuing unrelated traffic need not empty the FIFO.

A permanent native send failure queues the original negative SEND result
followed by DOWN, rather than returning credit to a queue the service has
discarded. The send and its partial/whole result exposure remain owned
until DOWN finishes. A duplicate CREATE or matching native input waits under its
original bound for retirement; a stale SEND receives the ordinary unknown-queue
result. The next attempt gets a fresh QID and never replays the failed packet. MQ loss during this retirement also removes the failed queue, while preserving
the original send outcome and result exposure in SendRetired. Permanent send
errors and queue expiry reach normal program diagnostics; transient ENOBUFS
retries are not logged on every turn.

Final close still physically stops all owners before retiring metadata. Actual fd/path cleanup errors are independent of the first cause; path cleanup checks the original observed dev/inode and leaves replacements alone. Shared Channel/PILS expose no separate close errno, so no fabricated errno receipt is claimed. Explicit cancellation calls close; there is no private CANCEL. The caller-owned Cell allocation domain permits bounded slot reuse without a hidden global/Atomic64 dependency.

PROGRAM is in apps/gnunet-communicator-unix. The public pure model covers framing,
MTU and opaque ids. Component checks and selected runtime observations have
distinct scopes; full runtime interoperability and peer qualification remain open.

The failed-send recovery change has two passing host component regressions over
private Unix streams and datagrams: a missing native destination followed
by recreation, and stream loss during the partially written negative result. They check negative result/DOWN ordering, absence of old credit, fresh QID,
preserved write exposure and delivery of only the new packet. PILS readiness is
an explicit fixture precondition.

The identity-update component case additionally uses pure-PILS signatures
on an Unix PILS stream, two datagram destinations and one unchanged
TRANSPORT MQ. It checks an unsent original sender-A packet, a different sender-A
whole datagram whose result ACK has a positive partial prefix, and a later
sender-B packet. Source/socket/queue identities and original bounds survive the
verified PID change; PILS EOF remains a source-loss error. This component
case does not claim a normal PILS daemon or C interoperability result.
