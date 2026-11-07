# Native PILS host

`Host` adopts a authorized Unix listener and a pure PILS service owner. Its
explicitly driven steps retain physical streams, partial framing, per-connection
FIFO output and public address scratch. Per-client limits bound admission;
malformed/slow clients close independently. Key-result output uses erased owners. The node supplies canonical logical time and owns listener policy/path cleanup,
readiness, shutdown and the persistent writer lease.

`identity::load_or_create` acquires an exclusive lease, creates the
official raw32 initial-key file using fresh entropy, syncs the temporary file,
renames it and syncs its directory. Existing malformed files fail rather than
silently changing the identity. Read-only domain clients use `load_existing`. Unix files must be private. Native lock I/O failures preserve their cause. The lease coordinates Rust identity writers; it is not a PEERSTORE namespace lock
or a proof that an unrelated historical writer has quiesced.

`pils-service SOCKET KEYFILE` is a controlled foreground acceptance embedding. It reports READY, uses official IPC and exits on stdin `quit`. Its1ms polling
loop is a fixture profile, not a performance benchmark or the complete production
launcher. The optional `service` feature adds the production `service::Host` and
`startup::{prepare,foreground,foreground_listening}`; `gnunet-service-pils` uses that path rather than
the fixture loop. `prepare` owns synchronous private-root setup outside service polling and
before service tasks/workers; the caller-driven host uses common canonical Unix/TCP connections,
kernel UID/GID checks, address ACL, bounded erased framing and an explicit shared
absolute UTC clock. Every connection subscribes immediately. All four
registered request families use the existing pure crypto owner; FEED broadcasts
immutable announcements in original per-MQ FIFO order. There is no active
periodic rollover/HELLO task in the reference. Polling performs no private-file
I/O and creates no worker, per-peer thread or C backend.

Normal preparation reads node-wide `[PILS] PROFILE` before loading or creating
the private root. `reference029` (also `reference-0.29.1`, the default) preserves
the official ordinary build: its empty address hash keeps PID stable across
address changes and its HELLO signature covers metadata only. `deterministic`
selects the official conditional build's canonical address hash and corresponding
PID changes, with metadata and address coverage. All normal consumers must choose
that same profile. Unknown choices fail before private creation; no signature
verification fallback or private wire format is introduced.

The standard production SERVICE captures activation/parent control first, then
uses shared `c,d,h,L,l,v` options, selected Logger and explicit fresh-process
daemon split. Only the child loads configuration or prepares authority/listeners;
parent success requires the original ready byte, never EOF/clean early
stop or a queued message. Child logging PID refresh keeps the selected owned file.

Its idle current-thread runtime adopts activation or prebinds TCP before USERNAME,
then leaves that entered preparation scope for apply/initgroups. New Unix
paths finish under the selected account. Only then does the unchanged synchronous
`prepare` construct the durable `[PEER] PRIVATE_KEY` authority, outside host
polling and before active service tasks. Its original root/fence/secret drop order
is retained. Logger and Host share the same selected SharedClock/skew authority. Embedding callers must supply the configured account before private-root
access and service tasks; the library checks real/effective primary IDs instead
of switching them inside async work.

`foreground_listening` consumes BoundListeners without rebinding; both
public foreground entries use one internal driver. Ready runs only after actual
root preparation and listener binding, with current Host identity still present. Failure of ready or service work reaches Host.close and retained cleanup
events. Independently failed cleanup observers retain both original causes. The standard Logger handles socket/progress diagnostics. First diagnostic
IO failure requests normal shutdown and is returned after original streams close,
key owners erase and writer fence releases. No global logger, secret logging,
private-key copy, background root job or synthetic write/ACK is introduced. The active source does not use the template's PILS
SECRET_KEY_FILE. Missing/malformed credential options are explicit and UID
matching takes priority through the shared implementation.

`service::Limits` bounds physical clients, single-frame size, retained per-MQ
output records/bytes, address scratch/count and syscall slices. The host keeps
one fixed slot per admitted client and a pre-reserved clients+1 event queue;
there is no per-poll connection-ID allocation. Original queue/refusal/native
causes stay observable and only the affected MQ closes. Explicit shutdown closes
physical streams, then erases the service keys, then drops the persistent writer
lease. Original partial frames survive canceled drives. Actual write progress
is not a request ACK, remote delivery or persistence result.

The hardened Unix loader refuses symlinks, multiple links, wrong effective
owners and group/other file permissions, verifies original held/path directory,
lock and key inodes, and preserves the file lock through the writer's
lifetime. Existing key and parent synchronization plus exact reread reconcile
an earlier interrupted directory barrier. New creation uses an owned mode0600
temporary with file sync, original-inode checks, rename, directory sync and
original-byte readback. Failed durability returns no usable owner; malformed
existing files never select replacement identity generation. Namespace ownership
and exclusion of hostile path replacement remain caller requirements.

One production-host model supplies a new Rust root, Unix/TCP streams,
all four valid message families, signature/DH/KEM checks and durable reopen. It is separate from the historical C/client profiles and does not establish
whole-node acceptance. No libgnunet implementation is used. Native private-root
and production service modules are explicitly Unix-only; the pure crate remains
independent of native platform/runtime dependencies.

The optional `client` feature adds `client::Client`, a movable, explicitly polled
Rust PILS client. The caller supplies exclusively borrowed `Instance` storage,
`EndpointSource` and the intended shared CLIENT/Resolver/clock context. Offline
crypto requests own their bytes and IDs; capacity is bounded by both the runtime
pending limit and the small metadata slot count. Payload storage uses the pure
core's optional actual-length erased heap backing, rather than embedding a
maximum-size frame array in every operation slot. The default service-only
feature set does not enable this client or a hidden Resolver/task.

The client uses the common `Framed<Origin>` owner for one original physical
connection. Each positive native write is processed before reading another
frame; full-write progress is reported to the original pure-core transmit lease. Partial output is immutable and drains after logical cancellation. Partial input,
output, connection attempts and retry timers survive a dropped `drive` future. A `drive` deadline limits that wait only. Fatal framing/protocol/I/O errors retire
the original physical stream and erase its buffers before invalidating the old
MQ identity and registering a retry. A clock-port refusal preserves its actual
cause and never fabricates a successful write, socket failure or operation
completion. A complete secret frame can remain retained until a dispatch-time
clock refusal is recovered; closing/dropping the owner erases that frame.

Initial CLIENT native connection failures retry within the same logical MQ
(first delay1ms, exponential cap15min). Established MQ loss reports retained
crypto operations and unsubmitted/submission-unknown FEED operations, then uses
the pure PILS retry policy. A refused CLIENT time/Resolver port requires explicit
`recover_ports`; it keeps the original admitted IDs and canonical clock context. `reconnect` returns its owned loss report immediately. Caller-requested shutdown
returns pending original IDs. There is no background callback whose completion
can be silently lost when a later close occurs.

FEED has no remote acknowledgement. Its full local write retires only the local
operation; this client retains no desired address set and does not automatically
replay it. Applications that need current addresses after reconnect must retain
their desired state and explicitly re-feed it. Sign/DH/KEM replay their original
request bytes and wire RID after MQ loss, so a canceled operation cannot be
mistaken for a newly admitted one. RID exhaustion is explicit; closing the old
physical MQ and reporting pending work precedes construction of another owner.

A verified HELLO is an observation from the selected ordered trusted MQ, not a
global authority. DH/KEM replies contain no peer field; Exact binding is limited
to that original MQ's verified announcement/response order. Signatures verify
against their returned signer. A changed Exact key fails the original
operation and erases the received secret; a mismatched local master key is
explicitly unavailable until a caller supplies the matching one. Profiles are
explicit, with no fallback between Reference029 and LSD0014 text semantics.

`cargo run -p gnunet-pils-host --features client --example pils-client -- SOCKET IKM`
is a finite direct acceptance caller. The optional third argument `recovery`
uses explicit stdin checkpoints for the owned fault observer. It is test
orchestration, not a production launcher, protocol field or remote guarantee. The direct and controlled-loss normal-C profiles have separate source-bound
receipts. They cover Reference029 on owned Unix sockets; they do not establish
conditional-build/C-over-TCP acceptance, every allocation/OS-crash combination,
a complete production node supervisor, or full PILS/Node interoperability.

The
existing historical profile descriptions above retain their original scope.
