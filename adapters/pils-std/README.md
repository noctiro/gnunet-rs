# Native PILS host

This adapter supplies the official PILS client and service over shared native
local/TCP framing. Protocol and cryptographic decisions live in `gnunet-pils`.

## Service

The `service` feature exposes `service::Host` and
`startup::{prepare,foreground,foreground_listening}`.
`prepare` loads configuration and the private root outside socket polling.
The caller owns listeners, the shared clock, stop policy and readiness.
The [normal executable](../../apps/gnunet-service-pils/) has separate Unix and
Windows startup entries around one foreground loop.

Every accepted MQ immediately subscribes to HELLO announcements. SIGN, DHKEM,
legacy DH and FEED retain official request numbers and original-MQ FIFO ordering.
Only FEED generates updates; there is no periodic identity/HELLO task.

`service::Limits` bounds clients, frame bytes, retained TX frames/bytes, address
scratch/count and syscall slices. One fixed slot belongs to each admitted client;
events use a reserved clients+1 queue. Partial frames survive canceled drives.
Shutdown closes physical streams, erases pure service secrets, then releases the
writer lease. Write progress describes local transfer, not remote processing.

## Polled native host

The `service` feature also exposes `Host`, `Limits` and `Progress` for bounded
synchronous polling of an already bound AF_UNIX stream listener. `Host::new`
takes the original `socket2::Socket` and rejects other families, nonstream sockets
and sockets that are not listening. The caller retains private-root and socket
path policy. This host owns its pure service and client buffers; `poll_once`
returns actual local activity without a background task.

## Private root

`identity::load_or_create` reads or creates the exact official raw32 seed at
`[PEER] PRIVATE_KEY`. `[PILS] SECRET_KEY_FILE` is not the active source setting.
`load_existing` performs no creation or writer-lock acquisition.

The namespace owner retains an original directory, persistent lock and complete
native file identities. Files must be private regular single-link objects;
symlinks, malformed keys and changed names fail. Unix namespaces require the
effective owner without group/other writes. Windows checks trusted ownership and
native DACLs; key files require the process user and private data access.
Namespace administration and hostile replacement remain caller exclusions.

Creation writes and syncs a private staging file, publishes that original file,
and reads it back through the held handle. An existing key is synced and reread
without reopening it. Only initial absence permits generation. Interrupted writes
are not retried; independent staging-cleanup errors remain visible. A failure
returns no usable key/lease even when publication effects are uncertain.
`KeyLease::directory_sync` reports the actual naming barrier separately from file
sync: Windows reports `Unavailable`. No directory durability is fabricated.

## Profiles

`[PILS] PROFILE=reference029` (also `reference-0.29.1`, the default) selects the
official ordinary build: an empty address hash preserves PID across FEEDs and
HELLO signatures cover metadata. `deterministic` selects the official conditional
address-derived identity and metadata/address signature coverage. All consumers
must choose the same profile; invalid selections fail before private creation.

## Client

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

## Example

```sh
cargo run -p gnunet-pils-host --features client --example pils-client -- SOCKET IKM
```

The optional `recovery` argument enables explicit stdin checkpoints for the finite
acceptance caller. Normal service configuration uses `gnunet-service-pils -c FILE`.
See the central [compatibility contract](../../spec/gnunet/compatibility.md) for
interoperability requirements and qualification scope.
