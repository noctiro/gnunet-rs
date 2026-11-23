# UDP communicator runtime contract

`Bound` qualifies the numeric sockets before opening the local services.
`Bound::attach` consumes the sockets and keeps the same configuration for
PILS, NAT, TRANSPORT and RESOLVER. Both the application and PROGRAM entries use
the same foreground. The peer key is loaded only after a verified PILS
announcement and must match it. Replay state is bound to that public peer.

## Process and storage

`[communicator-udp-rust] ACK_TIMEOUT` selects the sender's finite, positive
ACK liveness window; the default is five minutes. It is independent of the
official `REKEY_INTERVAL` and `REKEY_MAX_BYTES` settings. Matching peer-bound
ACKs refresh liveness. Expiry retires the original KX/BOX queues and pending
local outcomes before another endpoint can be admitted; native sends alone
provide no liveness or delivery receipt.

Destination-level UDP send failures retire only the affected endpoint's queues.
The original negative SEND result and native diagnostic remain distinct from
successful native transmission; other endpoints keep the shared socket and MQ.
Socket-owner, resource and short-write failures retain their terminal boundary.
Windows UDP sockets suppress asynchronous ICMP connection-reset receives.
The replay journal reports its actual directory-sync capability separately from
file synchronization and local commit observations.

## Address discovery

Official broadcast/multicast presence uses the original family sockets and
interface snapshots. Signature-verified address candidates enter the
APPLICATION Validate path; they never directly install an authenticated
queue. NAT/interface claims, communicator local publication writes and PILS
FEED writes remain separately observed. URI `udp://` and communicator `udp-`
addresses are encoded in their respective official contexts.

In the `HelloPublisher::Transport` profile, UDP submits the original address
ADD and DEL effects to TRANSPORT and continues to observe its verified identity
from PILS. TRANSPORT owns publication of the combined communicator address set.
Direct PILS FEED and its retirement state exist only in the
`HelloPublisher::Communicator` profile.

Interface refresh prepares the complete classification, advertised-address and
discovery projections before changing any consumer. Exclusive address and
discovery guards make their joint commit infallible; failed enumeration,
projection or admission retains the previous complete snapshot and retries on
the scan interval. Existing write receipts, pending announcements and membership
retirement remain with their original owners. Projection buffers are released
after installation; the scanner retains only the native rows.

The [NAT observer](src/run/nat_registration.rs) derives registration deadlines
from its selector's absolute logical clock. EOF, native network failure, input
expiry and source-level protocol/capacity refusal retire that source's claims,
then schedule a fresh REGISTER with bounded backoff. Its allocation, epoch and
address IDs are new; old requests, partial writes and callbacks are not replayed.
Interface claims and UDP sessions keep their independent owners. A new address
that exceeds claim capacity or fails classification is diagnosed and its actual
callback released, so later removals can proceed. The NAT client's bounded
allocation remains until the actual removal or source retirement.

## Identity recovery

Verified HELLO refreshes on the same PILS source can update revision and expiry
without rotating the identity. The program explicitly adopts such a current
observation only when its peer, address-hash derivation context, coverage and
matched local key remain the same. This preserves the original UDP key and
sessions after an ordinary FEED. A healthy changed peer on that same branded
observer retires original packet/peer/MQ authority, then selects a fresh matched
key and that full identity's original replay journal. Default sockets, fixed
packet backing, NAT/interface claims and desired FEED stay with the process. Old discovery signatures are cleared; canceled packets and exposed MQ prefixes
retain their loss facts. Uncertain replay history stops the process.

Physical PILS connection loss closes the old TRANSPORT source and retires
old packet, peer and discovery authority before releasing its key and journal.
The identity owner enters a paused phase without a usable key/journal facade.
The same PILS client must receive a signed, unexpired identity on a strictly
newer branded epoch with a newer revision before reconstruction. A socket
attachment alone cannot resume work. If the cached master no longer matches,
the program verifies this successor before reading the configured existing
key; it never creates a key or accepts a mismatch.

Repeated identity changes and source losses share one native/canonical
30-second recovery bound until replacement REGISTER and queue restoration
whole writes complete. The first connection failure is retained. Guards run
again inside the PILS driver after clock providers and before native I/O.
Clock, replay-history and ownership invariant failures remain terminal.
Queue/token serials, original NAT/application deadlines and lifetime traffic
counters do not reset. Default UDP sockets and NAT/interface claims remain
owned; old FEEDs retain their actual write/loss receipts. A replacement source
receives a new snapshot of current address intent, including after a previous
whole-written FEED. Shutdown while paused closes connectors without starting
another recovery or claiming an address withdrawal.

Each polling turn refreshes the canonical/UTC and native elapsed time
after the original native guards, including after a pending socket/timer wait. ACK expiry and PILS-key validity therefore use the current turn's sample; a
canonical clock rollback stops the owner. Original ACK, burst, discovery and
publication targets are retained through waits.

## TRANSPORT recovery

A lost TRANSPORT connection retires its original input, partial writes and
pending send callbacks before one retained, bounded-backoff CLIENT attempt
reattaches. The same process keeps its UDP sockets, peer keys, replay journal,
nonce counters and monotonic origin. A replacement sends the standard REGISTER,
then announces unexpired queues with fresh local queue identifiers and actual
remaining packet credit. New-source commands and traffic for announced queues
interleave with restoration, so duplex backpressure cannot stall a large queue
set. Current address ADDs follow completed queue restoration; original NAT claims and PILS FEED
operations keep their independent ownership and lifetimes. An MQ replacement
alone neither withdraws a still-live UDP address nor replays its HELLO feed. Physical stop and uncertain replay-store outcomes still stop the
original owner. Local registration and restoration logs distinguish actual
whole writes from peer delivery or acknowledgement. Connection, registration and restoration milestones use the ordinary INFO
level, including in builds that omit optional DEBUG diagnostics.

## Diagnostics and shutdown

Normal-owner cleanup emits one bounded `udp.traffic` INFO snapshot on success
or failure, subject to the selected logger and level. The same fixed counters
remain inline in the returned Report or its failure report. Native Initial
and BOX counts/bytes come only from whole `NativeSent` events; the separately
reported rekey counts/bytes are a subset of BOX. Incoming initial and BOX
counts/bytes come only from authenticated `Incoming` events and measure the
original ciphertext extent. These are local native observations, not peer
delivery or TRANSPORT validation receipts. Consumed `Discarded` events retain
only their count and first/last classified Error. Counts and bytes saturate
with an explicit overflow flag. No sequence, nonce, payload, key, per-packet
log or extra polling/clock sample is retained or introduced. Discovery/burst
send and progress events are outside the packet/byte totals; every actual
Discarded event is counted. Early setup-constructor refusals,
before any UDP traffic can occur, retain their existing error/cleanup behavior
and do not emit this normal-owner summary.

The process keeps original operations through waits and uses one fixed native
shutdown allowance for address withdrawals and queue teardown. A failed clock
permits clock-free withdrawals/physical close, without claiming an empty FEED
or remote removal. Native reversal notifications are explicitly diagnosed and
the same source-bound held callback is released; that release is not reversal
completion or an acknowledgement. In pinned v0.29.1,
`gnunet-communicator-udp.c` lists reversal as TODO `#5529`, and
`try_connection_reversal` only logs that no reversal is implemented. The generic
NAT notification/request API supplies no implemented UDP-specific reversal
exchange to reproduce here. This is an upstream-unimplemented capability, not
a missing implementation of a defined v0.29.1 UDP exchange; no private probe,
nonce, send receipt or connection success is invented. This does not establish
NAT traversal or mixed-node reachability.

Remaining normal-process and official-peer coverage is tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Identity profile

The PILS identity/HELLO profile is selected from `[PILS] PROFILE`, with
`reference029`/`reference-0.29.1` as the unchanged default and
`deterministic`/`reference-deterministic` for the official conditional build. Explicit `lsd0014-text` selects only the published textual derivation, without an
official interoperability claim. Optional `[communicator-udp-rust] PILS_PROFILE`
must agree with an explicit global choice. The PILS client and local-key
binding consume that typed choice; it is separate from UDP session/rekey policy. Normal replay roots hold the process writer fence above `udp-<full peer>` child
directories. Each child retains its original replay floors, outgoing high-water
and writer fence, including when an identity returns. Unsuffixed old snapshots
and temporary footprints are refused without migration or reset.
