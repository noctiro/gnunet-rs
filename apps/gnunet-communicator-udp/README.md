# UDP communicator PROGRAM

The normal configuration-only `gnunet-communicator-udp` entry composes the
original bounded UDP communicator, PILS client, NAT registration, TRANSPORT
APPLICATION client and one shared Resolver/clock. Numeric family sockets bind
before configured USERNAME; the existing identity is loaded only after that
boundary and a verified PILS announcement, and must match it. Replay
state is independent, private and bound to the same public peer.

Official broadcast/multicast presence uses the original family sockets and
interface snapshots. Signature-verified address candidates enter the
APPLICATION Validate path; they never directly install an authenticated
queue. NAT/interface claims, communicator local publication writes and PILS
FEED writes remain separately observed. URI `udp://` and communicator `udp-`
addresses are encoded in their respective official contexts.

Verified HELLO refreshes on the same PILS source can update revision and expiry
without rotating the identity. The program explicitly adopts such a current
observation only when its peer, address-hash derivation context, coverage and
matched local key remain the same. This preserves the original UDP key and
sessions after an ordinary FEED. A healthy changed peer on that same branded
observer retires original packet/peer/MQ authority, then selects a fresh matched
key and that full identity's original replay journal. Default sockets, fixed
packet backing, NAT/interface claims and desired FEED stay with the process. Old discovery signatures are cleared; canceled packets and exposed MQ prefixes
retain their loss facts. Physical observer replacement or uncertain
history still stops the process.

The process identity owner has exclusive Active(key+journal) and Retired phases. A failed reconstruction grants no new key/journal facade. Repeated changes
share one native/canonical 30-second recovery bound until replacement
REGISTER and queue restoration whole writes complete. Queue/token serials and
lifetime traffic counters do not reset. Address observations retain a live
socket across an identity cut; final stop keeps its separate withdrawal path.

Each polling turn refreshes the canonical/UTC and native elapsed time
after the original native guards, including after a pending socket/timer wait. ACK expiry and PILS-key validity therefore use the current turn's sample; a
canonical clock rollback stops the owner. Original ACK, burst, discovery and
publication targets are retained through waits.

A lost TRANSPORT connection retires its original input, partial writes and
pending send callbacks before one retained, bounded-backoff CLIENT attempt
reattaches. The same process keeps its UDP sockets, peer keys, replay journal,
nonce counters and monotonic origin. A replacement sends the standard REGISTER,
then announces unexpired queues with fresh local queue identifiers and actual
remaining packet credit. New-source commands and traffic for announced queues
interleave with restoration, so duplex backpressure cannot stall a large queue
set. Current address ADDs follow completed queue restoration; original NAT claims and PILS FEED
operations keep their independent ownership and lifetimes. An MQ replacement
alone neither withdraws a still-live UDP address nor replays its HELLO feed. Physical stop, identity loss and uncertain replay-store outcomes still stop the
original owner. Local registration and restoration logs distinguish actual
whole writes from peer delivery or acknowledgement. Connection, registration and restoration milestones use the ordinary INFO
level, including in builds that omit optional DEBUG diagnostics.

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
NAT traversal or mixed-node reachability. Stream activation descriptors are rejected; no inherited readiness is claimed.

The recovery increment requires its own normal-process qualification; source
and compilation alone do not prove recovery or unchanged C interoperability. Earlier evidence retains its original source and scope. This entry does not
establish full UDP or GNUnet completion.

The PILS identity/HELLO profile is selected from `[PILS] PROFILE`, with
`reference029`/`reference-0.29.1` as the unchanged default and
`deterministic`/`reference-deterministic` for the official conditional build. Explicit `lsd0014-text` selects only the published textual derivation, without an
official interoperability claim. Optional `[communicator-udp-rust] PILS_PROFILE`
must agree with an explicit global choice. The PILS client and local-key
binding consume that typed choice; it is separate from UDP session/rekey policy. Normal replay roots hold the process writer fence above `udp-<full peer>` child
directories. Each child retains its original replay floors, outgoing high-water
and writer fence, including when an identity returns. Unsuffixed old snapshots
and temporary footprints are refused without migration or reset.
