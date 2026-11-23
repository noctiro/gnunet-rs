# PT native host

This crate composes the PT core with the official DNS-interception, VPN, CADET
and DHT clients. Linux, macOS, Windows and FreeBSD share the protocol owner and
PROGRAM driver. The SDK exposes it through `official-pt` and `gnunet::pt_host`.

## Ownership

`Owner::new(Identities, Sources, clock, core_limits, families, native_limits, vpn_af)`
borrows the caller's Instance brands and channel metadata. It owns each enabled
client and starts no hidden task, Resolver or runtime. Each DNS notification keeps
its original Source, Epoch, opaque eight-byte ID, native request, core request,
absolute expiry and native hard bound. Only that original callback can receive
the reply. `drive` is a cancel-safe observation wait; `stop` physically retires
the original owners without sampling a clock and returns independent failures.

DNS source loss cancels its callbacks and their original VPN allocation interests.
Reconnection sends fresh INIT frames without replaying old answers or callbacks.
When PRE loses its DNS connection, PT also retires the original PRE CADET
connection and settles its tunnels before admitting new PRE work.
Allocation replies must match their original operations and address families.
The VPN client retains partial cancellation debt after the DNS callback is gone.
PT polls its native guards before its own clock wait and settles local outcomes
without a clock sample. A healthy VPN MQ survives DNS replacement; old allocation
results cannot satisfy a successor callback with the same opaque DNS ID.
After VPN MQ loss, an operation with zero bytes sent can use the replacement MQ
with its original DNS callback and deadlines. A possibly exposed allocation
causes the original callback to drop.

The [interception module](src/owner/interception.rs) retains rejected callbacks
until their original Drop decision can be admitted. A full DNS output budget
leaves that decision pending while existing writes and other sources progress;
retries keep the original token and deadlines. Callback metadata follows each
enabled DNS client's native request limit, independently of the core's smaller
business-admission budget. Only local reply admission advances its decision
state; whole-write and source retirement remain separate observations.

At attachment, the DNS client supplies a per-reply limit derived from the wire
frame size and its empty output budget. PRE drops a validated answer above that
limit. POST checks the unchanged payload length before allocating VPN mappings
for a rewrite. Full queues still apply bounded backpressure to replies that fit.

## DNS and VPN translation

POST translates every selected A/AAAA record in the answer, authority and
additional sections through same-family VPN allocations. Only a matching USE_IP
reply supplies a replacement address. VPN packet forwarding, routes, TUN and EXIT
ownership remain in the VPN service. Allocation and queue-write receipts confer
no forwarding or remote-application readiness.

Admission reserves the full transformed reply before exposing any VPN allocation
job. Capacity refusal therefore precedes a possible remote allocation. Results
fill the reserved slots; final encoding and compression validation precede reply
queue admission. The [POST host module](src/owner/post.rs) owns the original VPN
interests and their matching results within the shared PT owner.
Disabled providers require no host allocation-interest, channel or advertisement
table, and POST-only construction requires no CADET backing slots.

Queued rewritten responses use `packet::rewrite_uncached`: transformed A/AAAA
TTLs become zero so output backpressure cannot extend the VPN lease. Compression
alias validation covers the original and transformed packets, AD is cleared and
unrelated record bytes are retained. Existing RRSIG data does not authenticate
the rewritten RRsets. Pure callers can use `packet::rewrite` for a positive
floor of the remaining lease.

## Exit discovery and tunnels

PRE uses signed exit advertisements from DHT and CADET DNS messages 193/194 on
SHA512("exit-dns"). A request without an admitted live advertised channel is
dropped. Each tunnel retains its original EXIT peer, request deadline, bounded
attempt count, DNS IDs, questions and opcode. IDs do not wrap: after 65,536 IDs,
the old channel drains its outstanding requests and is destroyed before a new
generation opens. Whole writes, answers and timeouts remain distinct facts.

A prepared query keeps its exact attempt and channel-local DNS ID. Admission to
the CADET client consumes channel credit and one request attempt. A zero-credit
update parks the query while other tunnels can send. Retiring an unqueued query
releases its reservation on the tunnel.

The caller supplies a [discovery port](src/discovery.rs).
[`discovery::Native`](src/discovery/native.rs) owns a readonly DHT GET for
SHA512("dns"), block type 10, replication 1, DEMULTIPLEX_EVERYWHERE and an empty
extended query. One GET, output frame and input frame are bounded. Advertisements
are signed 112-byte public blocks. Readonly MQ recovery preserves the original
GET and its bounds; cancellation suppresses it and physically retires the MQ or
pending connection before ending. A write or end observation claims neither
remote success nor absence of matching exits.

The [advertisement owner](src/owner/advertisements.rs) binds verified blocks to
their original query and native lease. The [PRE host](src/owner/pre.rs) handles
CADET events and classifies one nested DNS frame per turn, allowing ready DNS
decisions to advance between frames. The owner resumes CADET input after the
original receive acknowledgement is written or the delivery is retired. Queries,
retries and valid responses reuse the core's admission-time reply reservation.
A fixed parser or size refusal withdraws the exit.

The bounded lease table keeps one monotonic absolute-expiry floor. Expired
admitted leases, observed on the canonical clock or at their original native
targets, advance this local admission boundary. All equal or earlier expirations
lose authority before their slots are reused, including after clock rollback or
an identity change. Repeated expirations keep their original hard bound; only a
strictly later signed expiry can replace it. Channel and control cleanup retain
their independent owners.

A received CADET DNS packet retains its original tunnel and byte cursor across
a later channel destruction. Reply classification still checks the original
Waiting attempt, DNS ID, questions, opcode, deadline and exit lease. On a destroyed
channel, classification finishes before unanswered requests are reselected.
Releasing the local packet sends no receive credit to that gone channel. Local
cancellation and expiry grant no new response authority, and admitted output
keeps its own completion and bounds.

## PROGRAM integration

The optional `program` feature provides [settings](src/settings.rs) and the
[shared foreground](src/foreground.rs). The normal
[daemon](../../apps/gnunet-daemon-pt/) uses `ClientStartup` and `StopSignals` for
original parent control and native termination on every supported platform.
Unix applies the configured process identity; Windows verifies its current
token. Local VPN IPC uses `AfProfile::native()` for the actual platform.

Official `[pt]` switches default to NO. All-disabled configuration exits before
constructing provider owners. TUNNEL_DNS selects only PRE DNS, DHT and CADET;
enabled address families select POST DNS and VPN. Selectors share the PROGRAM
Resolver and clock. `[pt-rust]` controls finite resource budgets and timeouts.
The daemon has NOARMBIND=YES and publishes no listening-service readiness.

Native hard bounds are checked before canonical-clock waits, including partial
VPN/CADET input, callbacks, allocations, control writes and exit leases. Every
bound is minted once. Clock rollback and backpressure cannot renew it. A partial
transmit or held reply at expiry retires its physical CADET MQ and removes its
old tunnel mappings before another PRE send is selected. Retries keep their
original callback deadlines. The VPN client owns its partial-input
deadline. The daemon sets it from the configured control timeout. PT settles
each original VPN operation from its matching local completion and retains
queued work awaiting submission. Provider construction failures disconnect the
original Resolver and preserve cleanup failures.

Fixed channel-retry targets participate in the shared clock wakeup, so an idle
provider set can reopen a retired channel without unrelated traffic. Already due
targets cannot hide a future callback or discovery deadline.

The selected PROGRAM Reporter carries provider and Resolver diagnostics.
Output failure wakes the original task and starts bounded shutdown; an original
business failure remains independent of the logger failure.

## Statistics and shutdown

[Metrics](src/metrics.rs) retains the official `pt` statistic names. The shared
STATISTICS owner uses the same configuration, Resolver and clock. Relative
nonpersistent deltas are attempted once; an ambiguous setter failure retires
that source without replaying a possibly admitted delta. Processing confirmation,
discard and unconfirmed shutdown remain distinct from storage durability.

Shutdown stops PT first. A normal stop publishes the final deltas and requests
the official STATISTICS processing barrier on the original connection, including
when all setters have already been written. Final admissions, barrier creation
and drain share one original native deadline while the Resolver remains live.
A PT or Reporter failure aborts the original statistics source without admitting
new deltas or starting a drain. Native timeout retires unconfirmed I/O; original
and independent cleanup errors remain in the result. The Resolver disconnects
last. Native deployment and official-peer qualification are tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
