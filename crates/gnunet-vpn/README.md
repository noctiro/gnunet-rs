# Official VPN packet and lease/flow core

The no_std/noalloc shared packet layer performs checked IPv4/IPv6/TCP/UDP/
ICMP parsing, checksums, construction, rewrite and bounded ICMP quote handling. It preserves TCP options and raw wire fields, and exposes exact official service/
gateway port tools. It does not infer authentication from an IP/checksum/tuple. Unsupported IP fragmentation/IPsec/active-routing cases are explicit errors. The active C ICMP translation range and raw code/rest behavior remain explicit;
this is not an unbounded general-purpose RFC6145 router.

## Bounded VPN lease/flow owner

The added `Engine` is an allocation-free VPN state/translation owner over
explicit ports, not a native TUN, sysroute, REGEX discovery or CADET runtime. No
network, OS route, thread or success stub is created. All protocol frames use the
existing official VPN/EXIT codec. Raw UDP/IP handling is this new VPN capability;
it does not use/recover any stopped communicator, network-DHT or GNS branch.

`Engine::new(&mut Instance, Storage, Limits)` borrows fixed actual-client,
redirection-response, lease, flow and shared packet rows. Packet slabs can have
different sizes and are selected by best fit. No maximum payload body is reserved
separately per flow. At least one slab must cover the declared raw-packet policy
and its bounded peer-envelope overhead. Local IPC results use at most32 inline
bytes per request. Instance/row/checked allocation id brand every capability;
these local ids never become private wire RIDs or channel fields. All source/job
and immutable output tokens remain stale across bounded row/source reuse.

The native IPC service calls `attach_client`, decodes with `ipc_af()` and calls
`redirect(client, WireRequest, absolute_now)`. Original RID bytes echo untouched. Input
validation/Capacity/counter overflow refuses before business admission. Real
allocation failure (no ready TUN/routes, expired request, no family/address
or lease capacity) returns official AF_UNSPEC, not a fabricated usable mapping. Successful allocation does not claim any discovered exit or established TCP
connection. Local `cancel_request` suppresses an observation and has no invented
wire CANCEL; already created leases intentionally survive callback/MQ lifetime. `prepare_client` permits one immutable pending frame per MQ. `Effect::request`
and `request_client` preserve exact original request/source association.

Only empty/expired lease rows are reused; unexpired addresses are not silently
retargeted under resource pressure. Expired addresses still held by live flows
are also excluded from allocation. Lease expiry prevents new tuples but does not
destroy active tuples: each flow retains its original virtual address, kernel
5-tuple and copied target. Lease expiry is `AbsoluteTime`, preserving the exact
official wire value and FOREVER. Genuine admitted packets update `MonoInstant`
activity in one fixed native epoch; `expire(absolute_now, activity_now)` keeps
wall adjustments separate from local idle duration. Idle expiry requests close
rather than inventing a stopped channel. The original C service's
legacy request protocol field is ignored just as its handler does; packet
protocol, service port and EXIT policy govern forwarding.

An verified original device first calls `attach_tun`. No lease becomes
usable until a OS provider admits the exact `RoutingRequest{action:Install,
prefix/interface plans}` and returns a successful original `route_applied` receipt. Configuration validation, write/enqueue success or a blind fd Drop cannot invent
that receipt. An admitted failed/retired OS job preserves Unknown route effects. `route_cleanup_request` offers Remove work, including on a dead old source;
`route_removed` requires original-scope cleanup/ownership release. A native
provider may instead call `confirm_routes_absent(oldTun)` from a verified original
platform close/device-removal contract or absence observation. No new
syscall is required when the platform contract is real. It cannot use a new epoch
or guessed reused ifindex, and no outstanding old route job may reapply effects. Cleanup must respect other owners' preexisting routes. `retire_tun` is blocked
until the old source is stopped, its job/route debt is clear and all independent
flows/packet effects have retired. Ordinary shutdown can remove routes while the
original FD is still held, then close. An unexpected-loss capability gap remains
an honest retained Unknown debt, not a no-op success.

`forward_tun(tun, rawIP, absolute_now, activity_now)` validates the whole packet/checksums, captures
the kernel tuple and builds genuine official UDP, TCP-start/data or ICMP service/
Internet messages in a shared slab. TCP options/sequence/flags remain actual
transport bytes; the kernel owns TCP state and this core synthesizes no ACK or
user-space TCP connection. `receive_peer` takes only native activity time; it
cannot expire or renew an absolute address lease. Native time regression is
refused before either expiry domain is changed. UDP source-port policy matches the active C sender. ICMP errors follow the official quote-omission contract, echo data is retained. Unsupported fragments/IPsec/cross-family ICMP classes are explicit errors. Full
peer frames are capped at the CADET application maximum64348, not merely the
wire's u16 limit. Too-large policy is permanent error, not endless Capacity retry
or private fragmentation. `build_parts` adds a noalloc fixed-header+borrowed-tail
packet builder so receive conversion needs no temporary maximum-size segment.

Service flows offer the exact descriptor port (first two bytes replaced by BE
port). Internet flows offer genuine `DiscoveryRequest` to an external policy
provider. `select_exit` requires that original admitted job and cannot pretend a
raw peer claim is eligible. The original job remains owned until explicit actual
retirement even after selection. No stopped DHT branch is called. `OpenRequest`
then identifies the standard gateway/service port and expected peer. Admission
preflights exist for routing/discovery/open/packet effects. `open_queued` records
native create admission, not connection success. `bind_peer` must receive
end-to-end CADET source evidence for that expected peer, never a queued
create or plaintext claim. It also receives the endpoint AF profile;
local IPC and peer profiles are separate. Buffered AF metadata normalizes once
before any prepared peer effect, allowing explicit Linux2/10↔Darwin2/30 sources
without guessing packet lengths. Prepared/native bytes never change or reseal.

`prepare_peer` takes oldest buffered flow data and permits one original peer
attempt per flow, preserving first TCP START before DATA. `receive_peer` accepts
only the exact original Peer and correct reply direction, rewrites original
reverse addresses/ports, and constructs a checksum-correct raw TUN packet. Reply zero ports retain the original tuple. ICMP replies/errors are translated
only over the active C-supported type contract, with explicit reconstructed IP+8
quotes. Capacity/WouldBlock retains caller input unchanged; permanent malformed
input requests source close and grants no fake receive_done. A Delivery
is eligible only after its original whole TUN packet actually writes. Semantic
`receive_done` does not prove that the native CADET ACK itself wrote.

Every final native output uses original `Effect`: queued, positive
exposed, whole written are distinct. Native short TUN writes are real
loss/unknown outcome and must not resume a packet suffix or replay on a new TUN. When a native loss report includes a positive prefix, the adapter reports
that original exposure before committing loss. Zero-exposure Unknown is still
Unknown, not permission to replay. `reject_prepared` is only for true nonadmission;
`unsent` needs conclusively zero-write settlement and closes packet flows
so subsequent TCP DATA cannot bypass a missing original START. Canceled waits are
not physical cancellation. Prepared/source-bound callbacks validate generation.

Closing a flow revokes new work but preserves original job/source/output debt. A lost CADET source retires only peer writes; already queued TUN packets may still
drain on their original live TUN. A lost TUN similarly leaves original peer writes
to settle on their CADET source. Neither plane fabricates completion of
the other. `peer_lost`/`tun_lost` require physical stop first. Original
outcomes and bodies remain in bounded storage until explicit release; uncredited
live incoming data cannot be released early. Old delivery/source callbacks cannot
credit a new channel. `close_required`, job retirement, `release_buffer`,
`retire_flow` and `retire_tun` allow an coordinator to drain all original
work without hidden tasks or leaked contexts.

One focused additional pure model covers allocation requiring modeled route
receipts, UDP official peer/raw-TUN roundtrip, whole-write credit gating, active
flow survival across lease expiry, non-reuse of its address, local cancellation
leaving a lease, independent queued TUN drain after CADET loss, and old TUN/route
job retirement with mandatory cleanup. OS/CADET receipts in this pure model are
explicitly modeled ports, not native execution proof. Existing packet/EXIT/native-client evidence is not
relabeled by this owner candidate.
