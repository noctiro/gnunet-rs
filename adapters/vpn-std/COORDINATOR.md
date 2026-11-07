# Native VPN coordinator

`coordinator::Coordinator::new(Parts { server, cadet, device }, policies, Limits)`
composes the caller's local SERVICE and pure Engine pools, one exclusively
transferred fresh CADET client and one verified TUN. Both MQ owners must share
exactly the same RuntimeClock Arc. Construction validates and fallibly allocates
only a fixed flow metadata table; every original physical owner is returned on
refusal. Call `poll` / `drive` with the local service listeners. No task,
thread, Resolver or implicit automatic discovery service is started.

The TUN descriptor is either newly kernel allocated by `Device::open_linux` /
`open_utun`, or explicitly borrowed through `borrow_existing`. Newly created
interfaces run MTU/address/netmask/link ioctls, IPv6 DAD observation and
native prefix-route operations. A submitted route request is never readiness:
original correlated ACK is required. EEXIST is checked by the exact
route query, never accepted blindly. Borrowed devices are unchanged: a real
snapshot must match the configured plan and exact route queries plus DAD
must succeed. Borrowed route states remain BorrowedVerified/Unverified/Released;
logical release never claims another owner's route disappeared or deletes it.
The coordinator requires the separately integrated borrowed-route Engine hooks.

There is one original configure deadline across all stages, not one renewed
budget per syscall. IPv6 tentative state keeps the original DAD deadline. After
an Ready sample, bounded distinct monitoring queries continue; an actual
missing/failed address, source loss or inability to obtain a fresh sample stops
admission. Control effects, snapshots, query completions and readiness observations
are delivered as their original typed native receipts through `Event`.

raw TUN reads enter `Engine::forward_tun`, retaining converted official
VPN/EXIT bytes in the caller's shared packet slabs. Configured Internet exits use
only the caller's finite explicit policies. External mode offers original
`DiscoveryRequest`s; the caller must bind provider admission, result and
retirement through `discovery_queued`, `select_exit`, `discovery_failed` and
`retire_discovery`. No automatic REGEX discovery is implemented here. Service
flows use their original requested peer and the explicitly configured peer AF
profile. No private fragmentation or AF guessing is introduced.

The CADET CREATE must finish writing and the exact current requested
channel must receive service credit before it is bound to the pure flow.
Queued CREATE and local write alone are insufficient. Opening and every native
TX have finite original deadlines. One shared immutable CADET TX owns each actual
attempt, including partial writes. Whole-write and positive-prefix callbacks go
to the original core effect. A native channel destroyed during a partial DATA
write retires logical peer authority but retains the immutable original native
frame, buffer and mapping until MQ write completion or physical loss.
Application data is never replayed on a replacement MQ. A whole native suffix
written after the channel ended remains a RetiredWrite, retaining its actual
positive exposure without becoming a successful peer send.

Received CADET message strings retain their outer delivery receipt. Every
inner official VPN/EXIT frame is processed in order. The original core delivery
becomes eligible only after an whole TUN packet write; all inner frames
must complete before the one outer CADET receive_done is submitted. Processing
credit is distinct from local ACK whole-writing and from remote IP delivery.
Capacity retains original received input under a finite deadline. Permanent
malformation/oversize or exhausted deadlines close the channel, without
inventing success or sending a false processing ACK. Slow channels are scanned
fairly and cannot monopolize another channel's completion.

A later remote channel Destroyed does not discard an earlier complete received
envelope while its original replies wait for TUN capacity or TUN writes.
The exact flow first enters a monotonic peer-ended state: new local packets for
that tuple and new peer prepare/queue/open/bind work are refused, while only the
already-bound received envelope can finish on its original TUN. Buffered peer
output is canceled; admitted immutable native attempts retain their receipts
and deadlines. TUN admission is capped by the original input deadline as well as
the existing TUN-write deadline. Each inner delivery is released only after the
TUN completion; the finished outer receipt is dropped locally, without a
CADET ACK on the ended channel. After held input and that link's native attempt
settle, the original peer-loss cleanup runs. Other links and MQ credit continue.
Local cancellation/Closing, device failure, malformed input and original expiry
still discard held input and preserve the first flow failure. No old flow is
rebound or revived by late credit, receipt or another packet. Whole-MQ source
loss retains its existing immediate failure/cleanup policy. This source change
was not exercised against a TUN, helper, device, socket or peer.

`request_shutdown` stops admission under one original finite grace. Owned cleanup
queries exact original routes and deletes only routes on the original newly
created device; borrowed configurations are only logically released. Existing
partial native attempts retain their physical owners. `close` independently stops
all IPC MQs, the CADET MQ and original TUN without a logical-clock sample;
`close_report` retains each independent native stop and first cleanup error.
Exposed route work whose missing ACK cannot exclude a late effect remains Unknown
even after independent source close. An unexpected old-TUN loss is not repaired
using a new epoch or guessed reused ifindex. `debt()` reports current remaining
flow/buffer/external-provider work, including after explicit late retirement.
A local close report is not a claim that downstream applications processed data
or that unresolved kernel effects or external discovery work quiesced.

Memory is bounded by caller Engine/client pools, the configured flow table,
live received CADET envelopes (one per flow), one raw incoming packet,
one immutable native CADET TX and one immutable TUN TX. No maximum payload vectors
are preallocated for each possible channel. Configured policy storage is borrowed.
Native control/query ports retain their own fixed resource limits.

This package provides a runtime library; it does not add the VPN foreground
process, automatic official REGEX discovery, an EXIT daemon or privileged platform
provisioning permissions. Unsupported platform operations return their actual
native refusal. Fragment/IPsec/active routing exclusions remain those documented
by the shared packet core. No full GNUnet-node interoperability claim follows
from these code paths. The author ran only rustfmt parse/check, not Cargo, tests,
compiler, sockets, TUN, ioctl, address/route changes or private-key reads.

Central integration compiles this library and the optional SDK graph on the
current macOS host. A full metadata table drops and retires only the never-opened
new ingress flow, preserving existing channels. Routing tokens are retained
before later validation. Only an successful same-epoch explicit close of
this coordinator's newly created nonpersistent device can prove owned interface
removal; unexpected loss or a close errno keeps unresolved effects Unknown.
Earlier close errno remains an independent report field. No privileged
TUN/route operation or full coordinator forwarding run has been qualified. The
separate local process DNS/negative-IPC profile does not exercise this coordinator.
Native control close errors remain independent of successful kernel ACK/Get
results. A first close errno and the count of unconfirmed closes stay visible in
Close/debt; admission stops and periodic watchers are not reopened after that
failure. An unknown closed descriptor is never retried.
