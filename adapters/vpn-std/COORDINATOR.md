# Native VPN coordinator

`Coordinator::new(Parts { server, cadet, device }, policies, Limits)` composes
caller-owned Engine pools, the local SERVICE, one exclusive CADET client and one
qualified packet device. SERVICE and CADET share the same `RuntimeClock` owner.
Construction allocates a bounded flow table and returns all original owners on
refusal. Call `poll` or `drive` on the existing runtime; no task, thread, Resolver
or discovery connection starts implicitly.

## Native device and routing

`Device` selects native creation, explicit borrowed adoption, or the Unix helper
process boundary. FreeBSD recoverable creation retains its original
[checkpoint owner](../tun-std/RECOVERY.md). Windows adopts an explicitly trusted
[Wintun session](../tun-std/WINDOWS.md).

Newly created interfaces run MTU, address/mask and link operations, DAD, and
prefix-route operations. Readiness requires actual successful native receipts;
route rejection is reconciled through an exact query. Existing devices instead
require matching interface snapshots, exact routes and DAD without mutation.
Borrowed route release is logical and never deletes or claims absence of
another owner's routes. Snapshots and native returns are time-local observations,
not an atomic configuration image or remote reachability proof.

Every control job keeps a finite original deadline. A late or failed route query
cannot grant readiness. Periodic IPv6 monitoring uses separate finite queries;
non-ready state or independent close failure stops admission. Typed `Event`
values preserve actual mutation, query, DAD and cleanup results.

## Packet and peer ownership

TUN input enters `Engine::forward_tun`; the caller's shared slabs retain official
VPN/EXIT frames. Configured exits use explicit bounded policies. External
selection emits `DiscoveryRequest` and requires matching admission, result and
retirement through `discovery_queued`, `select_exit`, `discovery_failed` and
`retire_discovery`. The consuming application owns actual REGEX discovery.
Service flows retain their requested peer and explicit numeric AF profile.

CADET CREATE must finish writing and receive actual current-channel credit before
peer binding. One immutable native transmission retains each admitted frame and
its original deadline, including partial writes. Replacement MQs never replay
application bytes. Completion after channel retirement remains a retired write,
separate from successful peer sending or remote processing.

Each received CADET envelope retains its outer delivery receipt. Inner messages
are processed in order, and a core delivery becomes eligible only after its
whole original TUN packet writes. All inner messages must finish before the one
outer `receive_done`. Capacity waits preserve the original input deadline.
Malformed input, cancellation and expiry close the channel without false credit.
A remote channel close may let already-bound input finish on its original TUN;
local cancellation, device loss or a Closing flow discards it. Old flow authority
never revives through late credit or another packet.

## Session recovery

Windows callers opt into `enable_wintun_recovery` before the first drive. An
unexpected loss returns the ended session's original adapter through
`Event::TunLost`. The coordinator cancels old native observers and routing jobs,
marks old packet effects lost and continues CADET, IPC, discovery and flow
retirement. The caller must consume or release the retained adapter.

`recover_wintun` checks that capability against the exact lost packet epoch.
It waits for old jobs, flows and packets to quiesce, restarts the same native
adapter, and attaches a fresh core packet generation. No name or reused index
can substitute another interface. Refusal identifies whether the caller retains
the adapter, owns a prepared session, or the coordinator owns the installed
session. Configuration is then read and verified through the existing control
state machine before `tun_ready` can succeed.

`refresh_wintun` uses the same retirement and verification workflow with a fresh
packet handle on the exact retained native scope. Original creator lifetime and
owned route debt remain attached; no absence or borrowed ownership is inferred.
Its explicit native stage failures retain the original recovery owner.

Core `rebind_tun_same_interface` transfers the original route scope without
claiming absence. Owned routes use an explicit Verify action and
`route_reverified`; borrowed routes retain borrowed verification. No route
mutation or old packet is replayed, and owned cleanup debt never becomes borrowed
by replacing its packet session.

One outage deadline covers old-debt draining, restart and verification. Rapid
failures reuse it; positive native I/O or one second admitted without an observed
loss ends the episode. The quiet interval is retry policy, not evidence of
packet delivery. The installed service owns bounded retry delays and first/latest
failure diagnostics. Native device qualification remains in the central
[open work](../../IMPLEMENTATION_STATUS.md).

## Physical interface recovery

`reopen_wintun` consumes the shared physical recovery intent. It checks the lost
packet epoch and waits for original routing, flow and packet debt. The native
adapter then provides a sealed old-scope absence observation and reopens only the
selected provider name, GUID and compartment. Old owned scope becomes Absent;
an old borrowed view is released logically. `can_retire_tun` and `retire_tun`
still require original jobs and independent flows/packets to quiesce.

`restore_wintun` additionally permits recreation from an original native creator
after selected-provider NotFound. Borrowed originals never acquire a creation
recipe. Every replacement attaches a fresh core source: reopened devices use
read-only snapshot, route and DAD verification; newly created devices receive
new configuration and route jobs under their own scope. Old deletion authority
and configuration effects do not transfer. Native admission is not readiness.
An absence fact remains available even when a later native reopen fails, and
independent reconciliation errors keep both causes. Refusals identify retained,
provisional and installed ownership explicitly.

Source-bound native control errors and non-ready observer results probe actual
physical absence before process shutdown. Present-interface configuration failure
does not become device loss. Recovery preserves original typed failures as
bounded diagnostics. Retired control timers stop contributing wake deadlines;
live old jobs and the original outage budget keep their independent wakes.
The installed service owns physical retry policy and releases every retained
intent on stop. Native qualification remains in
[open work](../../IMPLEMENTATION_STATUS.md).

## Shutdown and resource bounds

`request_shutdown` stops admission under one original grace. Owned cleanup checks
and deletes only the original owned routes; borrowed views are released without
mutation. `close` independently stops IPC, CADET, control observers and the packet
owner without sampling the logical clock. `close_report`, cleanup errors and
`debt()` keep independent outcomes visible, including late discovery retirement.

Uncertain native effects remain Unknown until actual reconciliation. Successful
close of a newly created nonpersistent Unix device may provide its platform's
removal proof. Wintun's void release API provides no separate kernel-removal
completion, so it cannot settle route debt. Physical close never proves remote
processing, and an unknown close result is not retried on a reused handle.

Memory is bounded by caller Engine/client pools, the fixed flow table, one
received CADET envelope per flow, one raw input packet, one immutable CADET
transmission and one immutable TUN transmission. No maximum payload allocation
is made for every possible channel. Original helper stop and process wait are
separate obligations; helpers are actually reaped by the consuming application.
