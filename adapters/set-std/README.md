# Generic SET native SERVICE owner

`gnunet-set-host` joins the distinct old generic SET `gnunet-set` owner to actual
standard SERVICE client sockets and one original `gnunet-cadet-host::Client`. The foreground supplies the branded pure and native instances, canonical
EndpointSource/RuntimeClock, configured listeners, service options and Unix ACL. It polls this owner directly; there are no hidden tasks, private RPCs or workers.

`Server::new(core, cadet, limits, options, unix)` retains those owners. `clock`, `report`, `poll`, cancellation-safe `drive`, `request_shutdown` and
clock-free `shutdown` follow the ordinary native SERVICE pattern. `initialized`
and `ready` mean the CADET MQ is attached; generic SET has no fixed global
port. Each LISTEN creates its own standard application port. Readiness is
not a SET processing receipt, remote acceptance, delivery or durability claim.

The pure core selects an explicit old SET native ABI. The host copies each
already encoded immutable core response/peer frame unchanged to its original
bounded sink. It does not use SETI/SETU envelopes or rewrite the declared peer
application ID. Incoming authority is the typed CADET Port and sender;
normal C union/intersection operation requests may leave the payload application
ID zero. Native channel creation alone creates no Incoming capability; a real
valid operation request must first be admitted by the core.

An ACCEPT applies AdoptPeer to that same Channel. Adoption waits until
all old input messages have been consumed and old pending sends have settled. The fully consumed initial request retains receive credit until adoption,
then its receive_done still refers to the original Channel and delivery. The mapping changes before the original local Written completion
is reported; a dedicated retained applied slot prevents losing that fact if pure
completion refuses. No unconsumed old packet is relabeled as a new operation. Adoption clears the listener association. Later ClosePort retires only unaccepted
incoming channels and preserves accepted operation channels. Parallel operations
with the same peer/application retain distinct branded channels and owner tokens.

Every native frame has its original immutable EffectId, whole/partial exposure,
fixed hard deadline and terminal disposition. Client close first retires
its physical IO, then accounts original output, then detaches the pure client. Channel destruction/loss settles original pending and queued sends before
peer_lost; shared CADET MQ EOF/Protocol(Closed) is an unavailable source, not a
particular peer's normal channel close. Original causes remain in CadetLost. All original channel/close causes are classified before pending Destroy hooks;
an already observed whole Destroy retains its local retirement fact;
ClosePeer and listener aggregation share one physical retirement. Automatic desired-port restoration is owned by the existing native CADET client. Canceled ports retire from its desired set before another epoch can reannounce
them; a partial unidentifiable restored announcement requires retiring its actual
MQ. Old exposed actions are never replayed. A later independent user operation
can open a new channel; a transport reconnect cannot make the old one successful.

Configured clients/ports/channels and peer/output queues are finite and fallibly
allocated. Output pressure retains the original unadmitted core action while the
oldest admitted write keeps its hard deadline. Count limits do not promise that
all maxima fit simultaneously. Peer queue bytes count payload capacity;
there is additionally at most one native pending frame, native bounded receive
buffers, fixed metadata and the independently bounded pure core. Temporary copy
space for admission is bounded by one frame. These are resource bounds,
not an RSS or performance measurement. NativePorts supplies original getrandom
errors and bounded shared complete-member zlib compression; no entropy fallback
or foreign C runtime is used.

The native effect class checks at most64 selector work units and tries at most
one action per poll. A blocked unrelated client does not block other
semantic heads. The pure selector preserves original client/channel/adoption/
port retirement dependencies, including admitted leases. Partial selection is
CPU activity only; it grants no effect receipt. A completed blocked pass resets
its cursor and waits for IO or pure progress, preventing a busy wrap.

The CPU class performs one original core step per native turn. A false step
only describes its selected round-robin operation/client slots. Before waiting,
the host completes a finite pass over all current slots; continuing that pass
is bookkeeping Activity, not a write or SET result. A true core step, actual
input or original settlement restarts the pass. Effect-selection bookkeeping
alone does not restart it. The first classification of a held peer message can
retain algorithm input while returning NotReady; that one attempt schedules the
new pass even if the CPU class already ran in the same poll. Repeated attempts
keep the original held_now and cannot renew the pass. This adds no worker,
self-wake loop, clock target or additional core work within one CPU-class turn.

First-byte client/peer classification and each immutable native write retain
fixed physical phase bounds. A held complete input freezes its original logical
origin through backpressure. Pure tick advances deadlines and a separate
fair progress class performs bounded algorithm work. Soft shutdown stops new
admission and waits for existing app sources within the foreground's own grace;
immediate shutdown independently attempts every original owner. Stopped/drained
requires physical source retirement, original terminal debt settlement and
pure quiescence. Cleanup errors remain observable.

Pure controls do not establish generic SET peer interoperability or native
service qualification. See the [release criteria](../../spec/gnunet/external/RELEASE.md).

A fully received DATA packet remains bound to its original adopted operation
when a later CADET `Destroyed` event arrives. The host classifies those
held messages before the original pure `peer_lost` callback; pending input keeps
its first cursor, owner, `held_now` and native hard under core backpressure. The
gone channel receives no new ACK/send. Once held input is consumed, only its
local packet is released, then existing original native transmit terminals and
pure retirement settle in their original order. Other shared MQ credits and
channels continue to progress. This preserves legal terminal messages such as
FullDone without turning EOF, source loss or a premature close into success.

Local cancellation, errors, expiry, ClosePeer and listener closure discard
held input before any later Destroyed event can arrive. A gone unknown/incoming
source cannot create a fresh offer or accept capability. Closing channels do
not accept new DATA. The existing input/first-byte hard remains a bound after
retirement; no clock target or input admission time is renewed.

A distinct local-closing fact prevents a remote Destroyed event from masquerading
as local cancellation of an original pending native transmit. An already
admitted suffix retains its original hard and terminal. A later
CADET Written callback still settles that same original local IPC/output debt;
it is not a peer receipt or protocol ACK. Legal FullDone and physical retirement
remain independent inputs to the existing generic SET completion rules.
