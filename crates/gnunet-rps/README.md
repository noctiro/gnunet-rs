# gnunet-rps

The `alloc` feature provides a `no_std` GNUnet RPS protocol owner and independent
client samplers. It implements the active v0.29.1 RPS peer messages through
`gnunet-wire`, not a private request-for-N protocol. The default main port hash
and shared-string subgroup KDF belong to the normal host/SDK; the core accepts
exact public hashes and never substitutes another derivation.

Brahms rounds use independently keyed HMAC-SHA512 min-wise history, fresh
unbiased random permutations, 45% push, 45% pull, 10% history, and the actual
push-flooding admission bound. View targets and history sizes are bounded and
can follow NSE estimates through `resize_all`. Round timing has bounded
one-half to three-halves jitter. Public local discovery sends bounded
CHECK_LIVE and PULL_REQUEST frames; local writes do not prove a remote peer is
live. A correctly attributable remote message is needed before sampling/view
qualification. An inbound PUSH does not bypass the view flooding rule.

Each original client sampling request owns independent HMAC elements fed by the
biased stream. Each returned element requires at least two observations
and is used once; a consumed element receives a fresh secret key. Results can
contain repeated peer identities. The currently implemented reference sampler's
probability value is zero, and no statistical or authentication proof is
claimed. Cancellation drops only that original operation. The native SDK must
retain its request identity, deadline, partial results, source loss and
original error; an incomplete sample is not a successful reply.

Group, client and effect handles carry an instance brand and never-reused
serial. Destroying and recreating an identical subgroup hash creates a new
handle. Native channel owners must additionally reject late callbacks for an
old channel before passing group/peer input here. The host must apply
receive credit only after successful core admission, and must return each
admitted original effect's Written, Unsent or Lost disposition. None is
a remote semantic ACK. Lost requests are not silently replayed. Subgroup ports
may be shared by local clients with the same coherent interval and close after
the last selection. One ClosePort action retires the original group port and all
of its channels, without allocating one effect for each known peer. Old admitted actions remain terminally owned after group
or client retirement.

View requests with N > 0 yield N total snapshots including the initial one;
zero means continuous. View/stream cancellation suppresses future and queued
unadmitted replies. There is no wire END/ACK or sampler request ID. Selected
subgroup stream/view context is kept separate. The implementation does not
copy reference bugs where view cancellation becomes infinite, a view update
crosses subgroups, or main-group stream observations enter a restricted
subgroup's sampler. Peer PULL_REPLY lists respect the smaller CADET
application-frame bound, independently of the IPC view limit; an oversized
view supplies a uniformly selected bounded subset.

Limits bound groups, clients, peers, sampler slots, view entries,
original queued/admitted effects and retained allocation capacities. Tables
start empty and grow fallibly. A changed group's state and effects are staged
before semantic commit, and unpublished metadata reservations cannot leave a
partly modified live table after failure. Retained accounting includes secret
samplers, names-free public identity tables, original snapshots, and temporary
round/staging capacities; it is not a process RSS or allocator benchmark. Internal canonical HMAC byte ordering and integer percentage arithmetic are
Rust implementation choices, not new wire profiles. Resource limits may reject
an otherwise valid frame rather than evicting or inventing a result.

Native CADET/SERVICE integration, official-C peer/client
interop, random/HMAC providers, recovery, statistical mixing and memory/
performance behaviour need their own evidence. Source presence is not full
RPS or whole-node acceptance.

Shutdown stops new admission and cancels unadmitted ordinary actions before
reserving close slots. Original admitted actions and already queued retirements
remain owned. Capacity can require draining those originals and retrying the
shutdown call; is_closed does not imply is_quiescent, which also requires no
remaining live group and no original effect debt.

`peer_closing(group,peer)` holds the original ClosePeer barrier until the host
has retired every old channel/input/pending frame for that group/peer,
then completes the original close effect. Discovery and incoming qualification
return WouldBlock during it; history/reply candidates being retired are skipped. The host checks this barrier before old IO and keeps public hints for a new
independent probe after retirement. Old wire channel/epoch handles remain
subject to the native CADET owner; no new peer-generation wire field is added.
