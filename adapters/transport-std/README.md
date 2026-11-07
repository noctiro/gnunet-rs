# Native Rust TRANSPORT host

`Server` owns accepted IPC sockets, exact-frame receive buffers, retained
partial-write cursors and fair connection directions around `gnunet-transport`. Dropping a wait future preserves these owners. The existing canonical listener
boundary is reused; the host does not depend on a C TRANSPORT backend.

`peerstore::Journal` owns the process file lock and retains the original
parent-directory and lock inodes. A known commit requires file fsync, rename,
parent fsync, exact bytes/inode readback and the same physical authority. Unknown
keeps the original candidate/predecessor and blocks fresh writes and timestamp
reservations until explicit recovery under that fence. The synchronous public
STORE wrapper preserves its original unknown transaction; public IPC supervision
still treats that uncertainty as fatal. A prepared original can be aborted only
before publication I/O. No detached writer can publish after quiescence.

The private GPS3 snapshot records an origin partition, generation and durable
timestamp highwater; the public GNUnet STORE/iterator frames stay ordinary. There
is no old Rust disk-format migration layer. Managed capacity is reserved from
public traffic before publication. Full input frame, origin and cumulative quota
bounds precede parsing, hashing, scratch allocation or copying. Managed projection
replacement preserves public/foreign rows, including equal namespaces. Empty
managed HELLO intent removes only managed rows. Generic public REPLACE retains
its official matching-key semantics across origins. Disk limits are4096 records
and4MiB, with original/current/prepared buffers retaining additional RAM.

The owner, private codec, physical fence/I/O and component tests are separate
modules. Timestamp reservations use this same writer; only known committed ranges
may be issued, with unused values skipped on reopening. Iterator snapshots cannot
observe their own replacement and self-feed. TCP replay values cannot regress. The managed component has temporary-file success/error/recovery tests;
new-code cross-process/crash/fsync-failure profiles and full native publisher
acceptance remain separate. The public server still implements the replay
STORE/iterator subset rather than the complete PEERSTORE service.

Normal composition uses the separate [TRANSPORT service](../../apps/gnunet-service-transport/README.md)
and standard communicator programs. Their process owners retain the PILS,
clock, storage and shutdown boundaries; this adapter supplies the shared server
ports rather than another embedded aggregate-node executable.

Journal fencing covers one canonical state-directory namespace. Its reserved
metadata filename and native inode identity cannot be accepted as a data file. Random exclusive-create temporary files never truncate an existing committed
file, including legitimate data names ending in `.new` or `.lock`; metadata and
temporary names are reserved. The stable fence inode is never renamed.

Physical framing uses runtime `framing::Framed<()>`. Outgoing Engine-owned Vecs
move directly into secure immutable frame storage; no second body copy is made. TRANSPORT reclaims its logical remaining-wire budget after every write. This is not an exact RSS bound: a written prefix, caller Vec capacity, RX storage,
FIFO metadata and an original pending effect can still retain allocations. FIFO metadata growth is fallible, unlike the old preallocated packed byte buffer. The Server retains the exact popped effect and returns its allocation error for
explicit caller policy. Queue-budget exhaustion retains the existing slow-client
close policy; it is distinct from metadata Capacity. Matching close/shutdown wipes
any pending bytes. PEERSTORE retains committed reply bodies before queue admission;
a full queue stops that client's next request while its original TX drains. It
never repeats a STORE/iteration effect to regenerate a reply. Other allocation
errors remain explicit with the original pending reply retained until retry or
shutdown. Started FIFO tails remain on their original MQ. Only wholly unwritten
frames can be removed. A terminal I/O error retires that whole physical owner.

The untracked stream wrapper may offer up to64 immutable suffixes to one native
vectored write, with no cross-frame body copy. Every successful write poll still
means one positive native operation; no virtual operation receipts are
created. Typed origin users use the separate tagged one-frame path and report
original positive progress before reading subsequent service responses. Clock
preflight and fair direction scheduling remain in the domain host.

Known-queue numeric UPDATE1222 refusal is observable as
`Step::InputRejected(QueueRejection)` carrying the original physical client,
peer, qid and error. It does not close that communicator or mint an ACK. The
complete input frame's storage is released after decoding; no business delivery
is inferred. Structural/role errors retain the existing owner-isolation policy. Callers must handle the returned event explicitly rather than hide it as progress.

The engine also accepts official unreliable/unknown communicator characteristics
and retains remote acknowledgement/retry ownership independently of local native
callbacks. Five-second local retirement and four-minute original retention are
explicit Rust resource policies. The process owner must settle retained remote
records at shutdown. Required carrier interoperability keeps its own current
normal-program evidence.

`Step::WorkDeferred` preserves an already accepted input and its original unsent
job after TX preflight refuses local resources. The host exposes the exact cause,
keeps the shared communicator and consumes RX storage once. Scheduled ticks and
later peer inputs skip this blocked original; `Server::retry_deferred` is an
explicit caller resource-policy action. It does not redispatch a FLOW, additive
grant or local completion. Diagnostic IDs grant no protocol authority. A real
Unix regression injects one entropy refusal with two peers on one communicator,
checks ordinary ticks do not retry it, advances the healthy peer in both
directions, then explicitly retries and reconstructs the original from offset0
with one CORE credit. Pre-input clock refusal happens before native IO. Other
local handler/storage/framing errors return their cause without treating it as
malformed peer evidence; they are not promised transparent retry and accepted
input must never be replayed. The existing retained pending-output Capacity
boundary remains separate and explicit.

Application address discovery is a separate bounded source port. `discover`
retains its original query lease on a source refusal and checks engine time
before invoking the source. `Journal` supplies exact-peer, nonexpired URL/HELLO
candidates;029 HELLO signatures authenticate metadata only. Sources grant no
identity or delivery authority. Callers must fairly drive discovery with IO and
timers. The sustained bidirectional test carrier can optionally expose its real
PEERSTORE Unix listener so independent public C clients can publish candidates.

The ordinary SERVICE accepts the active public TRANSPORT monitor and link
listing requests1250/1255. Standard requests have exact fixed40-byte framing,
YES/NO flags and original physical ClientId ownership. Monitor1251 records
project neighbour queues, addresses, network/status, validation times and
admitted pending attempts. One-shot1252 and link-list1257 are queued only after
that original peer-filtered enumeration has been fully prepared; they are not
whole-write or delivery receipts. Continuous monitoring retains each captured
update in its original bounded FIFO. A full/failed observation owner is physically
closed with `Step::MonitorRetired` and its original cause; no gap protocol or
silent snapshot replacement is introduced. Ordinary Reporter retains owner/cause.

Monitoring adds no Resolver, worker, timer or network route. Snapshot preparation
runs once per state-changing Engine turn, not once per popped output frame. Each
original subscriber is bounded to max(queues,peers)+1 pending frames and
max(queues,peers)*149+control_bytes retained bytes; the current and next global queue snapshots each use
the same byte ceiling, as does an initial prepared response batch. Building one
batch may temporarily hold one additional standard wire frame before the ceiling
check. Prefix workspace is independently bounded by control_bytes and the wire
frame limit. Retirement metadata shares the existing physical
client count until the ordinary step consumes its retirement observation. The same head-write/source bounds and native-first close rules apply.

A DV-enabled NativeObserver reads the same Actor's route, matching RouteLife
and current Bridge path/source. It supplies read-only link observations on the
original request; it does not install a route or announce CORE connectivity. A current installed Bridge path determines established DV visibility. Distance
matches active C's intermediate-vector count (Actor path.len()-2). Communicator
names/queue count come from direct queues to that path's first hop, with
whole-prefix deduplication. Source retirement invalidates and closes original
DV-bound listing MQs before old source IO; retained metadata is not rebound. Normal non-DV owners enumerate their direct state. An active DV source
without its observer refuses explicitly instead of returning a false empty
complete DV listing.

Public link fields describe this implementation's Flow/credit/jobs. No
separate C-style Flow retransmission task is used, so its running-task counter
is0; unmeasured Flow/DV RTT is FOREVER. Missing per-target Flow state has zero
state values, not a fabricated default grant. Rust does not copy C's private
scheduler/counter layouts. The fixed C server misses MONITOR_END and fails to
apply its peer filter during initial queue enumeration, while its public API and
client require both. Rust follows that public completion/selection contract;
the reference differences remain explicit.

The separate native caller is
`gnunet_transport_application_host::observation`, also available as
`gnunet::transport_observation` with `official-transport-observation`. It owns
one EndpointSource/Channel and one original standard40-byte query, on the
caller's clock/Resolver. UNIX and configured/live TCP selection reuse the
existing CLIENT path. Typed rows own their original complete frame and branded
epoch. Queue admission, START whole-write, row and matching END
are separate observations. The initial bound covers connect/whole START; an idle
continuous monitor needs no invented ACK or first row. Every partial frame and
the overall source retain independent original native/canonical targets.

EOF, malformed/wrong-kind input, clock/provider failure, cancellation and expiry
physically close the original source and return Loss facts. They never
become END or an empty complete listing. Read-only restart is explicit, obtains
a fresh epoch/START, resets per-epoch counts and retains the original overall
hard/expiry. It cannot join snapshots from different epochs or restart an actual
completed one-shot. A clock-free native guard remains callable while a bounded
output sink is blocked. Source input waits and write cursors remain inside the
Client when an awaiting future is canceled. Valid extra rows from fixed C's
initial-peer-filter omission are locally filtered without false selected-row
credit; fixed C's missing MONITOR_END still produces honest incomplete loss at
the original bound.

## Original native retirement observations

The Server retains the first unread selected native retirement, with a bounded
count of further coalesced retirements. It records the deadline or local
policy branch, original client/packet/transfer, native targets, retained output
extent and independent Engine-close error. No payload is copied. Taking this
observation consumes diagnostic metadata only; it cannot cancel work, reopen a
source or establish remote delivery. Observation capacity never changes the
existing physical-retirement decision. The process owner reports these facts
through its explicit observer, including when an original operation fails.

Complete direct DV input can move from the native head into the existing bounded
Engine inbox when the Actor cannot admit it immediately. The first-byte native
target, captured canonical target and original source accompany that input. This
lets later SEND_ACK control frames on the same communicator MQ make progress;
it does not return incoming flow credit or authenticate the retained body. The
ordinary borrowed-frame admission remains available when the Actor has capacity. Retiring sources cannot hand their retained input to a replacement actor.

Pre-native parent cancellation first excludes Framed tags and all recorded
native/packet facts, then locates every original chunk in Engine output or the
same Server staging slot. One synchronous transaction removes those chunks and
the original Job/attempt debt, restores only original route reservations, and
reports Unsent. A retired logical Job with all chunks already settled
and incomplete original-byte coverage reports Incomplete. Any known local outcome
preserves the shared MQ once the original Job ended and no parent SendRow remains;
Written alone never ends a still-active remote-ACK/retry Job. At the unchanged
deadline, cancellation stops that original Job before rechecking local
completion. Native, partial, uncertain or unlocated chunks retain the original
physical-retirement rule. `NativeGuardEvent` distinguishes TransferUnsent,
TransferSettled with its exact local outcome, and SourceRetired. Historical
FLOW consumption is retained and corrected by the loss/FLOW exchange; no
old snapshot is rewritten and no received-data or delivery credit is invented.

`NativeObserver::ready` returns `NativeAdmission::Admit`, `Deferred` or `Retiring`. Only the observer's Admit permits the original native enqueue. Deferred
retains the same immutable frame and targets for other permitted control work;
Retiring yields immediately to the same parent's retirement transaction before
further native IO. The observer-free port returns Deferred.

An asynchronous authenticated-address STORE keeps its original domain-output
FIFO barrier, but no longer suspends every existing physical communicator. The host continues bounded native write/read rotation and consumes only eligible
registered-communicator maintenance messages through the Engine's no-pump port. CORE/application/monitor business heads and new listener admission stay behind
that barrier. Maintenance output capacity is preflighted before consuming the
same original frame; it cannot become an unbounded second business queue. Original input/timer results remain retained independently. `Retiring` admission
immediately yields back to the Bridge cancellation transaction before old-source
IO; `Deferred` only waits. This does not claim to remove every bidirectional
application credit dependency or to qualify a normal multi-node result.

Accepted application MQs need no INIT or first-frame declaration. A completely
idle connection remains bounded by the original finite source lease and client
cap. Positive partial input starts its own fixed deadline; further byte progress
does not renew it. Output-head, DV retirement and unknown-mutation facts retain
their independent original bounds.
