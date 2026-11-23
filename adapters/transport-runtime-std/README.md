# TRANSPORT runtime

`gnunet-transport-runtime` composes the existing pure TRANSPORT engine, native IPC
server and public PEERSTORE server over one original fenced Journal. The caller
drives the verified native PILS client, canonical clock subscriptions/deadlines,
bounded admission, discovery and fair IO. It spawns no process Resolver, service
or backend task. The foreground wrapper explicitly polls the process Resolver.

## Public interface

`Runtime::new_service` and `startup::foreground_service` use asynchronous PILS
signing without reading local IKM. A current verified1831 announcement activates
the identity. Each accepted purpose35 effect retains its original engine token,
communicator/route, peer, immutable48byte snapshot, exact PILS identity and original
operation ID. Only the independently verified signature completion can
admit a response, which the pure engine verifies again. Local service pressure
leaves the original unclaimed request; result/output pressure retains the actual
verified result. No accepted input or crypto side effect is replayed.

Queue retirement cancels its original logical operation. An already copied
partial request drains on the original framed connection. Its canceled reply
is ignored. Physical PILS loss retires the TRANSPORT clients, creates and queued
outputs before a replacement epoch can activate. Owned native completion and
loss notices retain their original cause and operation through retirement.

`new_local`/`foreground_local` provide the optional explicitly enabled local-key
capability. Actual verified1831 plus a derived public-key match is required. Original snapshots are signed under the same identity/epoch borrow. No local key
is read by service mode, and an absent key file does not block that mode.

The process entry is `gnunet-transport-node -c official.conf --state-directory
NEW_RUST_STATE [--local-pils-key]`. It binds official TRANSPORT and companion
public PEERSTORE IPC, accepts the original inherited TRANSPORT sockets and
parent control stream, and observes shared native termination subscriptions.
Windows materializes transferred sockets before runtime registration and verifies
configured service identity against the current token. Unix foreground startup
does not switch configured USERNAME. Each endpoint applies its own TCP ACL and
`UNIX_MATCH_UID`/`UNIX_MATCH_GID` policy. New local paths are owner-only unless
GID matching applies, which permits group access. Inherited socket permissions
are retained. Windows refuses Unix credential checks while TCP and unchecked
local endpoints follow their configured access policies. The state path is a
new-format Rust journal, never a C sqlite path. It does not launch PILS, CORE or
a communicator.

The asynchronous foreground readiness callback runs for the first verified
identity activation. The original shutdown future stays polled during notification;
stopping cancels that wait and retires the original runtime. Caller-owned status
outboxes retain their original intent and partial submission across cancellation.
An embedding host gives `foreground_service_with_lifecycle` one stop future and
a nonzero drain budget. `PublicationStart::After` allows TRANSPORT to apply
communicator address changes while FEED waits for both the host signal and
three seconds without an effective address-set change. Each change restarts the
monotonic interval. Stopping before the signal leaves the aggregate HELLO with
PILS. `PublicationStart::Immediate` applies the interval without a host barrier
and is the standalone default. Stop takes precedence over initial setup, listener
polls, readiness polls and the publication signal. A synchronous storage call
must return before stop can be observed. `ForegroundExit` reports whether
readiness completed before retirement.

The normal entry selects `[PILS] PROFILE` before creating the state directory or
opening sockets. The default is `reference029` (`reference-0.29.1` is an alias). `deterministic` (`reference-deterministic`) selects the official conditional
address-derived identity. An optional `[transport-rust] PILS_PROFILE` must agree
with the global choice. `lsd0014-text` is an explicit published textual profile,
not an official interoperability qualification. Unknown or conflicting choices
fail without trying another mode.

That one typed choice reaches the PILS client and its optional local-key
matching, managed HELLO admission and managed GPS3 snapshot reopening. Remote
HELLO discovery is separate: `[transport-rust] HELLO_PROFILE` defaults to the
selected identity profile's HELLO policy and can explicitly select another
remote policy. Public PEERSTORE values remain ordinary opaque records; storing
one does not grant managed provenance or successful discovery verification. `Runtime::new_service`/`new_local` callers set `Limits.pils_profile` and
`Limits.discovery_hello_profile`, and supply a Journal opened with the matching
`peerstore::HelloProfiles`. Inconsistent owners fail before clock subscriptions
or a native connection. `Journal::open` and default limits retain029 behavior. No disk format or unresolved transaction is migrated when selecting a profile.

## Address publication

Communicator1200/1201 records feed one bounded aggregate owned by original
physical ClientIds. URI sharing survives another owner's delete/EOF, and duplicate
wire address IDs are retained (the normal C add helper transmits0). The shared
HELLO URI parser validates address syntax. Relative lifetime remains an original
refresh hint; the address stays owned until its original delete/physical loss.

The runtime retains the publication ID, physical PILS epoch and original
operation ID for each FEED. Each local full write settles its own revision. A
newer desired set remains dirty. FEED has no application ACK. A later mismatch
requests a fresh snapshot of the current resource set. Loss of the physical
PILS epoch retires the original FEED and reconnects the service owners.

A verified peer change on the same PILS epoch fences new local signing. The
runtime settles already-admitted output and withdraws the old managed records
before activating a replacement. Communicator streams and address leases keep
their original owners.
CORE streams reattach under the replacement identity. An already-admitted
unsigned FEED retains its original FIFO position through the change.

Rust PILS/Unix tests cover one-byte partial old FEED followed by a newer
aggregate, another original communicator surviving withdrawal, original FEED loss
before same-key replacement, no old-body replay and independent provider
HELLO/signature observations. A second legitimate PILS client can produce a late
stale set; the aggregator corrects it with a new operation and the current resource
snapshot. These are native lifecycle tests, not C/network or complete Node credit. The separate `own` module provides original-authority signing admission and
immutable managed-projection interfaces. `SignaturePlan` binds a pure offer to
the observed physical PILS epoch. Admission borrows that offer's original80-byte
region, queues through the native client's Exact identity and claims the
pure certificate in the same synchronous step. Its outcome distinguishes a
queued operation, a refused original plan and an admitted operation that still
needs retirement. Same-key metadata updates on the same MQ can retain the offer;
another physical epoch cannot supply its authority.

## Durable projection

`OwnedProjection` copies verified purpose29 values and the common binary HELLO
message within caller limits. Empty HELLO intent is a managed withdrawal. Its
backend must preserve public/foreign records, reserve managed capacity and retain
the original transaction/fence through uncertain commit outcomes. Each copied member retains its original offer and explicit Staged/Committed
provenance. Qualified committed records may be reused for a changed set or
HELLO-only renewal; only staged members need a new pure commit transition. Selection checks live desired leases, authority/peer, current-record expiry and
pending transaction fences before copying. An unknown replacement cannot fall
back to the preceding value. Pure PILS frame/signature tests exercise these
projection cases; four use explicit lifecycle commit inputs. A separate fifth
case composes Journal transactions: refused preparation retains the exact
projection, pre-I/O abort preserves its signatures, mixed current/staged members
commit, and HELLO-only renewal retains both purpose29 values across reopening.

`own_store::JournalBackend` implements `OwnRecordBackend` with the fenced
Journal. Its `ManagedTransaction` retains the original projection and filesystem
transaction together, including the original OS failure through recovery. It
rechecks current-record expiry at its preparation time; new staged cache
forecasts remain unchanged. The journal performs independent signature and full
private/public quota checks. This component test does not activate the runtime
publisher or establish a new native service, C or default Node profile.

`Runtime::poll_step` fairly drives the native own-address publisher alongside
FEED, validation, service IO and timers. One original signing operation is active
at a time; bounded certificate slots and compact claim indices retain staged and
current members without duplicating offer/value metadata. Purpose29 renews on its
own finite deadline; a HELLO-only refresh reuses still-valid committed addresses. The common binary HELLO receipt also has a finite deadline for FOREVER forecasts.
Purpose29 and the PEERSTORE HELLO run independently of the PILS FEED interval.

Resource and physical-identity changes cancel original logical signing work
before the next native-client poll. Copied frames keep their original MQ and must
drain or physically retire before pure ownership is released. A managed Unknown
retains its exact transaction and quarantines fresh writes. Public PEERSTORE TX
still drains, while new requests remain retained until recovery. Known outcomes
are consumed before later clock errors, and original native causes remain
available through notices and the storage-failure view.

## Cancellation and recovery

Graceful draining waits for managed withdrawal and required original FEED writes. Permanent close retires the PILS owner before settling local own effects;
unresolved storage remains owned and can be explicitly recovered without replay
or old socket ACKs. The foreground composition reports original publication
observations. Rust Unix component tests exercise signing, mixed committed/
staged publication, original-lease withdrawal, partial cancellation and shutdown. Fresh official C interoperability and complete Node acceptance remain separate.

`begin_shutdown` closes the original TRANSPORT and public PEERSTORE clients.
The original publisher withdraws its managed records. A fresh empty FEED then
follows any partial original FEED on the same physical PILS epoch. The closing
owner can observe a derived peer change on that connection. It keeps the
original withdrawal owner. `Progress::Drained` records the committed managed
withdrawal and required local full writes. A PILS announcement is an independent
observation. The runtime returns original write notices before its latched
terminal result. Timeout, clock refusal or physical epoch loss before settlement
fails the drain. `close` can end an unfinished drain immediately.

## Resource admission

Address quotas are a local admission policy. A complete ADD that exceeds the
bounded book returns its original `AddressRejection` through pure receive,
native host step and runtime progress, with a cumulative diagnostic counter. The formal CLI reports the refusal without inventing a wire ACK. The frame is
consumed once; its original MQ, accepted addresses and other owners stay usable. A later original DELETE can free capacity for another ADD.

The book publishes its serialized URI-byte upper bound from its native
plus URI accounting. Setup checks the full 72-byte PILS update wrapper and
104-byte HELLO header against the configured frame limit with checked arithmetic,
before subscribing or connecting. Publication/observation scratch derives from
that bound, while external PILS observations retain the previous 64-address and
4096-byte lower bounds. Raising the local metadata limit above 64 is supported;
incompatible frame policies fail setup rather than dropping a healthy shared
runtime after accepting an address. No accepted URI is truncated or omitted.

`own_aggregate` mirrors the original purpose29 port for purpose7 HELLO signing. It retains the original offer and native epoch, admits through the current
Exact PILS identity, and preserves refused versus admitted-needing-retirement
owners and native causes. Its completion handling borrows the original
operation event, and cancellation checks native operation quiescence before pure
retirement. The publisher uses this helper on native PILS. The focused Rust component
checks do not establish official C interoperability or a complete Node profile.
