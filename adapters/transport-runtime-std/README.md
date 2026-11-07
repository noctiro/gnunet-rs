# TRANSPORT runtime

`gnunet-transport-runtime` composes the existing pure TRANSPORT engine, native IPC
server and public PEERSTORE server over one original fenced Journal. The caller
drives the verified native PILS client, canonical clock subscriptions/deadlines,
bounded admission, discovery and fair IO. It spawns no process Resolver, service
or backend task. The foreground wrapper explicitly polls the process Resolver.

`Runtime::new_service` and `startup::foreground_service` use asynchronous PILS
signing without reading local IKM. A current verified1831 announcement activates
the identity. Each accepted purpose35 effect retains its original engine token,
communicator/route, peer, immutable48byte snapshot, exact PILS identity and original
operation ID. Only the independently verified signature completion can
admit a response, which the pure engine verifies again. Local service pressure
leaves the original unclaimed request; result/output pressure retains the actual
verified result. No accepted input or crypto side effect is replayed.

Queue retirement cancels only its original logical operation. An already copied
partial request drains through the original framed connection; its canceled
reply is ignored. PILS physical loss or identity change first retires the old
TRANSPORT clients, creates and queued outputs, cancels original signing operations,
and then permits a verified replacement epoch. Same-key address announcements
retain healthy clients. Owned native completion/loss notices keep their original
cause and operation even after runtime retirement.

`new_local`/`foreground_local` provide the optional explicitly enabled local-key
capability. Actual verified1831 plus a derived public-key match is required. Original snapshots are signed under the same identity/epoch borrow. No local key
is read by service mode, and an absent key file does not block that mode.

The process entry is `gnunet-transport-node -c official.conf --state-directory
NEW_RUST_STATE [--local-pils-key]`. It binds official TRANSPORT and companion
public PEERSTORE IPC, accepts the common original inherited TRANSPORT sockets and
control stream, and handles SIGINT/SIGTERM. It does not launch PILS, CORE or a
communicator. The state path is a new-format Rust journal, never a C sqlite path. Configured USERNAME and Unix credential matching remain explicit shared-platform
limits. Native communicator foreground and complete Node acceptance remain
required; this runtime is a reusable component, not a complete GNUnet node.

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

Communicator1200/1201 records feed one bounded aggregate owned by original
physical ClientIds. URI sharing survives another owner's delete/EOF, and duplicate
wire address IDs are retained (the normal C add helper transmits0). The shared
HELLO URI parser validates address syntax. Relative lifetime remains an original
refresh hint; the address stays owned until its original delete/physical loss.

The runtime retains a PublicationId, exact PILS identity/epoch and original
OperationId after copying the current aggregate through the existing PILS client. Each local full write settles only that revision. A newer desired set remains dirty. FEED has no application ACK: an observed later mismatch creates a fresh current
snapshot, never replays the retired body. Peer/key retirement cancels original
publication ownership; an unfinished FEED cannot progress on a same-MQ different
peer after observation, so that physical PILS MQ retires before another driver
poll. Original notice delivery precedes reconnect/activation. The new epoch may
explicitly publish its empty/current resource set under a new lease. A single
communicator loss leaves the shared MQ and other communicators healthy.

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

Resource and physical-identity changes cancel original logical signing work
before the next native-client poll. Copied frames keep their original MQ and must
drain or physically retire before pure ownership is released. A managed Unknown
retains its exact transaction and quarantines fresh writes. Public PEERSTORE TX
still drains, while new requests remain retained until recovery. Known outcomes
are consumed before later clock errors, and original native causes remain
available through notices and the storage-failure view.

Graceful draining waits for managed withdrawal and required original FEED writes. Permanent close retires the PILS owner before settling local own effects;
unresolved storage remains owned and can be explicitly recovered without replay
or old socket ACKs. The foreground composition reports original publication
observations. Rust Unix component tests exercise signing, mixed committed/
staged publication, original-lease withdrawal, partial cancellation and shutdown. Fresh official C interoperability and complete Node acceptance remain separate.

`begin_shutdown` stops admission and closes the original TRANSPORT/public
PEERSTORE clients, then retains the same PILS physical/identity epoch and original
partial frames. It drains a fresh empty aggregate behind them in FIFO order. `Progress::Drained` means the final empty set reached the local MQ as a full write;
it does not claim service application or a remote ACK. Original Written notices
are returned before that terminal progress. Dropping a waiting drive future
preserves the drain state. Timeout, clock refusal or original epoch/peer loss
fails the drain and retires owned operations without using a replacement identity. The formal foreground uses a canonical-clock 30-second shutdown budget and does
not repoll its completed shutdown future. `close` remains immediate permanent
retirement, including explicit abandonment of unfinished drain operations.

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
