# SERVICE history archive and original layout contract

This extension is production source for the alloc-backed SERVICE owner. It adds
no network command, message type, private RID, GNS/DHT owner, compatibility
migration layer or disk attestation signature. The earlier baseline had selected native/embedded static
compilation receipts; they do not qualify this version6 identity-lineage extension. No new model, crypto, key, storage, native or C execution was used;
recovery and mixed official interoperability remain unqualified.

## Trust and durable receipts

`prepare_archive(maximum)` prepares a bounded zeroizing image; it is not a commit.
`CommittedArchive` is an explicit **trusted provider contract**, like the external
source/entropy ports. Implementing that trait is a trust decision, not a way to
verify arbitrary bytes. Production implements it only on a private owner made
from actual `snapshot-host::Loaded` after Namespace::Messenger qualification and
nonzero generation. It exposes no network-byte constructor for Restored.
`Server::install_history` requires the exact History/Restored private domain pair
and the same configured local profile, before original IO starts.

The new independent Rust namespace uses `.messenger-rust-store`,
`.messenger-rust.lock`, `messenger.snapshot`, `messenger.pending.*`, and a distinct
magic. Existing OIDC/IDENTITY/NAMESTORE/REVOCATION namespaces and foreign-marker
checks are preserved. The shared fenced backend supplies ownership, atomic
replacement/readback and file/directory synchronization. Its checksum
establishes storage integrity; it is not a cryptographic peer-origin proof. No C
history/private-key directory is opened, imported or migrated. A marked root with
missing canonical generation-zero data fails closed; genuinely new empty roots
are actually committed before READY.

One explicit original worker job owns one immutable full image at a time. Native
Queue/commit/cancel/partial-write observations remain separate. New app payload
notifications, peer payload writes and CADET receive_done wait for the actual
current event cut's original worker receipt. One image freezes new retained
business mutations while the worker owns its bytes; original IO cursors,
already queued writes, PILS results and physical retirement still progress.
Unknown disk outcomes latch failure rather than replaying a mutation. After all
network owners physically stop, final serialization/commit/drain/join uses no
logical clock. Filesystem fsync/join has no fictitious finite cancel deadline.
A canceled foreground future can join an already admitted original job in Drop;
it cannot claim an unsubmitted final cut was committed.

## Retained facts and recovery

The bounded private image retains original authenticated raw frames, their
canonical hash, original author/public snapshot, declared layouts, source
allocation observations, original receive metadata, sequence/parent/reference
links, semantic/deletion facts, first-write missing-hash epoch aliases,
frontier/room state, contacts, session lineage and exact bounds, immutable epoch
membership data, and peer route candidates. TALK/SUBSCRIPTION payload/epoch
associations and all derived subscription intervals are excluded as described
below. Raw message
and owned textual payload allocations are zeroizing. No current Source,
operation/native job, current membership binding, private recipient key, AEAD
key, ephemeral scalar, physical channel or live IO authority is serialized.
Unauthenticated deferred packets are not promoted to durable accepted facts.

Loading checks exact format/trailing bounds and configured table/payload caps,
slot generations and references, retained allocation charges, session
successor chains/bounds, both retained-message and epoch DAGs, immutable epoch
membership reconstruction, alias completeness and allowed metadata. Retained raw
frames are re-decoded under their own explicit body/padding layout; their actual
canonical hashes, headers/parents and member/peer signatures are checked. A
Deleted row with no raw bytes is restored only as a trusted durable acceptance
fact, with structural/ownership checks, never described as a new signature check.
Temporary adjacency/Kahn workspace is linear in the configured node/epoch slot
bound and uses fallible allocations; no repeated full-graph walk per vertex is
used for cycle detection. Persistent retained charges include the new per-node,
per-session and per-peer metadata and lazy alias capacity.

All loaded nodes have `MessageOrigin::Archived(ArchivedFact)` and no live Source;
`ServiceAttribution.source` is None for them. Old scopes, operations and tokens
cannot be adopted by the new unique Core instance. Recovery does not replay
old semantic handlers to mint current membership or key capabilities. Real new
parents may complete historical graph links and wake dependants without
manufacturing old network input. A still-pending archived authentic message can
only be reconsidered after a new original source supplies its bytes and
passes the signature/source checks again; durable Rejected/Deleted/applied
facts are not reset by such replay.

Historical Active terminal lineages retain their old qualification separately
from current state. An new source must supply a matching sender/id/key
signature within that lineage's retained scope before continuation rebinds the
member. Missing parents defer that operation and remain genuine recovery targets.
Original timestamps remain exact inputs to expiry/subscription checks;
there is no invented monotonic-timestamp admission fence that would reject
legitimate out-of-order or clock-rollback continuation. A message waiting for
its missing original parent retains the opportunity for later activation.
Completed/LEAVE/KEY predecessor lineages cannot revive through an
ordinary packet. A genuinely new JOIN has its own signature/admission path;
no JOIN is synthesized on load. Local OPEN may propose a retained ID, but that
assignment is not membership. Actual active current lineage read rights include
only the union of its own historical sequence intervals, never an unrelated
rejoin with the same public key. Historical Closing ancestry can finish its original bounds
without making a current member; historical revocation flags remain revoked.
Historical PEER candidates may seed a fresh
connection attempt; they remain unannounced and grant no source,
reachability or channel-ready authority. The private image retains a bounded,
unique set of own signer identities admitted only through local
`configure_local_peer`/`rotate_local_peer` calls. It validates historical
ServiceSigner provenance against that set and each message's original authenticated
peer. The last historical local peer is diagnostic metadata, not a master-key
proof or a requirement on a new PILS identity. Restoring the owned store
does not configure any current peer or signer lease. A fresh PILS
observation grants current write authority separately; a remote PEER never adds
own-signer lineage or supplies that authority.

Healthy identity rotation first requires every current ServiceSigner operation,
including a verified signature awaiting its local commit, to settle. It
also refuses outstanding old-identity signing work attached to other sources.
The transition prechecks every room's current signer lease and the bounded
lineage allocation, including replacement growth peak. It then changes the
current peer and signer roles together without allocating, stopping sources,
changing their brands, renewing deadlines or changing historical signed bytes.
The provider remains responsible for all old native operation debt.

## Third-party original producers

`OriginalLayout` separates the original signed body grammar and optional expected
original signer from the immediate envelope padding encoder. `BodyLayout`
is either Explicit(Profile) or the proven profile-independent non-FILE SERVICE
grammar. Portable does not guess the original machine endian or interpret the
application's encrypted native-order group identifier. FILE NAME_MAX is always
explicit. `Message::decode_with_profiles` keeps each original immutable input;
`MessageRef` retains layout, source observation and original signer metadata.

The native bounded Policy selects an exact room/hash/signer override, retained
authenticated original metadata, or a declared original signing key. It does not
substitute the relay identity for every forwarded author. Signature-specific
ambiguous declarations are resolved only by verification and still checked
again by Core. Current relay incoming/outgoing padding and room-port word order
are independent explicit declarations. Only unsigned outer padding is repacked;
original tagged signature, header/body bytes and canonical hash remain intact.

There is no official profile-negotiation wire field. An unchanged C application
has its own FILE NAME_MAX interpretation. The separate high-level client's fully
mixed-producer private/epoch decryption and identifier API has independent
`ClientLayout`/`ShortLayout` metadata and profiled HPKE/AEAD entry points.
Raw identifiers retain their original creator order across later senders/epochs;
a later sender's native ABI cannot reinterpret them. This adds no wire field.
The private owned-history image retains these optional declarations and the
identifier-origin field. Its `GMSHIS06` layout also omits the historical
process-instance label as described below, and rejects earlier image bodies. It
is not a C store importer or a compatibility migration. No store/recovery path was
executed while preparing this source extension. Service mode forwards signed
PRIVATE/SECRET/group data opaquely rather than imposing client recipient/MAC
success on daemon routing. It never invents the missing AUTHORIZATION MAC.

## Bounds

Snapshots are bounded full-image microbatches, not an append-only WAL. No implicit
history eviction or unbounded disk growth is introduced; reaching fixed room,
message, epoch, history-image or policy capacities gives an explicit failure.
The filesystem parent must exist. Native network grace is finite, while actual
filesystem sync/join may block in the OS. Live instance domains use an
explicit caller-owned borrow without an atomic or allocation requirement.
None of this is a complete-node or official mixed-node runtime
acceptance claim. Live transport replay, provider jobs, current crypto keys and
application plaintext are intentionally re-established by their owners,
not restored as successful outstanding work from an old process.

## Caller-owned live domain and version 5

`Core::recover_archive(&mut instance, ...)` borrows a fresh caller-owned live
`Instance`. The validated recovered Core uses that current domain; no persisted
metadata becomes a live Source or provider capability. `Recovered` retains the
borrow until its Core and live handles are no longer used.

The private owned-store image starts with `GMSHIS06`. Historical
`SourceObservation` contains only original room/source slot generations and role;
it contains no process-global ID, memory pointer or live domain. These local
coordinates are not globally unique across archives. The previous private image
layout is rejected by the version check. No compatibility migration, silent
reset, file deletion or replacement history is performed. The
original store error and file remain for the owner to report. Official GNUnet
wire formats, signatures and encrypted record formats are unchanged.

## Transient discourse projection and cleanup (source-only forward)

The SERVICE owner already batches mutation events into one original
snapshot worker and flushes after network retirement. This forward changes that
image's content, not the worker/commit/receipt/clock or scheduling algorithm.
In the fixed C implementation, both TALK and SUBSCRIPTION are discourse records;
they occupy the in-memory discourse map rather than durable message storage.
The subsequent official HEAD excludes their hash-to-epoch metadata from durable
epoch output and removes it when discourse data is cleaned. A Rust EpochRow is
a different concept: immutable JOIN/LEAVE/MERGE membership state. Those rows and
ordinary signed raw frames, hashes, profile declarations, session bounds, source
observations and first-write aliases remain under their original checks.

Version5 prepares a source-free Deleted historical graph anchor for authenticated
TALK/SUBSCRIPTION: original hash, parents, sequence, timestamp and historical auth
lineage are retained, but raw/plain data, discourse ID, node/receive epoch, input
context/sender fields, transient layout/identifier hints and pending semantics
are not serialized. Its hash-to-epoch alias is omitted. This is trusted historical
acceptance under the existing committed-provider contract, not a new signature
result or payload from a live Source. Original non-transient children retain
their exact parent hashes and own epoch facts; session completion/frontier/DAG
indices therefore survive instead of being broken by coarse row deletion.
All subscription interval/renewal/audience state is omitted and recovery refuses
its presence, so an old process cannot restore a current discourse subscription.

A zero anchor epoch grants no right. Where a later metadata lookup refers directly
to a retired discourse, a bounded previous-link walk resolves an retained
non-transient first-write association or an unresolved original hash. It constructs
no membership, epoch row, source or provider success. New ordinary children can
retain their own true association without rebuilding the retired discourse alias.
Deleted anchor bytes cannot be replayed into a new payload or semantics; ordinary
archive-source and original signature/admission gates remain in place.

Live cleanup handles both discourse kinds. It erases their owned zeroizing
payload/context/epoch metadata and deletes exactly that alias with an allocation-
free bounded backshift that preserves colliding first-write entries and count.
An original mutation event marks the resulting cut dirty for the existing history
worker. No fixed-array shrink or live table index reuse is introduced. A later
child cannot silently reinsert an alias for a known retired discourse.

The format is `GMSHIS06` and prior versions are explicitly refused; there is no
migration, empty-library fallback, store reset or overwrite on failed recovery.
Native History propagates archive failure before READY and before accepting the
restored owner. The existing committed data remains the original store's data.
Recovery strictly checks the scrubbed anchor projection and ordinary retained raw
frames/signatures under the same trusted-boundary contract.

Pure archive tests use synthetic trusted checkpoint metadata for projection,
readback, discourse anchors, membership epochs, cleanup and collision-cluster
deletion. Graph completion drives `Core.advance` without adding old-message
semantics. These fixtures are separate from authenticated checkpoint recovery.
