# SERVICE history archive and original layout contract

The service archive stores local recovery state. Its format is independent of
the GNUnet wire protocol and does not import upstream C data directories.

## Trust and durable receipts

`prepare_archive_into(output)` writes a bounded checkpoint to caller storage.
Its guard exposes the written prefix and erases it on drop. With `alloc`,
`prepare_archive(maximum)` returns the same format in an owned zeroizing buffer.
The storage port commits the prepared bytes separately.

`CommittedArchive` is a trusted storage provider contract. It exposes the exact
bytes and nonzero generation read from an already committed service record.
The desktop adapter constructs its provider from a `snapshot-host::Loaded`
qualified for `Namespace::Messenger`. Network ingress cannot supply this
capability.
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

Within a room, each accepted message has a unique nonzero sequence that stays
unchanged across checkpoints. Byte offsets and traversal indices belong to one
borrowed checkpoint. Local GET and signed SERVICE REQUEST share the traversal
of authenticated deletion links. GET applies the requesting client's current
member lineage; REQUEST applies the session that signed the request. Current
room records take precedence, including a deletion of a previously readable
original. An original read only from the checkpoint has no live source or
member capability.

Detached graph pages use the same canonical message rows. Each page is bound
to its storage namespace, local peer, room generation and emission. The
directory pins the exact working checkpoint and rejects duplicate hashes or
acceptance sequences across pages and working rows. Pages hold settled public
`TEXT`, `FILE` and `REQUEST` originals and their final tombstones, as well as applied
`PEER`, `CONNECTION` and `MISS` originals. Peer controls retain their original
peer signer and cannot become tombstones. Unfinished application and pending
deletion timers remain working state. A resumable session completion walk
restarts from its signed closing hash if a new directory changes its coordinates.

A live REQUEST may read the same signed target after cutover. Core checks its
original source and message slot generations against the committed row
and uses the original signing session for history permissions. Recovery does
not recreate an in-flight request from that row.

Loading checks exact format/trailing bounds and configured table/payload caps,
slot generations and references, retained allocation charges, session
successor chains/bounds, both retained-message and epoch DAGs, immutable epoch
membership reconstruction, alias completeness and allowed metadata. Retained raw
frames are re-decoded under their own explicit body/padding layout; their actual
canonical hashes, headers/parents and member/peer signatures are checked. A
Deleted row with no raw bytes is restored only as a trusted durable acceptance
fact, with structural/ownership checks, never described as a new signature check.
Temporary adjacency and traversal workspace is linear in the configured
node or epoch slot bound and is reused across rooms. The service buffer
constructor requires caller-owned graph cells; heap recovery allocates its
graph workspace fallibly. Retained charges include room metadata, epoch alias
capacity and nested epoch storage.

`Core::recover_archive_with_service_buffers` uses the same `ServiceBuffers`
layout as `Core::with_service_buffers`. `ServiceRoomStorage` also backs the six
per-room tables, four processing collections, epoch alias buckets and epoch
membership snapshots. The original room slot selects its partition. Contacts,
their names and historical signers use the supplied `ServiceTables`, while the
event queue and work pool start empty.
Core charges the inline room slots, partition directory, `ServiceTables` and
KEY ancestry workspace at construction, and each room's partition when the
room is restored. Size the separate graph validation scratch with
`ArchiveGraphCell::required_cells`. This path needs no allocator. The hosted
image does not carry client group, confirmation or nonce state; the two reserved
counts must be zero.

With `alloc`, `recover_archive_with_frame_pool` borrows the signed-frame pool
and frame workspace; `recover_archive_with_fixed_history` also uses
[caller-owned room partitions](README.md#state-and-ownership) for the message
table, index and ready queue. Each archived room index selects its original
partition, including when earlier slots are vacant.

The paged service path verifies original frames in the committed image during
recovery. Eligible complete, applied originals retain a byte range and an exact
digest instead of a frame slot. Graph records keep their independent capacity
limit. To rewrite a paged archive, the storage owner supplies the verified
original bytes from the previous revision and installs new ranges after
confirming the new commit.

For media with a page directory, `GraphDetachment` prepares both the graph
page and a working checkpoint that omits the selected rows. The storage owner
commits both under one root before settling the detachment and releasing the
working slots. Rooted recovery validates the
joined graph using `ArchiveGraphCell::required_cells_with_detached`; it leaves
detached rows on their pages. A detached deletion updates the same rooted
selection and preserves the acceptance sequence and parent links.

All recovery paths use the same `GMSHIS06` encoding and validation. Failed
recovery drops staged state without granting live source or signer authority.

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
from current state. A new source must supply a matching sender/id/key
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
The transition prechecks every room's current signer lease and signer table
capacity, including peak memory when a heap-backed table grows. It then changes
the current peer and signer roles together without allocating, stopping sources,
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
identifier-origin field. Service mode forwards signed PRIVATE/SECRET/group data
opaquely. Client key recovery follows the
[AUTHORIZATION contract](../gnunet-messenger/README.md#authorization-constraint).

## Bounds

Snapshots are bounded full-image microbatches, not an append-only WAL. No implicit
history eviction or unbounded disk growth is introduced; reaching fixed room,
message, epoch, history-image or policy capacities gives an explicit failure.
The filesystem parent must exist. Native network grace is finite, while actual
filesystem sync/join may block in the OS. Live instance domains use an
explicit caller-owned borrow without an atomic or allocation requirement.
Live transport replay, provider jobs, current crypto keys and
application plaintext are intentionally re-established by their owners,
not restored as successful outstanding work from an old process.

## Live instance and image format

Recovery borrows a fresh caller-owned `Instance`. The recovered Core uses that
domain; persisted metadata grants no live Source or provider capability.
`Recovered` retains the borrow until its Core and live handles are no longer
used.

The private owned-store image starts with `GMSHIS06`. Historical
`SourceObservation` contains only original room/source slot generations and role;
it contains no process-global ID, memory pointer or live domain. These local
coordinates are not globally unique across archives. The previous private image
layout is rejected by the version check. No compatibility migration, silent
reset, file deletion or replacement history is performed. The
original store error and file remain for the owner to report. Official GNUnet
wire formats, signatures and encrypted record formats are unchanged.

## Transient discourse projection and cleanup

The SERVICE owner batches mutation events into one original snapshot worker and
flushes after network retirement. Transient projection controls the image's
content under the same commit and scheduling contracts.
In the fixed C implementation, both TALK and SUBSCRIPTION are discourse records;
they occupy the in-memory discourse map rather than durable message storage.
The subsequent official HEAD excludes their hash-to-epoch metadata from durable
epoch output and removes it when discourse data is cleaned. A Rust EpochRow is
a different concept: immutable JOIN/LEAVE/MERGE membership state. Those rows and
ordinary signed raw frames, hashes, profile declarations, session bounds, source
observations and first-write aliases remain under their original checks.

The image stores a source-free Deleted historical graph anchor for authenticated
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
