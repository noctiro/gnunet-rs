# Official Messenger bounded state core (M4)

This is alloc-backed state above the admitted M1/M2 codec and M3
cryptography, pinned to GNUnet v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. It is not a native service, daemon,
transport, persistent history store or a claim that full Messenger/GNUnet has
passed interoperability acceptance.

The default feature exports finite public types without allocation. `alloc`
enables the bounded owner. No C ABI, FFI, hidden scheduler, file/socket I/O or
implicit entropy exists here. Every admitted payload/draft is an exclusively
owned zeroizing buffer; Debug redacts messages, work, events and binding hashes. The caller owns a nonzero-sized `Instance`, passed as an exclusive borrow to
`Core::new(&mut instance, ...)`. The Core and every live handle, provider binding,
event and work item retain that domain lifetime. Private `Brand` equality checks
the original reference by pointer identity; equal-valued instances do not alias. Even after a Core drops, a retained live token prevents reusing, moving or dropping
its original Instance. No global counter, atomics, leaked domain allocation or
single-core/interrupt assumption is needed. The domain adds no heap allocation.

Owned `HandleObservation`, `BindingObservation` and `EventObservation` snapshots
preserve terminal diagnostics without retaining live authority. Their local
coordinates are not unique across instances and cannot reconstruct a handle or
select an operation. Runtime owners continue to use the borrowed tokens.

## state and ownership

`Core` retains fixed-capacity, generational rooms, original sources, member
sessions, contacts, message/tombstone slots, epochs, groups, subscriptions,
original provider/native jobs and logical missing rows. It accounts actual
retained capacities (including in-flight transferred original work), fixed
metadata, names, plaintext and nested epoch/group tables. Table lower bounds are
checked before bulk allocation; capacities are charged before insertion. Limits bound each table, nonce history, event queue, frame size and processing
phase. Capacity refusal is explicit; no successful eviction or disk durability is
invented. `forget_room` requires all room leases retired through their original
physical stop or completed CLOSE and terminal work, erases owned sensitive state
and recovers its exact charge. A logical room close need not stop a shared MQ.

Source/member/message/epoch/provider results bind an immutable `Binding` to the
original core, room, physical source generation, operation, member, original
canonical message hash, epoch, identifier and epoch revision. Slots cannot adopt
old generations or another Core. The core never moves a request to another MQ.

`attach_source` and `create_submitted` observe caller-owned native facts. `open/enter/close/synchronize` build the official requests. `take_work`
moves one original zeroizing frame or draft to its owner. `write_progress`
records exact bytes and complete local writes. Written is not an ACK, published
key, delivered message or member application. Only the original
notifications change those states. Sync preserves the original open/entered
phase and cannot reopen an already closing room. `source_requiring_stop` and
`next_deadline` let the native owner register finite alarms; cancellation
requires physical stop followed by `source_cancelled`, not an invented cancel
message. The native owner retains its original errors/partial-prefix/cleanup
facts separately; `source_stopped` updates this core's state only.

One Core explicitly selects its producer `Profile`; it does not guess native
endian fields or FILE NAME_MAX from content. The wire reset API requires
`Response::decode(input, Profile)` and `encode(Profile, output)`. Only the IPC
member-reset field is native order; ordinary network integers stay BE. M4 does
not swap it again. Initial/reset MemberId requires a signed JOIN. A collision
notification retains the old sender ID and stores the proposed new ID until the
signed ID(new) transition; `prepare_assigned_identity` continues that work.

## Messages, contacts, permissions and history

Admission structurally decodes immutable originals, computes their M3
hash and verifies the selected member or peer signature. Unknown signers
consume only finite deferred storage and grant no rights. A bad first signature
cannot poison a hash against a later valid signature. Same-hash incompatible
authorship is rejected; verified originals and deleted tombstones are immutable. Carried Sent flags never grant local-write authority. Local-send state requires
a matching original whole-write operation. Original sender hashes are
checked against serialized public keys or peer identities; context bytes
are retained without being treated as a membership proof.

JOIN, LEAVE, KEY, ID, NAME, peer/connection controls and application bodies
advance retained state. KEY/ID preserve contact identity and a one-way session
lineage; history ownership propagates to successors, never to an unrelated
session merely sharing a key. Closed sessions retain delayed history until the
iterative ancestry completion. A fresh completed-session rejoin gets a
new lineage. History uses verified admission sequence bounds instead of copying
every message map into every session. Deleted messages preserve author/hash,
parents and epoch while erasing ciphertext/plaintext; ancestor resolution and
session completion still progress through those links. Missing original hashes
are exposed and fetched through GET; Missing only completes its
matching Written GET, and logical rows can be explicitly retired.

DELETION checks session ownership and rejects epoch-message deletion and
forever delay. Its bounded delay follows the helper's timestamp+relative
remaining time capped at one minute. NAME uses first-NUL content. Normal
public-key contacts can be shared; anonymous contacts are scoped by the official
room XOR SHA512(member-ID) context. A legitimate key rotation into another
existing public key does not merge unrelated history/authorization lineages.

Discourse subscriptions use the member lineage and inclusive timestamp
intervals. KEEP_ALIVE renewals queue an original signature job and only a
echoed subscription updates the interval. Unsubscribe stops renewal;
expired original intervals are removed. Service mode prunes TALK payload older
than all retained subscriptions, preserving tombstone links. The DAG/frontier
classification uses the original outer kind: encrypted PRIVATE/SECRET envelopes
remain authenticated DAG vertices even when this client cannot decrypt them. Only successful AEAD plus inner-hash verification installs plaintext; no
recipient failure blocks unrelated later public messages. TRANSCRIPT is accepted
only for the matching own-sent original, same author lineage and intact
hash linkage. M3 supplies all crypto; this crate implements no new primitive.

## Epoch/group state and work

JOIN/LEAVE/MERGE construct immutable membership snapshots; missing epoch
references defer completion. LEAVE must actually remove an existing parent-epoch
member, avoiding the reference C absent-member undersized-allocation write. Announcement/group tables distinguish signed tentative confirmations from actual
MAC-checked key holders. Confirmation replacement does not inflate unique counts. Only valid complete cohorts contained entirely in the next member set can
ratchet a future key; a departing member who knew the old key prevents that
ratchet. The minimal M3 opaque-key extension uses exact sizeof-NUL EPOCH/GROUP
salts and epoch64 then identifier32. It exposes no raw key getter/hash.

key-provider jobs install only original results; ephemeral expiry and
revision/generation checks reject late/replayed results. ACCESS validates its
original appeal/group, member, epoch and retained advertised recipient key before
HPKE+HMAC recovery. MAC-checked nonce admission rejects replay without letting
an invalid MAC burn a valid nonce. Group proposals check referenced signed
announcements, initiator identity, sizes and disjoint cohorts. Revolution verifies
the key MAC and nonce, invalidates future use and all dependent ratchets,
but retains opaque old capabilities solely for authorized historical ciphertext. Deleting an ANNOUNCEMENT removes its confirmation, rather than inventing a
REVOLUTION or permanently revoking a still valid identifier/key.

`drive_epoch` advances at most one original operation per turn, using the
existing official non-group ANNOUNCEMENT/APPEAL/ACCESS exchange. It requests real
key/ephemeral providers, announces an possessed key, responds to authentic
appeals, and requests unknown keys before declaring possession. Simultaneous
initial announcements converge by distinct signed candidate counts and
identifier order; an already possessed different key does not create a permanent
split. Actual SECRET messages needing a key get priority. Native/signature/key
results and echoed messages must be fed back before further progress. This is
wire-compatible scheduling using existing official consumers; no extra protocol
fields or private messages are introduced. Incoming GROUP state is supported;
APPEAL for group-bit identifiers is rejected as the consumer requires.

The active AUTHORIZATION producer transmits192 bytes but the consumer requires a
separate AEAD MAC16 which is absent from those bytes. Received AUTHORIZATION
therefore fails `AuthorizationMacOmitted`; no zero MAC, invented field or Verified
state is substituted. The direct full-epoch exchange does not claim to repair or
successfully decode that defective official group-key transfer.

`seal_epoch_record` produces the encrypted official record from an admitted
opaque key. `complete_epoch_record` checks the original room/epoch/identifier,
valid flag and provider job, actually authenticates/decrypts the record, and then
installs the capability. Neither method claims NAMESTORE zone authorization,
retrieval, fsync or durability; those remain external ports.

## Host interfaces

A native client owner maps each original native epoch to the matching Source,
feeds `on_notification`, drains `advance` while `has_work`, and handles work
from `take_work`. Explicit bounded caller `SensitiveBuffer` scratch handles
private/secret opening. The signer decodes Work::Sign.body and uses the actual
IDENTITY/PILS owner and M3 encoding; `complete_signature` verifies its exact
original result again. The native owner decodes an Encoding::Ipc work frame
and submits its original Request; Encoding::PeerMessage is an official raw signed
peer frame for the peer transport. Deadline expiry requires physical
source stop. Queued SEND never counts as delivery or successful membership.

The official high-level close sequence is signed LEAVE whole-write, then a
separate CLOSE; an outer owner composes `prepare_leave`, its Written fact,
and `close` (no remote LEAVE ACK is invented). It must also map IDENTITY
changes, physical CADET/PILS/routing, daemon request/notification backpressure,
NAMESTORE record jobs, owned history commit/recovery, application callbacks
and frontend/REST delivery. Host adapters and service processes own these ports;
this crate supplies the pure state boundary.

## Testing

Pure structural models use public mock buffers and supplied source facts. They
exercise state transitions without establishing signature, AEAD, native storage
or peer interoperability. Use the relevant [test profiles](../../tests/README.md)
for those boundaries.

