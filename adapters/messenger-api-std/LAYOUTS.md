# Explicit mixed-producer client layouts

`Api::new_profiled` takes the daemon's native CLIENT limits separately
from `Profiles`. `Profiles::new(maximum, local, default, default_room,
default_record)` fixes the local Rust signed-body/short encoder, optional common
original decoder contract, room-capability creator and record producer. Five
preallocated finite directories hold explicit attributed-sender, exact message,
identifier, room and record declarations; their capacities are charged to
the client's byte budget. No profile negotiation or extra wire byte is invented.

For a received original, exact locally encoded SEND facts, an explicit held-input
override, exact message/sender policy and retained original facts precede the
optional common decoder declaration. GET is not a locally encoded SEND fact.
Missing original producer or new identifier creator emits `LayoutNeeded` once
while retaining that original notification and immutable input/hard deadline.
`provide_layout` validates its private owner/epoch/serial/room/message binding;
old needs cannot retag another input or replacement MQ. These are parsing facts,
not proof that the carried sender/hash is authentic. Core still checks the
original source, canonical message hash, public-key attribution/signature and
membership. Incoherent clock/expiry/source loss physically closes the original
native owner; `Loss::layout_need` retains any unresolved original need. Waiting
or supplying a declaration does not extend deadlines, ACK anything, or replay IO.

`ClientLayout.original` covers the signed outer body and that original envelope's
unsigned relay padding. `plaintext` independently covers the immediate decrypted
PRIVATE/SECRET short body and its immutable padding. `transcript` covers the
nested **unpadded** short in TRANSCRIPT. Original short hash includes padding;
HPKE/AEAD and carried-hash checks precede published plaintext. A relay may
repack only unsigned outer padding. Original signature, hash, ciphertext and raw
sender/recipient/group-identifier bytes are preserved without byte swapping.

`send_private_profiled` actually encodes/encrypts the short using the explicit
recipient decoder contract. Outer signing still uses the local producer. If a
separate sender TRANSCRIPT is needed it gets its own original operation and
HPKE encryption; its nested short retains the recipient body width while
the sender's encrypted wrapper uses the local encoder. This supports FILE's
original NAME_MAX instead of pretending all plaintext layouts are portable.
`send_secret_profiled` encodes one epoch ciphertext under one explicit
shared short decoder contract. It does not invent per-recipient wire tags or
multiple logical copies. Existing methods explicitly select the local common
contract. A caller can use core MessageRef metadata to display the actual
installed plaintext producer separately from the immutable ciphertext producer.

Raw group identifiers remember the original creator's bitfield order, including
cross-epoch derivation and persisted metadata. A later announcement, ACCESS,
SECRET or REVOLUTION does not reinterpret the same bytes using that sender's
ABI. `EpochRecordTarget` and `recover_epoch_key` carry independent original
identifier facts; none grants membership or supplies a key. Private NAMESTORE
records use their own exact zone/type/optional ciphertext-data hash profile.
`declare_record_layout` and `declare_record_identifier` accept only an actual
still-current original NAMESTORE source. Failed/expired reads require a fresh
explicit read; unknown writes are not replayed. Records genuinely encoded by
this client remember their scalar format before native STORE admission;
only the operation/result can complete storage. `RoomQuery` similarly
selects original GNS record decoding independently from daemon IPC; it consumes
the existing configured GNS native query client, not a new resolver.

There is no official profile negotiation. Configured facts can be wrong and then
decode/cryptographic checks fail; declarations do not authorize a member.
An unchanged C client assumes its own native short/footer/FILE layout. One epoch
broadcast cannot make incompatible unchanged decoders agree. Callers must choose
an shared decoder contract or explicit compatible recipient sends. The
pinned C consumer refuses group-bit SECRET, so this source preserves that
refusal rather than advertise unsupported subset decryption. AUTHORIZATION's
missing official MAC remains an explicit refusal. No fake MAC/key/provider
success or fallback plaintext is introduced.

This extension was prepared by source reads/generation and rustfmt only: no
Cargo/compiler/model, crypto/entropy/key, storage/recovery, native IO or C path
was executed. Earlier central compile/runtime receipts retain their exact scope
and do not establish new mixed-node interoperability. No C key store is read or
migrated, and the service remains an external-CADET/PILS component.
