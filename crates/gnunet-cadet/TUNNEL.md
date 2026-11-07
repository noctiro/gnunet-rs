# CADET tunnel crypto and control

The module is no_std/noalloc and uses only existing `gnunet-crypto` and `gnunet-session-crypto` primitives: exact Ed25519-seed to X25519 identity conversion, SHA512(X25519) legacy DH, GNUnet HKDF, HMAC-SHA512 and detached XChaCha20-Poly1305. No C FFI, private fallback, protocol framing or new wire identifier is introduced.

- Role is the bytewise identity order: lower Alice, higher Betty, self invalid. The local identity owner must derive exactly the Context's local public peer. Incoming peer/ephemeral/ratchet contributions are checked by the existing contributory DH primitives.
- Initial material is the three64-byte DH hashes in A–B0, A0–B, A0–B0 order. Exact `CADET Axolotl salt\0` derives five32-byte keys with the pinned Alice/Betty directional mapping. Original public KX fields and initial SHA512(RK32) proof are retained. Alice's first seal must advance a fresh local DH ratchet.
- `Context::initial_key_exchange` emits initial Alice KX fields; `Session::initial_auth` emits original KX_AUTH fields/proof. `verify_initial_auth` compares the supplied original candidate's public fields and proof, in constant time for the proof, before marking it confirmed. Wrong proofs/other candidates do not advance state, and repeated confirmation returns Replay without resetting a chain/cache. A valid whole encrypted packet can also confirm the peer, as required for Betty's initial receive path.
- Send DH ratchets and current/next receive header keys implement the root/NHK/chain schedule. Each message derives MK with byte `0`, advances CK with byte `1`, and derives its24-byte message nonce through the exact empty-context GNUnet HKDF. All C string contexts passed by sizeof include their trailing NUL. The public local ratchet key is cached, avoiding the C transmitter's repeated point multiplication on every message.
- Body ciphertext is tagged with empty AAD. Header plaintext is exactly NsBE32, PNsBE32, DHRs32; header AAD is the complete body ciphertext plus trailing body tag. Output uses the existing `official::cadet_peer` envelope and wire MAC offsets. CID/outer header/reserved are outside this AAD, exactly as the official transmitter does.
- Receive first authenticates the header, then derives bounded candidate chain/ratchet/skipped keys, then authenticates the body's separate tag and exact complete plaintext frame. Only after all those checks does an infallible transfer commit staged keys, root/chains, Nr and peer ratchet. Bad tags, bad frame structure, bad source, counter overflow, gap refusal and capacity refusal do not advance the live cipher state.
- Old ratchet packets can consume an original saved HK/MK once. Replays/duplicates never advance counters or release plaintext again. A failed saved-key packet never removes its key. No implicit cache eviction, clock or allocator exists; a full cache refuses atomically. `forget_skipped` is an explicit owner policy operation and never rewinds a chain. Lost/forgotten ciphertexts may then remain undecryptable, as a bounded skipped-key policy necessarily permits.

The source's signature-purpose38 connection monotime and its path/route ownership checks belong to the separate connection owner, not to this symmetric crypto core.

## Ownership and integration API

```rust
let domain = tunnel::context::Instance::new();
let mut rows = [const { tunnel::context::Slot::new() }; MAX_LIVE_PEERS];
let mut contexts = tunnel::context::Registry::new(&domain, &mut rows)?;
let context = contexts.allocate(actual_local_peer, actual_remote_peer)?;
let local = tunnel::LocalKeys::generate(&mut actual_entropy)?;
let public = local.exchange(); // retain with the original KX control operation
// Actual role/phase and remote control-frame reception happen in the controller.
let mut session = tunnel::Session::new(
    context, &actual_identity, local, actual_remote_exchange,
    tunnel::Storage { skipped: &mut committed_slots, staging: &mut staging_slots },
    tunnel::Limits { plaintext_bytes: actual_cap, maximum_gap: actual_gap },
)?;
```

`Identity::from_seed` consumes an **derived peer Ed25519 seed**, not PILS's persisted root IKM. It holds only an erased DH private owner/public identity after deriving it. `LocalKeys` has private scalar fields, no raw/import/serialization API, no Clone/Debug and only a public fresh-entropy generator. The original ephemeral is consumed/erased after deriving the implementation; the private ratchet remains exclusively owned until replaced.

`Controller::new_external_identity` instead binds an explicit trusted
`identity_dh::Source` and port. Standard PILS ECDH can provide the one required
64-byte identity contribution; the other two genuine ECDHE contributions remain
local. This requires no static private-key export. One original request binds
the implementation, role, exchanges, source epoch and original expiration. Awaiting
DH preserves working-session traffic; expiry retains an admitted job's actual
retirement obligation. A DH result alone never confirms a peer. The native
PILS provider is implemented separately in `gnunet_cadet_host::identity_dh`:
one native connection serves bounded jobs and context high-water records.
Only original identity/epoch/operation results can reach its private callback.
`identity_dh::Registry` similarly uses a stable source Instance and fixed caller
Slot rows; its owned Binding is held by the native Port. Physical stop then
Binding close/drop revoke admission, and a new MQ can receive a fresh unique
local bind ID even when its diagnostic epoch number repeats. No mutable borrow
of an old Instance, Box leak or per-peer PILS MQ is needed.
The native Node composes these owners for directly connected CORE neighbors;
discovery and full mixed-node interoperability remain work.

`SkippedSlot::new()` supplies opaque fixed storage. `Storage` separately borrows committed/staging slices; staging must be at least as long as committed. This uses explicit bounded temporary key storage rather than speculative mutation or hidden allocation. Keys, candidates, seed guards, message/header keys, nonces and intermediate KDF material use zeroizing owners. The sole private Keys Clone makes a transactional erased copy of symmetric fields; no private scalar is cloned. Identity/LocalKeys/Session/SkippedSlot/Opened/Sealed expose no Debug that could print private material or plaintext.

`Context` is an owned non-Copy lease. Controller/standalone Session constructors consume it. The fixed registry uses a stable explicit node-domain brand and a checked unique allocation ID, never a dynamic Context address or global ID. `scope = session.scope()` carries original public facts and only stable domain/registry references; old scopes and ledger generations do not pin per-peer objects. Closing/dropping the lease revokes admission, and its row may be reused only with a fresh ID. Old scope metadata never changes to replacement-peer facts. `seal(scope,cid,one_plaintext_frame,out,entropy)` and `open(scope,one_wire_frame,out)` reject foreign/revoked scopes before crypto/output changes. Original crypto counters/ciphertexts remain non-replayable; a fresh local lease is not permission to reuse a raw CTN under old tunnel keys. The scope **does not prove CORE authorization**: the bridge must first check the Neighbor/route epoch and expected end-to-end peer through the connection owner, then select that current live session. Raw CID alone is never an authenticated peer selector. Several authorized connections to the same end peer may share a session, since CID is not inside the official header AAD.

Seal preflights frame size, configured capacity, output capacity and counter arithmetic before exposing bytes. It returns `Sealed` borrowing the exact immutable complete ciphertext frame plus its scope/public counter. Successful seal immediately consumes the message MK/CK/Ns even if the caller later cancels, drops the view, has zero native exposure or loses its connection. There is no rollback API. Before sealing, the native bridge should reserve its immutable frame/metadata; bind the original channel `Attempt` to these exact sealed bytes. Partial native writes and cancellation of this same Attempt retain/continue the original bytes. Local seal, queue admission and full local write are not remote channel ACKs.

A **new distinct reliable-channel retry Attempt** may seal the retained same-MID plaintext with a fresh tunnel counter, as the official GCT_send retry path does. It must not be disguised as a re-creation of an existing encrypted Attempt. Long-term retransmission of already accepted old ciphertext would be rejected by the crypto replay filter and would not reach the channel's duplicate-MID re-ACK logic.

Open returns `Opened` only after both tags and whole-frame structure pass. Its bytes are caller-owned plaintext and its header is authenticated. Dispatch the complete ChannelMessage to the correct peer/CTN channel owner separately; its receive_done, send-window, DATA_ACK and delivery ownership remain untouched by crypto. Authentication failures wipe the attempted plaintext output prefix. Preflight/source/capacity failures leave output unchanged; other bytes beyond that prefix are untouched.

## Caller-driven controller

`controller::Controller` owns initial KX, FORCE_REPLY, final original authentication,
bounded retries and full fresh negotiation beside a working session. It borrows
two caller-owned skipped-key stores for at most one confirmed session and one
candidate. An unauthenticated candidate cannot replace working keys. Complete
authentication promotes the implementation; retirement erases its storage. The cached
initial proof remains separate from current ratchet root keys.

Inputs require the original connection book's private authorized `Endpoint`.
Only its genuine fresh purpose38 `ResetProof` can pause application sealing for
peer reset; raw CID, wall time and repeated proofs provide no reset authority.
`prepare` returns a linear immutable control output. `submit` binds its exact
bytes and route to the book's original physical attempt. Only completed
write receipts start retry timing; admission, partial writes and unknown outcomes
remain distinct. `seal_channel` consumes one original channel Prepared, and the
returned ciphertext must stay immutable through that physical attempt.

Every candidate also has an absolute finite negotiation lifetime, independent
of route availability, queue refusals and write outcomes. `next_deadline()`
includes that lifetime so an idle owner can still retire it. Expiry preserves
working keys and requires original pending writes to settle separately. A never
admitted retained keepalive yields to new authentication traffic without rolling
its cipher counter back; failed authentication output for a still live epoch
creates a new original attempt.

Every original DH Request also checks the live fixed context row's exact
allocation and candidate-admission generation before backend submit. A copied
queued request whose lease/candidate was closed or dropped cannot start IO,
even if it was never admitted and has no high-water entry. The native provider
also erases/refuses revoked results before any secret callback. An already
admitted request remains an explicit original job: lease revocation alone is
not physical retirement, and finish/retire still check its exact original
operation and quiescence. Revoked context high-waters reclaim only once
no original job for that context remains, so dynamic peer churn can reuse a
small ledger without waiting a full candidate TTL.

A caller-driven Node can keep the stable domain/rows and its shared source in
an outer storage scope, move Context leases/Controllers and externally borrowed
crypto Storage packages through bounded live/retiring/free slots, and reuse
peer rows under new IDs. No Controller/Session borrows a per-peer Context or
another field of Node. The fixed domain/row references remain explicit; an
all-owned self-referential convenience container is not introduced.

The controller has no socket, task, clock, discovery or implicit success path.
The native Node joins CORE/connection/PILS drivers with these owners
and the reliable channel/application service. Explicit persisted monotime ranges
and private physical-write receipts retain original reset/send ownership.
Connected-neighbor file exchange has run between two Rust foregrounds
with unchanged C PILS and controlled CORE IPC. Actual native management now
captures bounded peer/tunnel/path snapshots from those owners. Discovery,
complete CADET acceptance and C encrypted peer interoperability remain unfinished.

`request_ratchet` only requests a send ratchet once an authenticated remote step allows it; Alice's first step is automatically pending. External canonical clock/message-count policy must implement the official configured ratchet time/count. The default core gap ceiling is the source's256 derivations per chain; concrete slots remain the tighter memory bound. Automatic C-style oldest-key eviction/time expiration is not supplied. Counters refuse overflow rather than wrap/reuse; the controller must rekey before exhausting a32-bit chain.

Persistence/restart restoration is deliberately absent. A new process or new key epoch must obtain fresh original ephemeral/ratchet keys through `LocalKeys::generate` and the fresh-cryptographic-entropy contract. Restoring only counters, only root/chains, or old local keys with zero counters is unsupported and cannot be done through the Session/LocalKeys public API. No serialization or general key export is provided. Applications still must implement the Entropy trait honestly; no library can turn repeated/nonrandom input into a fresh-key guarantee.

## Official profile limitations kept explicit

Header nonce remains **GNUnetHKDF(HK, empty,24)**, fixed for that HK across its packets. This is an official header key/nonce reuse limitation; the implementation does not claim universal nonce uniqueness or general security merely because its model roundtrips. It does not add Ns, peer IDs or private AAD to change the official protocol. The strict per-message no-rollback rule above applies to CK/MK/Ns and their message-key nonces.

KX_AUTH's official proof hashes RK only. It does not cryptographically cover CID, flags or the initial ratchet-public field; comparing public fields to the retained candidate prevents accidental context substitution but does not invent a missing protocol binding. Successful data authentication remains necessary before trusting the advertised DH ratchet's derived traffic state.

The pinned C receive defects remain external unaccepted items: `t_h_decrypt` supplies an uninitialized destination MAC instead of the received wire MAC; body detached-decrypt calls include the trailing tag in ciphertext length. This Rust core uses the received header tag and excludes the detached body tag from ciphertext length, never reproduces undefined reads and does not alter official C. Neither self roundtrips nor existing C loopback IPC evidence establish encrypted C↔Rust peer interoperability.
