# Messenger formats and cryptography

GNUnet v0.29.1 Messenger API0.8, pinned revision
346358e26d4dcc2dc4f51bef5d52dca29c7d8165. Default Rust code uses no heap
allocation, native runtime or hidden RNG. Message/Short decoded fields are sealed:
getters borrow/copy views of their immutable original bytes; callers cannot
replace padding bounds or fields used by a cryptographic check.

## Public interface

The format API covers active client IPC/notifications and message bodies, blindable public/signature and HPKE structures, complete
signed/short framing, explicit endian/FILE-name profile and padding footer,
all4 packed record payloads and caller-sized SensitiveBuffer<N> ownership. Source constants preserve22..28 beyond the stale C KIND_MAX21. Actual SECRET
fixed body is72+data, ACCESS208, and AUTHORIZATION192. Exact decode rejects an
unexplained fixed tail; decode_prefix preserves ignored fixed-body bytes. Text
preserves original encoded bytes and first-NUL semantics separately.

`carrier` derives the official CADET room port using the listener's byte order
and frames messages in caller-provided storage. Relays keep the original
signature and signed bytes and regenerate only unsigned outer padding under
the channel's frame limit.

## Cryptographic operations

Operations reuse `gnunet-crypto` and `gnunet-session-crypto`:

- SHA512 canonical signed-message hash; size72/purpose12 CHAT_MESSAGE signature
  record; ECDSA/EdDSA signing with an opaque zeroizing IDENTITY SecretKey;
  algorithm-family-matched member/peer verification. PkeySecret::sign is the
  sole shared primitive entry addition and reuses the existing RFC6979 signer.
- Sealed SignatureChecked and HashCheckedShort results, created only after the
  respective check. A carried public key is never trusted as a member.
  Signed hashing excludes outer padding, starting after signature68. Short hash
  covers kind/body/padding after carried hash64 and is checked before body parse.
- SensitiveBuffer::encode_signed and encode_hashed_short actually install their
  signature/digest. Error paths erase failed owned output. Structural wire
  encoding alone continues to grant no signature, delivery or authority result.
- PRIVATE: official eligible-kind gate, hashed/padded short message,
  Base HPKE X25519/HKDF256/ChaCha20Poly1305 with info="messenger" (no NUL), empty
  AAD and enc32/ciphertext/tag16 framing. Decrypt authenticates then checks
  the short hash. Caller provides bounded plaintext scratch, erased on every
  admitted success/failure; no payload-sized hidden allocation is introduced.
- SECRET messages use XChaCha20Poly1305 with fresh nonce24, detached MAC16, actual
  padded/hashed short bytes and empty AAD. Decrypt also matches the caller's
  original expected identifier and checks the carried short hash before exposure.
  The outer signature/state still binds the public identifier and sender.
- TRANSCRIPT: hashed unpadded short payload and exact recipient key;
  original linked-message hash is supplied explicitly. Reading checks the short
  digest, preserves the producer's unpadded suffix without C's ambiguous footer
  heuristic, and does not invent an original-history link or decryption result.
- ANNOUNCEMENT/ACCESS/REVOLUTION: GNUnet HKDF-derived auth-key64 and
  HMAC-SHA512 over the independent C body-prefix bytes. Message salts include
  their sizeof(string) NUL. Actual MAC checks return a sealed MacChecked view.
- ACCESS: actually transport key32 as an HPKE packet80 and verify the recovered
  key's original body HMAC before releasing the zeroizing key capability.
- AUTHORIZATION: deterministic group-key nonce KDF and exact192-byte producer
  fields. Recovery reconstructs the omitted deterministic AEAD tag, checks the
  carried HMAC under the recovered candidate key, and releases the zeroizing key
  only after authentication. Room, member, group and event authority remain
  with the consuming engine.
- Epoch record236: derive key32 from handle-secret64 with ordered room64,
  epoch64, identifier32 and encrypt/decrypt shared key32 with nonce24/MAC16.
- Encryption record624: derive from handle-secret64/room64, serialize the real
  opaque HPKE private key into zeroizing516-byte scratch, randomize its suffix,
  AEAD the complete array, then authenticate before parsing a recovered private
  key. Exact active serialization consumption/length is checked. The public
  record holds ciphertext only. Record salt uses strlen bytes without final NUL.

## Secret storage and bounds

SensitiveBuffer erases its full capacity on clear/drop. AeadKey and RecordSecret
are opaque zeroizing owners, without Clone/Hash/public raw getters. Real key
providers may own and process their own newly provisioned keys; these library
functions never read a file. Secret copies, KDF output and plaintext scratch are
zeroizing owners. Debug redacts message/key/record/check contents. Borrowed raw
SensitiveBytes cannot erase its separate source, so retained sensitive frames
must remain in an erased owner. Fixed record scratch is516 bytes; variable short
plaintext storage is always a caller-selected SensitiveBuffer<M> budget.

Padding generation draws filler from explicit Entropy directly into that
scratch, writes marker0/native u16 footer, and uses512/4096/32768/65524 rounding. The NAME_MAX/endian profile remains explicit; no negotiation/private
format is added. Ciphertext/transcript producers reject an outer message that
cannot fit its signed header/minimum footer at the official65524 ceiling,
instead of copying C u16 wrap. Decrypt rejects failed tag/hash/body bounds and
erases output before returning failure. A cheap immutable body view is reparsed
after validation to permit safe error erasure without another hash/payload copy.

## Authentication boundaries

Cryptographic checks prove only their own property. The caller
must select trusted original member/peer keys, expected identifiers/events,
unique authorization contexts and record/room/epoch ownership. A valid
signature, HMAC, AEAD tag or recovered key does not grant membership, permission,
message continuity, epoch validity or durable publication. The current functions
hold no hidden room database or default successful state transition. Native
PILS still needs its CLIENT: signing_payload only supplies its input,
with no invented operation receipt. GNS record signature/zone validation and
NAMESTORE storage outcomes remain outside the packed record cryptography.

## AUTHORIZATION constraint

The selected C producer computes a detached AEAD tag, includes it in the
shared-key-derived HMAC, and omits the tag from its192-byte transmission.
The tag is deterministic from the wrapping group key, derived nonce and
ciphertext. Rust reconstructs the original encryption/tag and verifies both
ciphertext and carried HMAC in constant time before releasing a candidate key.
No extra field, default tag or unauthenticated key is exposed.

`open_authorization` requires the original wrapping group key.
`verify_authorization` requires that key and the transported shared key;
ordinary one-key `verify_mac` reports `GroupKeyRequired` for this body.
These operations do not grant group/epoch membership or validate the sender's
signature. The selected C receiver still passes its omitted tag to AEAD opening;
Rust recovery does not repair that separate C receive path.

## Composition

The [Messenger core](../gnunet-messenger-core/README.md) owns room, membership,
epoch and DAG transitions. The [native client API](../../adapters/messenger-api-std/README.md)
composes these operations with service clients; the
[service host](../../adapters/messenger-std/README.md) owns routing and persistence.

## Native layout profiles

The pinned MEMBER_ID reset producer/reader uses native u32 without
htonl/ntohl. Response encoding/decoding therefore requires the explicit original
producer Profile; the native client retains Limits.profile in each Notification. Other network u32 fields, including RECV flags, remain BE. This is one documented
reference wire property, with no private extension or old compatibility fallback.
