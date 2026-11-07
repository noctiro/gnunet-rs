# Messenger IPC, bodies, records and cryptographic operations (M1–M3)

GNUnet v0.29.1 Messenger API0.8, pinned revision
346358e26d4dcc2dc4f51bef5d52dca29c7d8165. Default Rust code uses no heap
allocation, native runtime, hidden RNG or C FFI. This is not a complete Messenger
room/client/service implementation. Message/Short decoded fields are sealed:
getters borrow/copy views of their immutable original bytes; callers cannot
replace padding bounds or fields used by a cryptographic check.

The existing M1/M2 layer implements every active client IPC/notification, all28
active kind body codecs, blindable public/signature and HPKE structures, complete
signed/short framing, explicit endian/FILE-name profile and padding footer,
all4 packed record payloads and caller-sized SensitiveBuffer<N> ownership. Source constants preserve22..28 beyond the stale C KIND_MAX21. Actual SECRET
fixed body is72+data, ACCESS208, and AUTHORIZATION192. Exact decode rejects an
unexplained fixed tail; decode_prefix preserves ignored fixed-body bytes. Text
preserves original encoded bytes and first-NUL semantics separately.

M3 implements operations, reusing existing gnunet-crypto/session-crypto:

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
- AUTHORIZATION outgoing: deterministic group-key nonce KDF, AEAD MAC and
  HMAC using the transported new shared key, then the actual192-byte wire fields.
  Received AUTHORIZATION cannot provide its omitted MAC and returns the explicit
  AuthorizationMacOmitted failure. There is no fabricated zero MAC, extension,
  receiver key-recovery guarantee or verified group transition.
- Epoch record236: derive key32 from handle-secret64 with ordered room64,
  epoch64, identifier32 and encrypt/decrypt shared key32 with nonce24/MAC16.
- Encryption record624: derive from handle-secret64/room64, serialize the real
  opaque HPKE private key into zeroizing516-byte scratch, randomize its suffix,
  AEAD the complete array, then authenticate before parsing a recovered private
  key. Exact active serialization consumption/length is checked. The public
  record holds ciphertext only. Record salt uses strlen bytes without final NUL.

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

Cryptographic checks deliberately prove only their own property. The caller
must select trusted original member/peer keys, expected identifiers/events,
unique authorization contexts and record/room/epoch ownership. A valid
signature, HMAC, AEAD tag or recovered key does not grant membership, permission,
message continuity, epoch validity or durable publication. The current functions
hold no hidden room database or default successful state transition. Native
PILS still needs its CLIENT: signing_payload only supplies its input,
with no invented operation receipt. GNS record signature/zone validation and
NAMESTORE storage outcomes remain outside the packed record cryptography.

The AUTHORIZATION limitation is pinned to messenger_api_message.c:439-447
(size),828-834 (encode),1187-1193 (decode),1439-1452 (HMAC),1945-1980 (decrypt)
and messenger_api_message_kind.c:395-451 (producer). Size/encode/decode
omit MAC16 while decrypt/HMAC require it. The outgoing producer computes
that MAC for its local HMAC and then loses it on wire; matching that operation
does not repair the upstream information loss.

Still required for a complete Messenger implementation:

1. Bounded room/open/enter/sync state; member IDs/reset/collisions; contact/key/
   session transitions, sender attribution and authorization using the actual
   cryptographic results and original IDENTITY/PILS operations.
2. Message DAG/previous/merge continuity, duplicate/history/missing-message
   recovery, deletion/delay, transcript links, subscriptions and discourse.
3. Epoch/group announcement/appeal/access/revolution/authorization lifecycle,
   event/identifier/nonce uniqueness, timer/storage gates, revocation and
   the unresolved received AUTHORIZATION omitted-MAC protocol defect.
4. Actual bounded persistence and native CLIENT/SERVICE/CADET source ownership,
   reconnect/flow control, Entropy/key-provider wiring and interoperability.


Checked Message/Short fields are sealed behind getters so callers cannot replace padding and invalidate original hash bounds. This proves no signature, encryption, room/group state or C interoperability.

The pinned MEMBER_ID reset producer/reader uses native u32 without
htonl/ntohl. Response encoding/decoding therefore requires the explicit original
producer Profile; the native client retains Limits.profile in each Notification. Other network u32 fields, including RECV flags, remain BE. This is one documented
reference wire property, with no private extension or old compatibility fallback.
