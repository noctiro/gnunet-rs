# Native high-level Messenger client (M5)

`gnunet-messenger-host` owns the caller-driven `Api<E,N>`, admitted Messenger native CLIENT, bounded Messenger Core, opaque signing identities, crypto/entropy, and explicit optional native NAMESTORE/GNS ports. It creates no service, socket actor, Resolver, private file loader or C FFI. Polling starts native work; dropped wait futures retain the same original ownership.

Implemented paths:

- Actual CREATE whole-write readiness, OPEN/ENTRY/SYNC/GET and asynchronous notifications; original Source/Binding/native Epoch/Operation/queue/exposure mappings. The native partial-write head follows native admission order, independently of cross-room draft order.
- Current JOIN/ID initialization with generated/retained HPKE keys, typed public send, official automatic SECRET wrapping when a epoch key exists, explicit SECRET, recipient PRIVATE plus separately encrypted sender TRANSCRIPT, names, subscriptions/renewal, deletion, cached messages and resumable authorized history. Public send uses the official public client YES-only kind gate; protocol control has its dedicated operations. Private rooms wait for a key rather than silently falling back to plaintext.
- Signed LEAVE whole-write then CLOSE under one original lifetime, CLOSE notification/room-lease retirement/reopen, retained history and other live rooms. Explicit settled-job DESTROY preserves its local whole-write control report before physical close. Neither implies a service ACK.
- One handle identity per shared MQ. `change_identity` draws replacement HPKE keys, emits old-session-signed KEY in every active room, and commits the selected owner only after matching session transitions. Stale drafts and histories keep original public attribution. Explicit secret-owner retirement is bounded and refuses active dependencies.
- Automatic full-room epoch distribution over ANNOUNCEMENT/APPEAL/ACCESS, genuine provider/signature/HMAC/HPKE/AEAD operations; explicit epoch entropy, announcement, appeal, access, revolution and GROUP proposal operations. State changes still require input/provider checks. The active official AUTHORIZATION wire omits MAC16: no zero MAC or Verified result is invented.
- Optional NAMESTORE epoch lookup, encrypted HPKE/epoch storage, whole-zone finite monitor, original native operation/epoch/RID/zone comparison and fixed room/source/public snapshot. Explicit caller RecordSecret64 is independent of IDENTITY private hashes. Flags0 records restore historical Revoked capability directly; they grant no future send or old membership. Native result codes and record metadata remain available as actual `RecordProgress`, never fsync/publication receipts. Initial/rotated own recipient keys are genuinely sealed and submitted after the member transition. Epoch stores are explicitly callable; a watch applies records for the room/source snapshot captured at watch admission.
- Actual NAMESTORE room entry/details advertisement with explicit zone/label/flags/expiration, shared `record_text` codec reexport, and independent finite original-query GNS room-entry/details discovery. Discovery stops physically on its first loss/refusal/retry/expiry and never replays retained native intent. `enter_advertised` prepares the ENTRY. The selected GNS service owns GNS validation; this wrapper does not claim to authenticate zone blocks itself.
- Fixed original logical and native hard targets, hard wake registration before canonical coherence, no-clock shutdown/cancel, bounded round-robin/provider/decrypt work and retained input backpressure, exact first loss plus independent native/record/core cleanup facts. Explicit reconnect restores retained room intent through fresh sources and operations. Old user SEND/STORE and uncertain physical bytes remain failed or retired. Caller must retire ordinary terminal receipts to release finite capacity.

Usage contract: create the external native `Instance` owners and EndpointSource values from the existing process Resolver/CLIENT/RuntimeClock. All configured ports must share the same clock Arc. Supply an owned IDENTITY SecretKey (or explicit public anonymous identity), entropy E, and only if local encrypted records are desired an explicit opaque RecordSecret. Poll `Api::progress`, consume state/IO observations, retire terminal operation rows, and use `can_reconnect`/`reconnect` after consuming a recoverable loss. NAMESTORE monitors are finite original snapshots: stop/start a fresh monitor after adding/reopening rooms or changing zone identity; old replies cannot be adopted by replacements. Crypto and cached historical keys are owned/zeroizing; diagnostics redact sensitive content.

A preallocated, byte-charged ledger retains bounded OPEN and distinct door
intent with the existing room identity/history. Unconfirmed intent keeps its
original caller Span; established membership persists until explicit close or
Stop. The old completed OPEN timeout does not limit membership lifetime. After
CREATE writing on a new MQ, recovery uses fresh branded Sources and
OPEN/ENTRY work. Real new JOIN authorizes fresh current name/subscription and
record-watch setup. Every physical attempt/effect keeps a finite fixed bound;
backoff never extends it. Whole-ledger metadata scanning is bounded, and the
work budget counts new operations. Waiting for JOIN does not self-wake.

Old SEND/STORE and old source receipts are never submitted again or relabelled
successful. Consumed terminal operation slots are reclaimed before reconnect;
diagnostics remain bounded with explicit omitted counts. Explicit room quiesce,
forget, cancel and close remove the corresponding recovery intent. The normal
command continues an established membership task through eligible losses while
observing the same unique input owner for EOF/Stop.

boundaries: this is a high-level CLIENT candidate, not the distinct native Messenger SERVICE/CADET relay/foreground/REST layer. There is no private storage/fsync implementation or automatic new identity/key-file provisioning. The native daemon IPC profile remains explicit and independent from the local signed-body producer, recipient short-body/padding encoders and raw identifier creator. `Api::new_profiled` takes bounded `Profiles`; `LayoutNeeded` retains the exact original notification/source/deadline until `provide_layout` supplies its grammar. See [LAYOUTS.md](LAYOUTS.md). None of these declarations replaces original source/hash/signature/AEAD checks. The official missing AUTH MAC remains a interoperability limitation.

One pure scheduling model source exercises plaintext integer FIFO ordering and native hard registration despite canonical-clock churn; it constructs no key, Core, native endpoint, Resolver, store or crypto object. This child ran no Cargo/compiler/model/native/C/crypto/key generation/derive/sign/hash operation, file key loader, socket/device/route/network or store. The handoff source hashes identify public code files and explicitly listed public reference C/H only.

The high-level client public scheduling model passed without crypto/key/native/store activity. Those checks applied to the earlier integrated high-level client. Persistence/recovery is supplied by the distinct SERVICE owned-history layer; its prior receipts retain their original scope. Official mixed-node runtime interoperability remains unqualified.

KEEP_ALIVE discourse intent is retained independently of old native SENDs. The generic `send`/`send_bounded(Body::Subscription)` path and the subscription
helpers share one bounded ledger, using the existing rooms × subscriptions limit
and actual-capacity accounting (including allocation growth peaks). A new
unconfirmed request retains its first logical/native Span across source loss. Only its exact received echo followed by semantic application establishes
a long-lived intent. A Complete wire job can retire normally while the ledger
keeps its original echo identity/timestamp and finite semantic-work bound.

After CREATE, room recovery and authenticated JOIN/KEY/ID transitions,
retained intent prepares a new signed subscription with its original discourse,
relative duration and complete flags. Each new effect has a fixed finite bound;
no old operation, native suffix or successful receipt is transplanted. The
ledger derives renewal timing only from its own current echo, so late old echoes
or previously unknown history cannot restore cancelled intent or overwrite its
current timer. The old pure automatic timer is paused without changing signed
intervals or retiring already admitted jobs. FOREVER duration stays wire MAX
and has no finite renewal timer; finite duration whose end saturates still keeps
its finite renewal delay.

Unsubscribe (including flags3), explicit `keep_alive=false`, room quiesce/close,
whole-owner cancellation, disconnect and close withdraw the corresponding
intent. The flags0 withdrawal is this library's existing explicit local policy;
the C helper itself leaves an older timer untouched for flags0. A timeout is
recoverable only for this owner's exact internally admitted effect of an already
established intent; ordinary user/first-unconfirmed deadlines retain their prior
failure behavior. The normal TALK CLI preserves its first admission across
reconnect and does not issue a duplicate replacement subscription.

The logical subscription table grows geometrically when its existing aggregate
byte ceiling permits, reducing repeated prefix copies during bulk admission. Both old and replacement capacities count toward the growth peak. If the larger
allocation is refused, one exact-minimum fallback preserves the previous local
admission policy; refusal leaves the original table and protocol work intact. This changes allocation policy only, not wire fields, deadlines or confirmation. It is not a resident-memory or throughput measurement.
