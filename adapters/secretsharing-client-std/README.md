# Native SECRETSHARING client

`gnunet-secretsharing-client-host` is a caller-polled client for the official `secretsharing` endpoint. It sends actual780 generation or781 decryption requests and accepts only the corresponding783 share or782 decryption result. Every `Client` is one operation on one original MQ, as in the fixed C public API. It uses shared CLIENT, framing, the caller's clock and explicit Resolver capability; it creates no service, task, worker, consensus, key, randomness or cryptographic success.

`Client::new(source, &ipc::Request, limits, original_bounds)` freezes the selected endpoint once and copies the complete exact request into zeroizing storage. It does not retain a whole Configuration clone or borrow private share input beyond construction. `drive`/`poll_progress` retain the same owner and partial cursors, so dropping a pending observation future neither cancels nor restarts the request. Pre-attachment ordinary connection retries use the original CLIENT backoff and original bounds. Once attached, any loss physically closes the MQ; there is no replace-epoch, exposed-frame replay or implicit reissue.

whole request write is required before accepting any reply. `Written` records positive syscall bytes and whole-write state only, without service/peer/consensus credit. A complete response must have the original expected kind and exact public shape, pass the explicit frame/peer caps and remain inside the original native/canonical bounds after parsing/allocation. The original MQ is physically closed before `Generated` or `Decrypted` is exposed. EOF, malformed input, timeout and cancellation produce a typed `Loss` with original partial/whole/input receipts, retaining native errors/errno through `Error::source`; none is turned into an empty or successful response. The official protocol has neither RID nor cancel ACK. Physical cancellation may occur after an irreversible contribution, as the public C contract states.

Owned `Share`, `Decryption` and private-result `Progress` intentionally implement neither Debug nor Clone. Their `OwnedFrame` storage erases on every drop. `Share::view` borrows the original serialized threshold, roster, secret and native-index columns; generated results reuse the original783 owned backing without another share copy. Standalone `Share::copy_from` makes an explicit zeroizing copy when requested. `Decryption` keeps the original raw success word and all128 plaintext bytes, including failed-response bytes. Empty shares, nonmember sentinels, threshold0 and unknown nonzero status remain original values. This transport does not qualify threshold, membership, proofs, field elements or the mathematical result. A caller must use the appropriate computation/verification owner.

`Bounds` captures native first and checks the original canonical target before and after provider samples. Its overall native/canonical targets never move; initial connection/first-write, write and first-partial-response phase targets are each fixed once and clamped to the original pair. `poll_native_guard` arms original native deadlines without a clock sample or IO, and closes before exposing expiry. A partial/Pending request never permits acceptance of a premature response. Explicit `close` and Drop are clock-free physical retirement. Wire `start`/`deadline` fields remain exact absolute values: the C public deadline is a consensus hint, not a reason to invent a local response; the caller's separately selected finite bounds govern this owner.

Default caps are65535 bytes per complete frame,4096 participant entries and65535 bytes per syscall, with30s initial,30s write and15s first-partial-input phase bounds, all capped by the caller's original lifetime. A frame profile is540..65535 bytes so the minimum decrypt request is representable. The real16-bit frame extent can impose a smaller roster bound than the configured peer cap; oversized requests/replies fail explicitly. Only one original request and one response are buffered; no peer/result aggregation grows without bound. These are frame/participant/native-owner limits, not measured process RSS or a budget for an arbitrary caller's clock/Resolver implementation or externally retained result owners.


After attachment the original RX and TX directions are driven fairly. When either is Pending, both are polled within that bounded turn; a backpressured
request cannot hide independent native EOF or read errors behind the original
write deadline. A complete response observed before the request is whole is a
protocol refusal, checked at that read boundary before a later TX turn. It grants no success or write completion. Retirement snapshots Framed's retained
input extent, including a malformed header whose positive bytes preceded its
native error. Original request bytes, source, write prefix, immutable canonical
and native targets, zeroizing ownership and no-replay policy remain unchanged.

Four prepared Unix-source cases cover native TX Pending plus peer
write-half EOF, a complete premature expected reply, exact malformed-header4
loss facts and an ordinary whole request followed by its exact expected reply. They use original native owners and supplied raw response shapes; they prove no
DKG/decryption mathematics, authentication, peer agreement or service success.
