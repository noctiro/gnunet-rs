# Official SETI intersection core

This crate implements the active GNUnet v0.29.1 SETI collection and operation
owner, including alternating Bloom reconciliation. It is `no_std`, has no
allocator or unsafe code, and creates no network, resolver, task or thread. A native SETI **service** listener/CADET adapter remains a separate integration;
this core does not claim that an IPC client alone supplies that service.

The pinned source is commit `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, specifically
`src/service/seti/{seti.h,gnunet-service-seti_protocol.h,gnunet-service-seti.c,seti_api.c}`,
`src/include/gnunet_seti_service.h`, and the container Bloom implementation. The codec lives in `gnunet_wire::official::seti`.

## Resources and ownership

`Service::new` borrows an explicit stable `Instance`, fixed client/set/listener
rows, shared `ElementSlot` payload slabs, and fixed `OperationSlot` storage. The caller chooses variable slab sizes. Each operation uses three bitmaps of
`ceil(element_slots/8)` bytes, one reusable Bloom buffer, and context storage. It references original shared element bodies rather than cloning a maximum
payload for every operation. Removed/released elements are reclaimed only when
all original snapshot references retire. Adds and local removes after an
operation starts do not change that snapshot.

All local capabilities carry the original instance, row and checked never-reused
allocation id. A new announcement of the same logical listener has a different
`Port`. A new operation/channel cannot accept old `PeerSource`, `Delivery` or
`Effect` callbacks. These local identifiers never enter official messages.

The implementation supports current-set iteration through `elements()` and local
Rust `remove()`. **Active official SETI has no REMOVE or ITERATE IPC assignment.**
No such private command is invented. `dispatch()` handles all registered IPC
commands: CREATE, ADD, EVALUATE, LISTEN, ACCEPT, REJECT and CANCEL. CREATE/ADD do
not fabricate service ACKs. Unknown cancellation/rejection ids are harmless;
unknown ACCEPT produces the FAILURE result on its original set MQ.

## Native interfaces

1. Call `attach()` only after an local MQ is accepted. Decode official
   requests and pass them to `dispatch()`. LISTEN returns a logical listener;
   announce `listener_app()` on the CADET port and call `bind_listener()`
   for that original binding. Unbind/close the old port separately.
2. EVALUATE returns an immutable snapshot operation in `Opening`. Open its
   `operation_app()` on `operation_info().peer`. Only a end-to-end CADET
   source for that expected peer may call `bind_peer()`. Inbound channels must
   use `incoming()` with their original live `Port` and authenticated
   endpoint. Raw channel integers, plaintext app ids and peer-claimed metadata
   grant no endpoint authority. These are explicit trusted ports, like entropy;
   the pure owner does not claim to authenticate an arbitrary caller's bytes.
3. Call `progress_next(entropy)` to build at most one bounded Bloom filter. `prepare_peer()` and `prepare_client()` encode into a caller-owned final
   output buffer before accepting one original immutable effect. Retain those
   exact bytes through native completion/stop. `can_queue()` precedes actual
   native admission; `queued()` records admission, `exposed()` only an actual
   positive write, and `written()` only complete original writing. Protocol and
   result cursors advance on `written()`. Never substitute queue success or a
   canceled wait future for these physical facts.
4. An original never-admitted output can use `reject_prepared()`. A port
   completion proving zero exposure can use `unsent()` even after queue
   admission. It advances no protocol/result cursor. Exposed outputs cannot use
   either path. Partial suffixes must physically drain or their original source
   must stop. No exposed output is reencoded/replayed on a replacement channel.
5. `receive_peer()` consumes one complete original CADET application
   frame. Its `Delivery` is eligible only through `receive_ready()`; the first
   operation request remains uncredited until the listener suggestion actually
   writes and ACCEPT snapshots a set. `receive_done()` consumes that exact
   permission and permits the native adapter to issue its own CADET ACK. This semantic permission does not claim ACK writing or peer delivery.
6. `close_required()` requests channel retirement. Call `peer_lost()` only
   after stopping/detaching that original physical source; it returns original
   pending effect, queued/exposed state, uncredited delivery and physical cause. Expected cancellation/failure close is not success. `detach(client,cause)`
   similarly preserves the original MQ output facts and cancels its operations;
   peer channels still need separate physical close/drain. `retire()` recycles an
   operation only after peer stop and original immutable output settlement
   (plus terminal result writing if its client remains alive).
7. Drive `expire(now)` from the same explicit monotonic clock used for original
   deadlines. It requests failure/close, never invents a physical stop. The
   initial incoming timeout is finite; after the request is suggested,
   waiting for local ACCEPT follows pinned C's lack of a renewed timeout. Caller
   accept/evaluate deadlines and explicit cancellation remain available.

A slow local MQ retains at most its one original client output; other clients
and operations have independent bounded state. Output capacity refusal leaves
protocol/result cursors unchanged. Permanent element/context/filter policy
limits are explicit errors, not unbounded queues or fake successful results. The adapter must close/reject a source if its ordered input cannot be admitted
under policy; it must not stall a shared runtime indefinitely waiting for an
unavailable larger slab. One BF construction scans bounded slots; callers can
schedule it independently of socket polling for their chosen CPU budget.

## Wire and compatibility details

* Actual P2P messages are OperationRequest, ElementInfo, BF chunks and Done.
  There is no private element-list fallback or fragmentation header. BF chunks
  use the official 60 KiB complete-frame ceiling and consecutive implicit
  offsets. Every fragment's count/XOR/salt/size/k is checked before assembly.
* Counts and XOR agreement implement the official probabilistic intersection
  criterion; neither is an authentication proof of a malicious peer's inputs.
  Full and removal-delta results have their official status values. The sender
  that writes P2P DONE waits for the expected channel close before local
  DONE; the receiver validates count/XOR and drains local results before closing.
* Element hashes use native u16 size, native semantic u16 type, and opaque data.
  Bloom mingling uses native u32 salt. `Limits.native` selects that actual
  compatibility profile explicitly. No endian selector is added to the wire.
* RESULT has an unannotated u64 in pinned C: 24-byte prefix on its 64-bit ABI,
  20 on four-byte-aligned u64 profiles. `Limits.result_layout` uses the actual
  local consumer ABI, defaulting to `ResultLayout::native()`. It never guesses
  layout from payload length. Rust emits the element-type field in network order
  for the official C public consumer. Pinned C's producer omits `htons` there;
  copying that producer defect would corrupt the public consumer's result type.
* Pinned C does not populate OperationRequest.app_idX and routes by the actual
  CADET port instead. Rust emits the same zero field and never uses it as routing
  or endpoint authority. Optional context is one complete original nested
  message and must also fit the CADET application envelope (72 + context
  <= 64348), rather than becoming a permanently untransmittable accepted effect.
* Pinned C has zero-cardinality floating/cast UB, a first-fragment overflow gap,
  weak fragment XOR checks, and an unset generation-added field. Rust uses an
  ordinary all-zero Bloom for empty sets, checked assembly, consistent metadata,
  and immutable snapshots; it does not reproduce C memory/undefined behavior.
  Native adapters must report transport rejection when a C peer itself
  rejects an empty-set edge case, rather than fabricating interoperability.

Two focused models are supplied for central execution: two-core official
reconciliation with full/delta results, snapshot mutation and empty sets; and
original prepared/queued/partial-loss ownership, source/port generations, Bloom
fragment-header rejection, initial expiry and unknown ACCEPT failure.
