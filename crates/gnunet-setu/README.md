# Official SETU union core

Pure SETU algorithms, active IPC/P2P codecs, bounded sets and operation/service
coordination. Native sockets and CADET ownership belong to the
[host adapter](../../adapters/setu-std/README.md).

The protocol reference is official v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. Active sources are
`src/service/setu/{setu.h,setu_api.c,gnunet-service-setu_protocol.h,`
`gnunet-service-setu.c,ibf.c,ibf.h,gnunet-service-setu_strata_estimator.c,`
`gnunet-service-setu_strata_estimator.h}`, `src/include/gnunet_setu_service.h`
and `src/include/gnunet_common.h`.

## Install boundary

The new gnunet-setu crate has default=[] and uses core plus caller-owned slices
for IBF/strata and the Codec interface. Explicit alloc adds set, union and
service modules. Explicit zlib additionally enables the already pinned
miniz_oxide 0.9.1 with-alloc implementation. No other registry version is added. SDK default embedded graphs must not implicitly enable alloc/zlib.

The crate exposes pure reconciliation engines and host ports. The
[native SETU service](../../apps/gnunet-service-setu/README.md) composes MQ,
CADET and clock ownership. Pure model execution does not qualify that service.

## Implemented behavior

- official/setu.rs borrows every active CREATE, ADD, LISTEN, EVALUATE, ACCEPT,
  REJECT, CANCEL, incoming request, result and union P2P message. Reserved fields
  and source padding are retained where significant; encode preflights exact
  framing/lengths. ABI selection is explicit, never a private negotiation field.
- ibf.rs derives native64 keys through the GNUnet HKDF, calculates the
  source CRC/index sequence, deduplicates bucket indices, performs checked
  insertion/removal/subtraction and signed peeling, and packs/unpacks actual
  20-byte-stride slices including ignored wire padding. Scratch is caller-owned.
- strata.rs implements all 8 estimators, 32 strata, 79 buckets and 3 hashes,
  nested trailing-one insertion/removal, raw count1/2/4/8 serialization,
  and directional difference estimates with extrapolation and caller79-cell
  peel scratch. An estimate never substitutes for reconciliation completion.
- set.rs creates exact native16 size/type + data SHA512 element fingerprints and
  uses sorted immutable Rc<Element> owners for deduplication and stable snapshots.
  Later add/remove cannot mutate an operation's original membership. Active C
  has no REMOVE IPC/public function: remove is an internal Rust method only.
- union.rs and union/work.rs implement zlib strata exchange, checked
  full/differential mode selection, incremental filter generation, contiguous
  receive slices, subtraction/peeling, full64-byte hash offers/demands, exact
  demanded-element authentication, complete and missing-only full transfers,
  bounded larger-IBF active/passive retries, DONE/FULL_DONE/OVER and result modes.
  Every physical output is immutable and branded to the original Union. Repeated
  borrows preserve its token; sent accepts only that original lease. WouldBlock
  retains the original input/work, including a peeled key waiting for admission.
- service.rs owns bounded app/set/listener/incoming/open/operation lifetimes.
  It dispatches official requests, snapshots EVALUATE/ACCEPT, issues
  Listen/Unlisten/Open/Send/CloseClient/Close, validates connected peer,
  retains original deadlines without reset, and preserves cancellation/cleanup
  debt. An incoming listener and accepting set may use separate app MQs as in C.
  Client/operation handles have unforgeable local Rc identity and never reuse a
  checked serial. Incoming IDs are bounded nonzero original official u32 IDs.

Union ADD_LOCAL events carry received immutable elements; ADD_REMOTE
carries the demanded local element when symmetric mode identifies it. The set itself is never silently changed by an operation: the application can
apply returned ADD_LOCAL elements according to the public API. Terminal DONE or
FAILURE becomes available only after the host retired callback, not from
queuing/sending a frame or passing a Book TTL. Cancellation suppresses all result
callbacks and retains any leased suffix until exact sent/physical retirement.

## Host integration contract

1. Configure one explicit source Abi and independent set/union/service Limits. A host supplies exact finite original time/expiry at evaluate/incoming; it
   owns a canonical clock listener for next_deadline and calls expire using real
   time. Clock errors must be propagated via abort/cleanup, not replaced by now.
2. Register an application MQ with connect and dispatch complete frames
   through receive_client. Retain moved Incoming/ServiceResult until that exact
   app MQ admits/writes them; moving a pure observation is not an app ACK. An
   encode/admission/transport failure is an host failure: use abort or
   physically close the app source and report client_closed.
3. Listen/Open effects are original intents. Only bind/open completion
   calls listener_ready/connected. A failed listener_ready Err means the exact
   failed original bind attempt has already retired. connect_failed likewise
   means the exact failed original attempt has actually retired. Late cancelled
   opens/binds must be physically closed before retired/listener_closed.
4. Retain a Send effect's original operation, Transmission and immutable bytes
   across pending/partial writes; call sent only after that whole original local
   frame was actually written. Feed received bytes to that original peer
   operation only. Neither a completed local write nor a remote input grants any
   new private wire credit or operation authority.
5. Close requires physical close of that exact original channel/attempt before
   retired. Actual app closure calls client_closed; issued listener/bind scopes
   remain until Unlisten and listener_closed, including late bind cleanup. Host cancellation and hard IO budgets must actually close original native
   sources. shutdown requests the same original effects, and is_quiescent checks
   callback consumption. Neither source slots nor terminal callbacks are
   recycled merely because a logical deadline elapsed.

The coordinator issues each Send lease once while direct Union.outbound permits
reborrowing the same token. An externally dropped pending future must retain its
original operation/lease in the host adapter; never request a replacement or
rebind a new channel under the old scope. The host must implement bounded actual
physical retirement even if a peer or local partial write stalls permanently.

## Source ABI and active-source quirks

- GNUNET_NETWORK_STRUCT_BEGIN/END are empty in pinned common.h; only explicit
  GNUNET_PACKED members are packed. Accept length is56 on align64=8 or52 on
  align64=4; Result prefix is24 or20, with source padding. Evaluate prefix is144;
  Incoming40; initial P2P Operation72. Abi::native selects the Rust target
  ABI, while explicit Abi{order,align64} supports a known matching C deployment.
- Options' upper_bound/RTT/bucket_factor/hashes u64 values, IBF size32/salt16/
  counter-width16, key64/CRC32 arrays and element-hash size/type16 inputs are
  native order in active C. Lower bound32, request IDs, counts and other
  documented network scalars stay BE. No endian fallback or invented field exists.
- C writes htonl(salt32) into native16 then promotes it through ntohl. The codec
  exposes exact salt_field/effective_salt; new Rust retries use effective salt0
  and strictly larger checked odd bucket sizes. Salt is an internal valid filter
  choice, not an authenticity primitive or fabricated entropy.
- Active C does not populate OperationRequest element_count/app_idX. Incoming
  accepts its CADET port/peer authority rather than rejecting zeros in
  those unused advisory fields. Real strata/full size claims activate bounds.
- Active full-mode control allocates an extra16 zero bytes; canonical output
  preserves that total32 size and decoding retains trailing source padding.
- Outgoing strata uses zlib SEC count1. C's raw SE checker wrongly expects
  the all8 size for variable counts; raw receive accepts an exact declared count
  but new output does not depend on that C raw-checker defect.
- Largest outgoing IBF slice is3275 buckets so 16+20*N fits65535; C's3276 macro
  crosses that framing limit. Bucket growth/round limits and finite index
  trials turn pathological filters into failures, never synthetic success.
- Empty IBFs choose width1 instead of C clz(0); malformed signed overflows are
  refused. Keys with >32 trailing ones stop at strata storage. Internal
  remove is the defined inverse of insertion, instead of the C unused remove bug.
- Mode selection uses checked finite arithmetic. C's negative float-to-unsigned
  counter-cost conversion is undefined; that case selects valid differential
  mode unless force_full. Internal mode choices may differ while wire remains
  official. Empty-set full selection and force modes remain callable.
- Contradictory local force options fail before service admission. An active
  force-delta option selects differential transfer even for an empty set and
  rejects incoming full-mode controls; force-full rejects incoming IBF slices
  before any filter or remote-size state changes. The normal original close
  obligation remains after peer rejection. This enforces the public option
  contract in Rust; it does not repair the official C chooser's unused delta flag.
- Active C full-mode SYMMETRIC does not produce ADD_REMOTE; this core preserves
  that observable limitation. It does not invent remote-difference reports from
  a full transfer where the sender cannot know the receiver's initial overlap.
- Peer element data can fit65527 while ABI Result wrappers are larger. Codec
  encode checks the complete result length and returns TooLarge when a
  particular app result cannot fit. A native host must fail/retire that original
  operation on such a output failure; no private fragmentation is invented.

The key64/CRC/strata are only reconciliation hints. Actual full SHA512 hashes and
native size/type/data fingerprints authenticate demanded content. CADET/PILS peer
identity and authentication remain external capabilities; this core does
not replace them with a hash of a public key or a locally constructed ACK.

## Resources and scheduling

All growing resources have explicit independent bounds. Default per-set limits
are4096 elements/16MiB; per-union8192 known elements,32MiB fresh received payload,
16384 received records,8192 reports,1024 output frames/8MiB,1048576 maximum IBF
buckets and32 rounds. Service defaults32 client slots/8 operation slots. These
are configurable local capacities, not wire promises. Payloads/cells allocate
only when needed; no thread or per-peer runtime is hidden. Immutable Rc snapshots
share payload bytes and use bounded metadata instead of copying data. One caller-owned Zlib state can serve sequential operations. advance(budget)
handles one element, one original IBF peel/slice, or the fixed bounded estimator
calculation per action. A peel scans at most the configured filter shape;
estimation scans the fixed32*79 prefix per estimator. Explicit bounds remain
necessary when choosing a scheduling budget; this is not a constant-time claim.

## Checks

Run `cargo test -p gnunet-setu --all-features --locked` for packing, peeling,
nested strata, full/delta exchange, snapshots, lease scope, cancellation and
physical retirement controls. These pure tests do not run a normal C peer.
