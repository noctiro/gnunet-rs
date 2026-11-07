# Bounded Resolver daemon core

Allocation-free `no_std` Resolver cache and lookup state machines. Hosts supply
storage, time, DNS effects and connection lifetimes. The machine-readable
`api-status.json` records the service criteria.

The modules contain exact byte machine-file parsers; original/search/PTR name handling; hosts and dynamic cache; and a transactional lookup owner using the existing official request4/response5 codec, DNS packet model and DNSSTUB request identities. Results preserve queried-name bucket insertion, exact lookup case versus case-insensitive insertion, reverse section/prepend order, strict UTC expiry,1025-bucket overshoot, Any A→AAAA sequencing, original shared deadline, CNAME fresh lookup/deadline, malformed/wrong-ID ignore, no-upstream30s wait, EOF and immediate/optional soft shutdown. No NSS/DNS replacement or TUN/interception helper is introduced.

## Caller storage

`owner::Resolver<'a>` borrows `Buffers<'a>` containing client/lookup/cache/effect/cleanup/blob metadata slices and one initialized byte slice. `Limits` separately sets per-name, per-record and CNAME work bounds. Record width65535 is supported without multiplying that width by every metadata slot. The host can use `Vec::try_reserve_exact` plus `resize_with`/`resize`, then borrow the buffers; no self-reference, leaked allocation, uninitialized storage or `Box::new(huge_array_return())` is required. A no_std host can supply static slices.

Create the owner with a nonzero caller epoch. Never reuse an epoch when resetting the same backing. Client, lookup, blob and effect identities include original scope/generation. Epoch, original backing identity and generation checks prevent stale results from binding to later clients or payloads.

`owner.make_scratch(second_buffers)` creates distinct `Scratch<'a>` with the exact same geometry. Scratch has no request/client/effect ports. A business transition validates scope, profile and capacities before copying. It copies logical buffers to scratch, mutates scratch, and swaps only logical storage on success. On error the original owner is unchanged and scratch may be dirty. Caller clocks, entropy draws and conversion scratch are external effects and are not rolled back. There are no socket resources inside these snapshots.

Two equal-capacity copies are required. A third matching Scratch is optional for test/checkpoint comparison, not required by the host. `examples/storage.rs` actually allocates and constructs a profile with clients64, lookups128, hosts1024, dynamic buckets1025, records4096, ordinary effects512 and two8MiB aggregate pools. On this target the owner control is696 bytes; vector reserved bytes are9,879,888 per store /19,759,776 per pair. These figures exclude allocator overhead/RSS and separate native-text/DNS parsing/TX scratch. The example checks connect→shutdown→Stop release. It does not claim that every record can simultaneously occupy65535 bytes; aggregate exhaustion is explicit `Capacity`.

Snapshots currently copy the entire initialized pool and metadata on each transaction. Pool compaction uses safe offset relocation with a bounded O(S²) metadata scan. These are correctness-first costs, not a throughput claim. The full profile does not prepay a381MB per-owner inline record-width product; that superseded implementation is absent from this implementation.

## Host execution contract

`Evaluation { mono, utc, idna, random, text }` supplies independent monotonic/UTC clocks, an explicit IDNA capability, entropy below the supplied bound, and caller conversion buffers. There is no default ASCII backend. Test-only ASCII capability rejects every non-ASCII input; capability or entropy errors remain explicit and atomic. Parse DNS with `gnunet_dns::Packet`, then feed the record view to `dns_result`; original packet/arena bytes may be reused after success because projected names/RDATA are copied to the pool.

`take_effect()` returns an `EffectTicket`; repeated calls retain the same in-flight effect. `effect(ticket)` borrows an `Output`, `StartQuery`, `CancelQuery`, `DropClient` or `Stop` view. `current_effect()` recovers the ownership ticket after a canceled drive future. Host code must copy an Output into a persistent, genuinely bounded TX queue before `release_effect(ticket)`, end the core borrow, and perform asynchronous writes from that TX owner. If TX admission fails, retain the original ticket and retry; do not discard bytes or manufacture completion. Local release is neither successful OS write nor remote processing acknowledgement.

For StartQuery, call the DNSSTUB resolve operation, which copies the packet. Then report the actual `Admission` through `query_admitted` (including its explicit `evicted` token), or an failure through `query_unavailable`; only then release its ticket. If admission cannot be adopted by the core, the caller still owns and must cancel that token. Normal send syscall errors must retain the DNSSTUB request's retry behavior. Deliver results only with the original lookup+stub generations. `stub_evicted` detaches the old association without an early END; the old lookup deadline cannot cancel the replacement slot owner.

Cleanup has lookup-sized reserved cancellation slots, separate from ordinary output capacity. Closing client slots retain a reserved close reason until physical close is acknowledged by local effect release. One `tick` processes one earliest due lookup; after draining effects, call it again at the same time while `next_wakeup` is due. Thus equal deadlines and EOF with multiple tokens make bounded progress even with E2. Cancellation effects precede later query admission. Final Stop supersedes individual cancels because the host must stop/drop the whole DNSSTUB and its sockets.

Direct `cache::Cache` component mutations may be dirty on error. The public Resolver stages these operations. Standalone cache users must provide their own transactional staging. CNAME recursion is replaced by an explicit finite work limit with atomic refusal, and stale C raw RequestSocket aliasing is replaced by generational detachment; these source differences are recorded, never described as silent official success.

## Host integration

`verify.py --upstream OFFICIAL_SOURCE --api-build NORMAL_BUILD --output DIR` captures commands, exact nonzero test names, expected compiler error codes, no-default dependency metadata, safe allocation JSON, before/after source hashes and artifact hashes. `tests/ui` independently requires only E0599 for staging authority and E0502 for a view used after release, plus successful controls with the same public types. No missing import/type error counts as a lifetime witness.

The [Resolver host](../../adapters/resolver-std/README.md) supplies startup,
machine files, DNSSTUB, service IPC, clock/entropy/IDNA, timers and cleanup.
The daemon core uses DNSPARSER/DNSSTUB; public FQDN helpers and native name
service calls belong to the client API.

The workspace integration uses relative workspace dependencies and the default
`gnunet::resolver_service` export. The verifier writes all targets and diagnostics
under its fresh output, pins Rust1.99.1, verifies the six-package feature-free
production tree, and checks exact45 requirement/source anchors against the
normalized `official-profile.json`. No removed application module is a current
dependency.
