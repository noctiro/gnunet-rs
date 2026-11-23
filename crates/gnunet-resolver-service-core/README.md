# Bounded Resolver daemon core

Allocation-free `no_std` Resolver cache and lookup state machines. Hosts supply
storage, time, DNS effects and connection lifetimes. The machine-readable
`api-status.json` records the service criteria.

The transactional lookup owner uses the official request4/response5 codec.
Datagram mode handles machine files, hosts and dynamic cache, search names,
DNS packet effects, and DNSSTUB identities. Native system mode emits typed
questions and accepts address or reverse results without a separate cache.
Both modes retain their original deadline and scoped cancel identities.

## Caller storage

`owner::Resolver<'a>` borrows `Buffers<'a>` containing client/lookup/cache/effect/cleanup/blob metadata slices and one initialized byte slice. `Limits` separately sets per-name, per-record and CNAME work bounds. Record width65535 is supported without multiplying that width by every metadata slot. The host can use `Vec::try_reserve_exact` plus `resize_with`/`resize`, then borrow the buffers; no self-reference, leaked allocation, uninitialized storage or `Box::new(huge_array_return())` is required. A no_std host can supply static slices.

Create the owner with a nonzero caller epoch. Never reuse an epoch when resetting the same backing. Client, lookup, blob and effect identities include original scope/generation. Epoch, original backing identity and generation checks prevent stale results from binding to later clients or payloads.

`owner.make_scratch(second_buffers)` creates distinct `Scratch<'a>` with the exact same geometry. Scratch has no request/client/effect ports. A business transition validates scope, profile and capacities before copying. It copies logical buffers to scratch, mutates scratch, and swaps only logical storage on success. On error the original owner is unchanged and scratch may be dirty. Caller clocks, entropy draws and conversion scratch are external effects and are not rolled back. There are no socket resources inside these snapshots.

Transactions use two equal-capacity stores. Each copy includes the initialized
pool and metadata. Pool compaction uses safe offset relocation with a bounded
O(S²) metadata scan. Aggregate exhaustion returns `Capacity`.

## Host execution contract

`Evaluation { mono, utc, idna, random, text }` supplies independent monotonic/UTC clocks, an explicit IDNA capability, entropy below the supplied bound, and caller conversion buffers. There is no default ASCII backend. Test-only ASCII capability rejects every non-ASCII input; capability or entropy errors remain explicit and atomic. Parse DNS with `gnunet_dns::Packet`, then feed the record view to `dns_result`; original packet/arena bytes may be reused after success because projected names/RDATA are copied to the pool.

`take_effect()` returns an `EffectTicket`; repeated calls retain the same in-flight effect. `effect(ticket)` borrows an `Output`, `StartQuery`, `CancelQuery`, `DropClient` or `Stop` view. `current_effect()` recovers the ownership ticket after a canceled drive future. Host code must copy an Output into a persistent, genuinely bounded TX queue before `release_effect(ticket)`, end the core borrow, and perform asynchronous writes from that TX owner. If TX admission fails, retain the original ticket and retry; do not discard bytes or manufacture completion. Local release is neither successful OS write nor remote processing acknowledgement.

For StartQuery, call the DNSSTUB resolve operation, which copies the packet. Then report the actual `Admission` through `query_admitted` (including its explicit `evicted` token), or an failure through `query_unavailable`; only then release its ticket. If admission cannot be adopted by the core, the caller still owns and must cancel that token. Normal send syscall errors must retain the DNSSTUB request's retry behavior. Deliver results only with the original lookup+stub generations. `stub_evicted` detaches the old association without an early END; the old lookup deadline cannot cancel the replacement slot owner.

For `StartSystemQuery`, adopt the original operation with `system_admitted`
before releasing its start ticket. A failed start uses `system_unavailable`
to retire the lookup and its ticket. Submit typed results with
`system_result` after servicing due deadlines. The core queues address
or name responses and the final END, preserving the original wire ID.

The lookup-sized reserved cancellation lane has capacity independent of
ordinary output. One `tick` processes one earliest lookup. Call it again
after draining effects while the next deadline is due. Cancel effects
precede later admissions. Final Stop transfers retirement of the entire
backend to the host.

Direct `cache::Cache` component mutations may be dirty on error. The public Resolver stages these operations. Standalone cache users must provide their own transactional staging. CNAME recursion is replaced by an explicit finite work limit with atomic refusal, and stale C raw RequestSocket aliasing is replaced by generational detachment; these source differences are recorded, never described as silent official success.

## Host integration

`verify.py --upstream OFFICIAL_SOURCE --api-build NORMAL_BUILD --output DIR` captures commands, exact nonzero test names, expected compiler error codes, no-default dependency metadata, safe allocation JSON, before/after source hashes and artifact hashes. `tests/ui` independently requires only E0599 for staging authority and E0502 for a view used after release, plus successful controls with the same public types. No missing import/type error counts as a lifetime witness.

The [Resolver host](../../adapters/resolver-std/README.md) supplies startup,
machine files, DNSSTUB, service IPC, clock/entropy/IDNA, timers and cleanup.
The daemon core uses DNSPARSER/DNSSTUB; public FQDN helpers and native name
service calls belong to the client API.

The workspace integration uses relative workspace dependencies and the default
`gnunet::resolver_service` export. The verifier writes all targets and diagnostics
under its fresh output, pins Rust1.100.0, verifies the six-package feature-free
production tree, and checks exact45 requirement/source anchors against the
normalized `official-profile.json`. No removed application module is a current
dependency.
