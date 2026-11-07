# RECLAIM business core

`gnunet_reclaim::business` is a callable `no_std + alloc` business engine for the
active GNUnet v0.29.1 RECLAIM operations. It uses the existing public object,
list, GNS-record and local IPC codecs. It creates no socket, resolver, service,
key, random source, persistent store, scheduler, worker or thread. Default
noalloc builds keep the existing codec-only modules.

## implemented paths

- Store/update attributes and credentials, assigning an explicitly supplied real
  entropy result only when the original object ID is zero. Newly assigned IDs
  are checked against a NAMESTORE scan and other IDs in the same plan.
  The relative expiration and object serialization are stored under the
  official data-to-string identifier label. A store response is emitted only
  after its original NAMESTORE code0 completion. The C credential
  pre-lookup whose contents are ignored is unnecessary here.
- Delete attributes/credentials, purge attributes referencing credentials that
  no longer exist, and update affected ticket refs/presentations. Each actual
  provider write is separately retained/settled. RP TXT and other records are
  preserved; no C temporary-array bounds/forgotten-TXT bug is reproduced.
- Issue or reuse tickets. Reuse requires exact RP bytes and exact selected ID
  and required-presentation sets in a observed ticket row, including the
  capability issuer/label match. Otherwise the engine requests the actual
  credential presentation(s), one per credential, then fresh entropy,
  builds the records and waits for the original NAMESTORE result.
- Consume the mutable GNS-name capability. The first scoped lookup uses
  official ANY0 to retrieve RP TXT, attribute refs and presentations together.
  The engine compares bounded exact RP bytes, then performs bounded sequential
  scoped lookups of the referenced attribute labels. Actual absent
  results contribute no fabricated attributes. Only the completed original
  queries can produce the final consumed result. No signed/private ticket
  protocol, fixed audience key, JWT verification or resolver is invented.
- Revoke: derive/check the original issuer, collect the referenced rows,
  request fresh IDs, then actually delete the target ticket, write each moved
  attribute, delete its old location and update other refs. An old location is
  never deleted before its original new-location success. There is no claim
  that multi-label revocation is atomic or immediately invalidates cached GNS
  records. Partial/cancelled/unknown outcomes retain completed steps.
- Attributes, credentials and ticket iterators use a bounded NAMESTORE
  scan, then a frozen snapshot and one initial result credit. Each NEXT
  grants one more item. App output written does not grant credit. Only the real
  provider END permits natural iterator END, and that end finishes only after
  its exact original app frame is wholly written. A failed scan emits **no fake
  iterator END**: the native host must close its original app MQ instead.

The capability is exactly `base32(random32).typed-public-ztld`, not an opaque
new binary ticket. `identifier_label` implements the real52-character Crockford
encoding. `capability` parses the current GNS-name/typed-zone form. Issuance
stores public `RECLAIM_ATTRIBUTE_REF`32byte values and serialized
`RECLAIM_PRESENTATION`, raw RP bytes in TXT (without a terminator), plus a private
`RECLAIM_TICKET` containing the terminated name. The relative refresh
interval defaults to the official one hour. Ticket names and URI limits remain
those in the existing official codec.

Authority scans validate known RECLAIM object encodings before planning. The
normal service schema has one attribute or credential per canonical ID label;
ambiguous multiple objects, zero/mismatched authoritative IDs and malformed
objects are refused instead of following C unchecked casts/NULL/array UB.
Unknown record types and unrelated normal NAMESTORE rows are preserved. New
STORE effects preflight the **whole NAMESTORE frame**, including its
private-key, per-set and label prefixes; permanent oversize is TooLarge rather
than an endlessly pending native credit or invented fragmentation.

## API and original ownership

1. Create a caller-owned shared `Factory::new(Limits)`. It owns aggregate
   zeroizing payload, metadata, table, job and source resource accounting.
2. A trusted native/provider owner calls `factory.bind(Provider)` only
   when that source is actually usable. `Source` is an opaque local allocation
   and never claims endpoint authentication, socket creation or key derivation.
   `source.lost()` permanently revokes new use after loss/close; it is not
   the retirement receipt for any in-flight operation.
3. `factory.start(ipc::Request, now, deadline)` retains the original complete
   request once, including its original RID and opaque secret zone material.
   It returns an independent `Job`, not a private network operation identifier.
   The caller maps the original accepted app source and RID to that owner.
4. `job.prepared()` borrows the exact original `Effect` and `Action`. Native
   ports are explicit: `PublicKey`, `Identifier`, `Scan`, `Store`, scoped
   `Lookup`, and `Presentation`. Native adapters preserve the original
   SDK operation/epoch, deadline and immutable frame associated with this
   token. Wrong Factory/source/operation tokens are rejected.
5. Only after native admission call `admitted`. Report positive
   original bytes with `exposed`, and whole original writes with `written`.
   Actual remote NAMESTORE/GNS results require the original whole write;
   credential/entropy/key library ports require no fake socket callbacks.
6. A scan feeds checked original rows through `row`, including the exact
   matching original key, and calls `complete(ScanEnd)` only on END.
   Capacity leaves that borrowed input untouched: retain its original frame
   for retry or explicitly stop/retire the source. A valid final `complete`
   consumes the original provider receipt once, even if later business memory
   allocation fails; do not replay it.
7. `response()` borrows one immutable, already encoded official result. Keep its
   exact `Output` as app-frame metadata and report `output_queued`,
   positive `output_exposed` and `output_written`. Queue/write completion never
   proves app consumption, GNS publication, durability beyond the provider's
   own contract, or extra client NEXT credit.
8. Cancel/STOP uses `job.cancel`; no RECLAIM RPC CANCEL/STOP ACK is fabricated.
   `expire(now)` never extends the original deadline and detects a regressing
   supplied monotonic clock. It leaves admitted provider/queued output debt
   intact. `retired` is legal only after original native cancel/physical
   stop quiescence, including for revoked sources. `output_lost` records actual
   original app-MQ loss independently of provider debt. No cleanup method needs
   a clock sample.

`status()` retains the first terminal reason, successful store count,
last raw NAMESTORE code/exposure, an indeterminate-outcome flag and
separate provider/output debt. A cancelled original late Stored0 may add the
completed step, but never resumes the next migration or emits success.
Unknown results never replay or imply rollback. Unknown on one RPC is not a
fabricated physical loss for other operations using a still-live shared MQ;
the provider owner handles any backend fence/recovery/source loss.
Dropping a Job does not magically cancel independent external IO. A native
owner must keep its own original operation and drain/close accounting and use
`quiescent()` before claiming its coordinated shutdown is settled.

For protocols without a business error field, local End state is explicit.
An issue failure uses the official missing-ticket result. Iterator failure
requires physical app-source close; it cannot be represented as natural END.
Consumed authentication/RP mismatch returns logical GNUNET_NO0; ordinary consume
failure uses SYSERR and success uses logical GNUNET_OK1 in the correct BE32
field. The existing decoder still preserves the pinned C producer's erroneous
htons-in-u32 word when it receives that producer; this Rust producer does not
repeat the native-endian mistake.

## Credential provider contract

A host can fulfill the original `Presentation` effect using the
[credential provider](../gnunet-reclaim-credentials/README.md):

```rust,ignore
let p = gnunet_reclaim_credentials::presentation(credential, selected)?;
// Complete only the same admitted Effect/Source; the core verifies id/kind
// binding and copies its exact serialization into the original bounded quota.
```

Pinned Meson activates BASIC STRING/JWT. JWT presentation is the **complete
original credential payload**, even when only some attributes were selected.
It is not selective disclosure, signature/issuer/header/expiry verification or
an authentication assurance upgrade. The companion default reports inactive
PABC/unknown semantic support as unavailable rather than generating a fake proof.
This core stores opaque unknown credential formats but issues a backed ticket
only after a configured presentation provider completed. Consume returns
serialized presentations; it does not add a mandatory verifier absent
from the active C protocol.

## Resource/performance boundaries

Payloads and persistent derived capability IDs use zeroizing owners, without
ordinary Clone/Hash/JSON/private byte Debug. Action Debug explicitly redacts
capability labels and keys. Checked per-job/source brands and counters are local
Rust metadata; none enter official messages. The aggregate quota counts actual
Vec capacity, payload/owner metadata and Rc allocation/layout storage. Tables
allocate/grow fallibly with amortized bounded capacity; a growth retains charges
for both old and new buffers until the old one is released. One pending effect
and one pending output per job avoid duplicate frames/background queues.

Defaults:32 jobs,16 shared provider sources,256 scan rows,256 records/items,
16MiB aggregate bytes and65535 complete frame bytes. No per-peer thread/MQ is
created. A32million-unit per-job conservative comparison budget is never renewed.
It preflights scan planning costs and charges subsequent identifier/consume
work. Configured maxima refuse excessive work explicitly. These units bound
algorithmic comparisons, not measured CPU time. The engine uses bounded linear
snapshot searches/sequential referenced lookups, not a secret-derived hash
index. This avoids uncontrolled fanout but can cost more latency than parallel
lookup. Table metadata/Rc fixed allocations retain the existing standard
allocator-abort behavior on global OOM; payload/table buffers otherwise use
fallible allocations. External native buffers and allocator bookkeeping require
those native layers' independent budgets; this is not a process RSS promise.

The multi-label plans have no cross-label transaction/CAS primitive in the active
NAMESTORE protocol. Native hosts must serialize their own overlapping authority
mutations where appropriate; another external writer can race the scan. No fake
lock, wire TX_CONTROL, global recovery/rollback or atomic revocation claim is
introduced. Expiration/publication and cryptographic record authenticity remain
the NAMESTORE/GNS provider's contracts. Caller monotonic timestamps and
provider sources must come from the same configured runtime context; the pure
engine creates no ambient clock or Resolver.

## Host interfaces

This is callable **business core source**, not a production RECLAIM
SERVICE daemon. Still required are the original accepted-MQ/RID registry,
listener/ACL/PROGRAM foreground, native NAMESTORE scan/store and existing
GNS-client bridge, source-clock/SDK-operation mapping, entropy and identity
public-key adapters, local credential-provider dispatch, fair polling and finite
physical shutdown/drain. The already integrated RECLAIM native client is not
such a server. No GNS host/resolver/recovery implementation or stopped
branch is inspected, resumed or reassigned by this package. A provider may use
an explicitly configured existing GNS service via the existing client.

The `reclaim-alloc` SDK feature exposes this business layer. Native service
ownership remains outside this core.

## References

The implementation follows official commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, especially
`src/service/reclaim/gnunet-service-reclaim{,_tickets}.c`, the public service/lib
headers, object serializers and active plugin build.
