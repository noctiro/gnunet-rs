# Native DHT service owner

The caller retains its listeners, SharedClock/Resolver, Instances, stop latch and entropy port. `Server::new` reserves bounded metadata and native CLIENT owners; enabled direct IP explicitly binds its UDP sockets and samples interfaces. It does not read a private key. `poll` fairly drives the enabled underlays, original PILS, local IPC and the same original DHT network work. The GNUnet underlay owns CORE, NSE, PEERSTORE HELLO monitor/STORE and TRANSPORT application sources; an IP-only configuration does not construct or poll those native clients. Local service readiness uses the PILS identity and enabled underlay readiness. When CORE is enabled its INIT_REPLY must agree with PILS.

CORE peer tokens and DHT peer/job tokens remain bound to their original generations. HELLO addresses are verified public metadata/dial candidates, not address authentication. Purpose6 path signatures and purpose7 local HELLO signatures share the same PILS queue, with distinct typed targets and original operation/identity facts. A whole native FIFO admission is distinct from whole CORE writing and remote processing. Partial/unknown writes are retained as original source facts and never replayed as PUT success. Local GET/PUT/monitor/HELLO commands use the same volatile cache and bounded owner. The ordinary HELLO cache ingress uses the installed BLOCK validator and the block's own expiration; it invents no publisher MQ.

Original canonical and native bounds are separate. Original job bounds are captured before business work and never renewed by peeking/polling/clock revision. Native guards precede canonical/provider polling; issued signature tombstones last until a callback or physical source retirement. Continuous monitoring has no daemon-wide deadline; a new finite monitor admission follows old source retirement. `begin_close` physically closes the same owners, and `poll_close` drains CORE returns without a clock/Resolver. `into_report` preserves unresolved prefixes and does not authorize quiescence. There is no storage worker, disk durability, hidden task, implicit Resolver or key loader in this library.

The standard SERVICE executable supplies configuration and original process resources to this native service composition. The ordinary neighbour controller starts an autonomous self-identity-hash HELLO search on the first logical DHT peer, pauses when the last peer retires, and schedules subsequent rounds using the reference minimum/jitter policy. Its same original round budget survives capacity refusal; resulting GET jobs still use the existing native Work ownership. Verified HELLO RESULTs feed a separate bounded address-candidate queue, alternating with PEERSTORE candidates; a candidate is consumed only after selected-underlay admission or a retained explicit address rejection. This is candidate validation, not authenticated reachability or a remote ACK.

Accepted local PUTs that have not entered any original CORE FIFO retain a
bounded original intent. This covers startup with no usable peer and safe
rerouting only after old unadmitted frames/signatures actually retire. A real
new peer wakes those intents. Any native FIFO admission permanently
ends the intent's retry authority, including later source loss or Unknown;
already prepared multicast siblings retain only their own original job debt. Client disconnect does not undo an already accepted service-owned PUT. This
adds no PUT acknowledgement: official message152 remains a TODO, and client
whole writing, service-local acceptance, native FIFO admission, whole writing
and remote storage/replication remain distinct facts.

The queue defaults to1024 intents and8MiB of retained payload Vec
capacities. Metadata and each payload are reserved before local acceptance;
payloads are allocated on demand, not as1024 maximum blocks. The one original
copy survives independent volatile-cache expiry/replacement and is borrowed
without another full copy on retry. The original canonical retention is at
most5minutes and never exceeds the block's original expiration; retry spacing
is at most5seconds. Count/bytes and shorter finite lifetimes are explicit
`network::Limits::unrouted_put*` policies. The native owner binds each PutId to
its first pre-admission native anchor once; all later frame/signature targets
also stay within that original hard, including after clock rollback. Known
output backpressure sleeps until capacity/routing changes or the original
bound; allocation/provider failures are not silently reclassified as pressure.

Each genuinely new unsubmitted attempt rechecks the installed BLOCK verifier. A semantic rejection retains its original intent/source/time metadata and
category separately; it does not become an empty result, successful routing or
a new request. Existing signature callbacks, CORE completions, source epochs,
positive prefixes and Unknown retirement remain with their original owners. `PutStats.submitted` means original FIFO admission only. Ordered original
PUT tokens use binary membership and native-bound lookup; pruning uses
O(n log n) membership work instead of repeated quadratic scans. Stable removals
remain O(n), with no extra payload copy or auxiliary allocation.

No product, model,
native, storage, crypto or official peer interoperability execution was performed;
the complexity improvement has not been benchmarked.

## P2P monitor last-hop classification

Received peer GET/PUT monitor notifications retain their original options and
add `LAST_HOP` only if no original forwarding job actually enters a CORE FIFO. A prepared frame, pending signature or cache RESULT reply does not establish
forwarding. The first admission settles non-last-hop classification;
otherwise every original child must actually retire before last-hop output. Issued signature tombstones remain attached until their original callback. Local client command notifications and RESULT monitoring keep their existing
semantics. The P2P wire frame is not rewritten for this monitor-only decision.

Each original observation retains one bounded frame per monitor client,
independently of the number of forwarding peers. Separate `monitor_fanouts`,
`monitor_frames` and allocation-capacity `monitor_bytes` policies default
to 256 groups, 128 recipient frames and 1 MiB. Preflight precedes the business
commit. Ready frames alternate fairly with ordinary local results; native queue
pressure retains the same original frame. Disconnect and monitor-stop prune only
original matching ClientIds/selectors. Close abandons notifications when their
local owners close, without claiming physical MQ quiescence, delivery or
signature retirement.

No monitor, product, model, peer,
signing, storage or official interoperability execution was performed.

## PUT path-size truncation

Before allocating a forwarded PUT or asking PILS to sign, the business owner
fits its route to an explicit `PutFrameLimit`. It keeps the longest borrowed
suffix of original signature elements and sets the truncation boundary to the
last removed signer. Existing truncation boundaries are replaced only when
further elements are removed. Zero retained elements still preserve the new
sender's original predecessor. Payload, expiration and retained signatures are
unchanged. New boundary bytes are included before choosing the suffix; a payload
that cannot fit still fails as `TooLarge`. An oversized old full path need not
pass u16 encoding before it can be truncated.

The standard native owner fixes the carrying limit before constructing any
business/provider owner. A whole DHT message is nested in a four-byte DHT_CORE
message, then in a CORE_SEND frame. Its cap is
`min(core.frame_bytes - 48, 65487, 64512 - 1) - 4` (64507 bytes for the default
CORE profile), further restricted by a smaller explicit caller policy. Aggregate
queue/source budgets and IP MTUs do not substitute for this per-message bound. The same selected fields determine encoding and original PILS signing material. This implements PUT processing in the public [LSD0004 draft07 section7.3.2](https://lsd.gnunet.org/lsd0004/draft-schanzen-r5n.html#section-7.3.2).

Only PUT size handling changed;
RESULT policy and original MONITOR/FIFO/Unknown/signature retirement semantics
retain their prior scope. No codec, model, signature, native or peer execution
was performed.

## Opaque unknown-type PUT transit

The selected BLOCK registry exposes its installed-type membership
independently of a block operation's result. `NetworkBlocks::type_capability` is
explicit and fallible; a missing/unavailable provider is an error, not absence. The built-in implementation uses the same real `Context` registry lookup.

A received peer PUT whose concrete type has no installed handler follows opaque
transit: original type/key/payload/expiration and normal routing, path validation,
size fitting, signing and MONITOR ownership are preserved. `Outcome::OpaquePut`
asserts no payload validity, cache admission, local query match, FIFO admission
or remote replication. It does not build an owned cache Entry or make an extra
whole-payload copy just for monitoring. Real recipient frames retain their
existing bounded allocations. ANY=0 is rejected before capability selection.

For an installed type, invalid blocks, unsupported algorithms/operations,
provider errors and resource failures retain their original rejection. None is
reclassified as opaque data. This implements the distinct unknown-type PUT
behavior in [LSD0004 section7.3.2 step2](https://lsd.gnunet.org/lsd0004/draft-schanzen-r5n.html#section-7.3.2)
and the fixed official receiver. GET, RESULT and local command policies remain
separate. Affected BLOCK/DHT/native/SERVICE strict macOS/Linux checks and the
allocation-enabled M0 DHT core check passed; no block, codec, model, signature,
native or peer execution was performed.

## Recorded-path recovery and RESULT reserved fields

The routed-message receiver verifies the underlay sender's separate
last signature first. A bad sender signature always fails. An Authentication
failure in an earlier recorded element removes that element and its prefix,
retains the exact predecessor boundary and verifies the surviving suffix again. A failure in GET removes all PUT elements. Other primitive/provider/resource
causes remain original errors. Strict whole-path proof APIs remain available
with the failure reason; they do not silently apply recovery.

The native business path carries updated flags, boundary and both PUT/GET
segments consistently into forwarding, monitoring and cache admission. Untouched
segments are borrowed; only the segment extended by the sender signature
needs an owned buffer. Original payload, expiration and surviving signatures
remain unchanged. Opaque PUT, size fitting and original job retirement retain
their existing separate semantics.

RESULT wire decoding retains its raw reserved16 field, including nonzero values. Forwarded RESULTs encode that original field unchanged. New local/cache replies
explicitly originate zero. This follows public LSD0004 section7.5.1; the fixed C
receiver accepts nonzero but its forwarding path clears it, a documented source
difference rather than a Rust requirement. No extra field is added to the wire.

Affected macOS/Linux strict core/native/SERVICE checks, M0 allocation-enabled
DHT and M0 noalloc wire checks pass. No signature, codec, model, peer or official
interoperability execution was performed. Historical test/model targets were
not requalified by these selected production compilation checks.

## Opaque GET/RESULT and ready-response priority

Installed-type membership belongs to the common fallible `Blocks` contract. Local and peer GETs preserve an absent type's original XQUERY and serialized
RESULT_FILTER without invoking an unknown codec or inventing a nonce/filter
format. ANY remains a separate valid wildcard; concrete PUT/RESULT type0 is
rejected. A missing group from an installed handler is distinct from absence,
and installed validation, operation, provider and resource errors remain errors.

Unknown RESULTs retain their path/sender verification, query key/type and
original local UID/QueryId or reverse-route correlation. Borrowed reply metadata
avoids constructing a trusted Entry or another whole-payload copy. They never
enter trusted cache/local matching or produce Last. Independent payload-hash
seen state is allocated on demand, with per-route count and aggregate element
bounds; output reservation precedes committing it. This follows the public
unknown-type processing rules even where the fixed C receiver drops unsupported
RESULTs or serializes an absent filter as empty.

Payload-level filtering matches the fixed C local consumer. It does not promise
lossless enumeration of identical bytes under every BTYPE. Concrete Last is
conservatively More for ANY, consistent with the C local wildcard path. For an
ANY candidate, the concrete query validator's explicit No means only that
this implementation is Irrelevant; the original wildcard request survives unchanged. Generic malformed/unsupported/provider errors are never caught as that No.

Pending constructors retain a typed Get/Put/Result class. A borrowed bounded
iterator prefers RESULT while preserving order within classes. Native selection
skips genuinely busy resources without copying unselected payloads. Original
retirement requests are issued idempotently and do not block an independently
ready send; they retain their tombstones until terminal/physical closure. Already issued signatures and admitted CORE requests are not preempted. The
existing CORE priority field uses URGENT2 for RESULT and BEST_EFFORT1 for other
DHT payloads; critical-control3 remains separate. No wire field was added.

Full current mixed-node acceptance remains open.

## Recent reverse routes and terminal replies

Reverse routes use a private preallocated deque in original admission order. Once every fallible query/filter/XQUERY/output/monitor preparation succeeds, a
new accepted GET at the configured route cap evicts only the oldest route and
appends its replacement. Front eviction does not shift the entire table. A
repeated live request merges in place and retains its original age and until. The configured recent-window size and TTL remain Rust resource policies.

A cache FILTER_LAST response removes an existing matching reverse route or
avoids creating a new one. A genuinely terminal forwarded RESULT removes that
reverse route after successful output/cache preparation. Multiple result updates
commit in one stable pass using original increasing indices, so deleting one
entry cannot redirect a later update. ANY's conservative More and opaque
nonterminal filtering remain separate; only a Last closes metadata.

Eviction/Last drops that route's own filter/seen state. It does not cancel, renew,
replay or claim completion of original signatures, pending frames or admitted
CORE work. Those physical debts keep their original Job/Peer and bounds.

## Forwarded fields and received blocks

Received P2P GET/PUT replication levels pass unchanged through private u16
forwarding interfaces. The routing planner bounds fanout independently. A new
local origination or retry applies the existing maximum16 profile explicitly;
the original local u32 request, monitor fields and retained intent stay intact. No new local IPC range rejection or implicit high-bit truncation is introduced.

Before RESULT processing can commit terminal route/query changes, the owner
captures whether its original query hash has a live reverse route or local
query. An unmatched RESULT retains bounded independent monitor observation,
without allocating a trusted cache entry, delivering a query reply or creating
forward work. Duplicate/irrelevant replies do not imply an absent query.

Only installed and validated HELLO blocks enter discovery. Valid HELLO PUT now
uses the same existing all-address TRANSPORT hint path as valid RESULT; a valid
unmatched HELLO RESULT still reaches discovery, which precedes the pending-query
gate in the protocol. Opaque outcomes grant no such authority. Existing
try_connect, address bounds and physical owners apply. A hint is not a successful
connection. Affected macOS/Linux strict core/native/SERVICE and M0 alloc static
checks pass; no runtime acceptance is claimed.

A local PUT for a nonzero block type whose handler is absent follows the
same original bounded network PUT intent and retry path as a validated local
PUT. Type absence grants opaque transit only. It does not construct a validated
cache entry, satisfy a local query, or claim storage, replication or remote
processing. The local PUT monitor may observe the submitted bytes. Wildcard type zero remains invalid for PUT. An installed handler's malformed,
signature, key-association, expiration or unsupported-operation refusal remains
an error; a provider failure cannot be reclassified as handler absence.

An unsubmitted retry rechecks the registry capability. An absent type
keeps its original bytes/options/key/expiration and original retention target;
a newly installed handler must validate before a new handoff. The first real
native FIFO admission permanently retires that intent as before. Disconnecting
the submitting local MQ neither fabricates a send receipt nor replays an already
admitted PUT. The three new pure boundary
cases compile without execution. Native and official interoperability behavior
remain unverified for this revision.

## Direct IP composition and own HELLO

`Limits::underlays` selects the GNUnet backend, the direct IP backend, or both. One business/cache owner is shared. A raw IP identity prefix is a peer claim,
not a CORE authenticated connection. Original native endpoints and pending
sends retain their source generation and truthful completion/retirement facts.

The local DHT HELLO combines addresses from the latest PILS announcement
with the IP owner's current local interface URLs. Its original PILS expiration
is preserved. A purpose7 request under that exact PILS identity must
complete and its copied frame must retire before the new set is installed. An
address change during signing retains the original snapshot until that result
retires, then signs the new snapshot; an old signature never authorizes a new
local address revision. The standard HELLO block and DHT message encodings are
used without a new wire field. Selected official signature coverage remains
explicit; the normal profile does not authenticate address bytes.

This owner never calls PILS FEED: FEED replaces the global address set and can
change the node identity. It never reads a private key or manufactures a
PILS_PEER_ID observation. The upstream IP plugin reports local addresses but
does not currently feed them into PILS; the explicit local HELLO composition
closes that publication gap within the Rust implementation. Source regressions
use cryptographic fixtures and explicitly modeled provider responses; they
do not establish native or official-peer interoperability.
