# GNS service owners and official IPC frontend

This package supplies the current pure-resolver manager, native dependency
providers, ordinary DNS/system/files-profile composition and official type500/501
IPC Server. `gnunet-service-gns` provides the standard SERVICE process lifecycle. Full security is supplied by the separately implemented validating DNS factory;
there is no successful dummy provider or client-as-server substitution. These
source components do not claim runtime or mixed-node acceptance.

`Manager` owns the current `gnunet_gns::Resolver`, a bounded query table and one
explicit provider operation per original query. The public ports use the current
`EffectKind` shape. The historical native GNS draft is only a source reference;
its DNS authority field and older native APIs are not a current ABI.

Every request has one finite source-clock target and one original native target. All nested effects and any read reconnect inherit those exact bounds. Callers
poll `poll_native_guard` before sampling their shared clock and pass that sample
to `poll`. Query native alarms remain effective while the source clock is
unavailable or rolled back. `poll_close` and explicit cancellation need no source
time and do not admit new ordinary work. The installed SERVICE retains one SharedClock and broker rather than
substitute a second time/resolution domain.

A native failure is consumed for only its original `EffectId`. Shared-source
failure/recovery is a separate owned observation and cannot clear unrelated
queries or declare an old mutation complete. Provider read reconnect belongs to
the same original operation; potentially exposed NAMECACHE insertion cannot be
replayed. Invalid DHT candidates remain on the same original GET until a valid
candidate, exhaustion, budget exhaustion or cancellation. Authenticating the
original encrypted GNS block remains the existing resolver's responsibility.

Successful local admission/write is not a revocation answer, cache reply,
NAMECACHE store ACK or DHT result. Receipt kinds are checked against the original
effect, and record-view allocation is bounded by returned records and the
resolver's configured resource caps. A late callback is retained as a distinct
observation and cannot finish an already expired lookup.

Cancellation does not Drop an operation and call it complete. The operation is
fenced once and retained while its real `poll_close` runs. A distinct cleanup
error does not imply `Closed`; the provider's terminal report is returned
in `Event::Retired`. A new effect for that query is admitted only after the old
operation actually retired. Results may be consumed only after that original
operation is gone, while unrelated requests continue fairly. The caller must
preserve owned failure and retirement events even if the final lookup succeeds
(for example when optional cache insertion fails). A returned business result
still needs reply encoding/whole write on its original client connection.

Source review and later static compilation are not
runtime recovery or mixed-node interoperability acceptance.

## Native IPC providers

`native::NativeProvider` adds the standard NAMECACHE, REVOCATION and DHT
clients. It requires a auxiliary `Provider` for DNS, system resolution and
symbolic service mappings. This constructor has no fallback implementation for
those capabilities. Their concrete auxiliary composition and standard SERVICE entry are supplied
explicitly. Real network acceptance and further recorded capabilities remain
separate from source construction.

NAMECACHE uses one multiplexed native client and bounded per-operation mailboxes,
with genuine opaque operation/RID/epoch mapping. Each encrypted response is moved
from the client without a second ciphertext copy, then the existing GNS
resolver authenticates/decrypts it for its authoritative zone and label. Only the
CACHE response supplies a status. Partial cancellation drains the original
suffix under the client's existing fixed retirement bound. Full-write loss is
Unknown, never a replay instruction. Shared source loss keeps its owned
cause, while each affected operation supplies its own local terminal result.

REVOCATION follows the existing one-request-per-MQ native API because its wire
response has no request ID. Only a query word 0/1 yields revoked/valid;
unknown words fail. Original MQ close, exposure and transient connection failures
remain separate from the raw service response.

DHT uses one native client with original `GetId`/epoch mappings, one
bounded candidate mailbox per live query and receive backpressure while a
candidate is held. It requests official GNS_NAMERECORD block type 11,
DEMULTIPLEX_EVERYWHERE and replication 10 with an empty extended query, as in
pinned v0.29.1 `gnunet-service-gns_resolver.c` (`DHT_GNS_REPLICATION_LEVEL` and
`GNUNET_DHT_get_start`). This client observation grants no block authentication. Bad candidates remain the pure resolver's decision. The original GET is reused
by the client's safe read reconnect, with its original whole-query bounds.

GET cleanup waits for whole STOP writing, removal before issue, or actual
old-MQ retirement. A stuck STOP is fenced by the same original native hard and a
native sleep even when canonical time fails. Retiring that old MQ lets the
same client safely restore only other still-live readonly intents. A canceled
GET is not reconstructed. The administrative whole-provider close is retained
as physical metadata rather than emitted as a fictitious backend failure.

Shared clients are lazy until an operation exists. Query caps and request-body
caps are separate. The mailbox tables reserve only their configured operation
rows; ciphertext candidates allocate their bounded size. There is no
unbounded diagnostic log or per-query copy of all shared source errors. Each
native constructor/submission is guarded against the original hard. Shared
client polls also use the earliest still-relevant original hard, with expired
operations canceled/retired individually before the next shared IO poll.

The DHT native adapter receives only a minimal observation-deadline seam: after
its canonical clock work it rechecks the same optional wait deadline before
starting the next native step. That observation is still not GET completion.

## Ordinary auxiliary dependencies

`auxiliary::Auxiliary` composes DNS-only recursive operations, actual
shared Resolver forward subscriptions, and an explicit prepared files registry. It is the concrete auxiliary argument for `native::NativeProvider`. It creates no
second Resolver broker, runtime, thread or hidden background service. The standard
GNS SERVICE listener/foreground composes this provider through the same original
Manager, clock and Resolver.

System redirection uses the original foreground `Context::ip_get`/`Query` and
actual `Delivery` callbacks. Only `Completion::End` returns a complete record set;
partial lists, source loss, timeout and malformed replies remain failures. The
address API supplies no DNS TTL, so its explicit configured data lifetime is a
policy value. Actual addresses keep `Origin::System`. Clock-free cancellation
revokes only the original subscription's receipt; its report explicitly leaves
any shared wire/tombstone/partial IO with the same foreground Driver. The service
must actually disconnect that Driver before reporting whole-service closure.

The registry combines bounded `/etc/protocols` and `/etc/services` files (or
explicit caller-supplied bytes) with the official GNS-specific GANA assignments. File entries take precedence, followed by GANA and then numeric service ports. The pinned official resolver first calls libc `getprotobyname` and
`getservbyname`, then uses the same GANA/numeric fallback order. This Rust files
profile does not consult independently configured NSS backends for those two
lookups; that boundary does not imply missing lookups of unrelated OS databases. The pure `gnunet_gns::assigned` table contains all
currently published GNS protocol/service assignments, with ASCII-insensitive
names. It does not duplicate the IANA or system NSS databases. A complete GANA
match remains usable if files preparation failed; other requests retain that
original preparation error. Genuine unknown names remain `None` for literal
SBOX handling. Preparation reads are synchronous and may block. Their byte and
row bounds are checked before any live service resource needs this table.

Ordinary DNS keeps numeric bootstrap servers explicit and never sends a DNS name
back into GNS. The original selected GNS2DNS namespace is preserved as the pure
`Dns` effect's `authority`, before unresolved labels are prepended. It binds
referral/bailiwick scope without guessing from the full question. DNS replies are
matched to the source, original wire ID/opcode and complete IN question,
using DNS ASCII case-insensitive name comparison. A TC prefix triggers TCP without
requiring its intentionally truncated RR body to parse. UDP and TCP share the
same already-fixed exchange and whole-query boundaries. TCP prefixes/bodies retain
partial byte counts; expiry never becomes a successful empty answer.

Referrals, glue and recursive nameserver address resolution use only DNS. CNAME
chains already present in a complete answer can produce their target RRset
without an unnecessary second lookup; alias expiration bounds the result. Names,
record counts, DNS bytes, rejected packets, depth and total exchanges are bounded. The receive buffer needs its configured datagram cap to distinguish truncation;
parser records use header counts, and decompression storage grows only as
needed up to its declared cap. DNS TXT character strings are decoded into the
canonical GNS plain octets, preserving empty strings and embedded NUL bytes.

recoverable DNS errors retain one owned original cause and an omitted
count, while the last terminal cause is returned separately. Native socket byte
counts and callback/operation closure are independent of DNSSEC authentication. `failed_counted` and `NativeFailure::spent` charge already performed recursive work
even when a DNS/TCP attempt fails; fallback cannot silently recover that original
query budget. This does not add tickets, wire fields or retry deadlines.

Security-required GNS2DNS remains an explicit capability boundary. A real
`Secure` provider can be installed with the same clock and original owned request,
authority/security records and bounds. No fake validator is provided. Without one,
nonempty authenticated security records fail as `SecurityUnavailable` before native
DNS work instead of silently trusting AD or downgrading the request. The standard
SERVICE installs `with_dnssec`, which verifies the supplied DS anchor through the
DNSKEY and RRSIG chain, including bounded authenticated denial proofs. Supported
algorithms and resource profiles remain explicit; current mixed-node acceptance
and complete DNSSEC coverage are still outstanding. The pinned C's rejection of
all co-located GNS2DNS security records is recorded as a source difference, not
copied as a claim about the standard's full behavior.

Standalone DNS QTYPE=RRSIG remains explicitly `Unsupported` in this
required-security interface. [RFC 4035 section 2.2](https://www.rfc-editor.org/rfc/rfc4035.html#section-2.2)
excludes RRSIG records from RRset signing;
[RFC 8482 section 7](https://www.rfc-editor.org/rfc/rfc8482.html#section-7)
leaves standalone RRSIG-query handling unspecified. This is a deliberate query
policy, distinct from verifying the signatures accompanying ordinary requested
RRsets. An isolated signature response is never presented as an authenticated
RRset, and this policy does not block those accompanying signatures. No later
work-in-progress draft is treated as an established standard.

The candidate
author ran no compiler, query, parser/model/test, cryptography, key generation,
resolver, socket, storage or worker. Central static checks remain separate from
runtime restart/recovery and mixed-node acceptance.

## Official IPC frontend and SERVICE owner

`server::Server` retains canonical type500/501 client framing around the
same Manager. Each original peer and call has an opaque local identity separate
from WireId. It preserves partial output prefixes, immutable suffixes,
bounded frame credits and original input/request/native bounds. A query result
is taken only after its original native task retired; a queued result is distinct
from whole local write. Bad input/client loss cancels only that peer's
original calls. Soft stop gates new input and finishes previously admitted
results, while Immediate physically retires peers and drives native cleanup.

`native::diagnostics` consumes owned causes/reports into static diagnostics. It
erases only borrowed token authority into diagnostic serials; no static token,
completion or cancellation authority is reconstructed. Whole service completion
still requires the frontend's local Stopped plus separate original shared
Resolver Driver retirement in `gnunet-service-gns`.

The standard SERVICE app supplies prebind/USERNAME/Unix access ordering, daemon
ChildReady after local preparation and stdout flush, the single process
SharedClock/broker, bounded source recovery, dependency construction,
selected Reporter and unconditional original-owner cleanup. It consumes the
separately implemented validating DNS factory rather than a placeholder security
success. Source construction/static checks do not constitute runtime acceptance.

`Manager::new_with_refresh` adds an independent near-expiry cache refresh owner. It never retains or completes an old caller QueryId/EffectId. A single optional
pure hint feeds a preallocated table (default8, configurable through64), deduped
by original query key including active retirement. Its native hard is fixed in
the native-only guard before the next canonical sample; one new default30-second bound
covers the original DHT GET, retirement and at most one NAMECACHE
update. Canonical expiry is anchored at the authenticated cache receipt that
created the hint; delayed consumption cannot obtain a fresh complete budget. Existing Provider Remote/CachePut effects reuse the same clients,
clock and Resolver. A dropped wait, reconnect or phase transition never renews
that budget. Only the old GET's Close::Closed permits cache admission.

A candidate must be correctly bound, signed, decrypted, fully record-framed and
strictly later than the original authenticated expiration. Candidate work is
finite, and aggregate retained candidate Vec capacity defaults to512KiB; each
job owns one bounded label, plus the sole pure hint. Shared native request/frame
limits remain separate. A selected candidate's authenticated expiration is
rechecked before cache admission without repeating signature verification. The
manager returns background Started/Selected/Stored/late/retirement/error
observations independently of caller results. Status1 is a local cache fact,
not a remote publication or replication proof. Exposed cache mutations retain
the native provider's uncertainty and are never replayed.

Zero refresh jobs disables pure hint allocation. Current LocalOnly/LocalMaster
policy still governs each authority; `[namecache] DISABLE=YES` disables
cache use and refresh in normal SERVICE configuration. Background resource or
source failure cannot turn an authenticated foreground answer into failure. Shutdown closes original refresh operations and shared providers; quiescence
includes active/retiring refresh owners. The native foreground keeps one
optional-refresh error plus an explicit omitted count, and separate protocol/
status/expiry observations, rather than an unbounded error list or a fatal
caller-query result.

`Server::enable_interception(source, configuration, interceptor::Limits)` attaches
an explicitly configured DNS PRE_RESOLUTION source before ordinary clients. It
uses the exact same clock Arc and Manager, with a separately branded DNS callback
domain retained by the original Server instance. No self-RPC, extra resolver,
listener or task is created. Parsed questions select an explicit typed zTLD or
administrator suffix mapping. Ordinary non-GNS/malformed/other-profile requests
are forwarded on the original callback; malformed selected mappings are refused.

Interception rows retain callback tokens, fixed Bounds, same-Manager query IDs
and pending output until whole-write/source retirement and original query
cleanup. Lost DNS epochs cancel their original GNS work; reconnect restores only
the subscription and never old callbacks or responses. The fair Server turn and
native-first guards poll the same source. Soft stop drains its original decisions
before closing the shared provider. Immediate escalation preserves a queued
original loss observation instead of replacing it with an empty later close. Packet preparation reuses bounded shared DNS/IDNA codecs and GNS outcomes;
local queue admission/full-write facts are not remote DNS delivery or DNSSEC
verification. The bridge and packet/privileged profiles remain unexecuted pending
runtime authorization; source composition is not an interoperability receipt.
