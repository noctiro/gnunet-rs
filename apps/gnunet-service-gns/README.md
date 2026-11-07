# GNS SERVICE

`gnunet-service-gns -c configuration` is the ordinary GNS500/501 IPC service,
using standard SERVICE `-c/-d/-h/-L/-l/-v` preparation and the selected Logger. The original activation listeners and parent-control FD are adopted once. TCP/adopt preparation precedes configured `USERNAME`; Unix creation/access
follows the identity change. `[gns] UNIX_MATCH_UID` defaults NO and
`UNIX_MATCH_GID` defaults YES, matching the public service template. Explicit
shared service policy is preserved; normal shutdown defaults Immediate.

READY means local listeners, Server and dependency factories exist and stdout
was flushed before the original ChildReady. The service keeps one process SharedClock and
one Resolver broker/Driver. NAMECACHE and DHT share bounded multi-operation
clients; REVOCATION keeps its genuine one-request native MQ. Individual source
or query failures leave unrelated queries live. Exposed NAMECACHE writes are
not replayed on recovery. Retained DHT read intents keep their original GetId,
source generation and deadline.

The installed DNS factory uses the actual `with_dnssec` validator. Its complete
chain/denial implementation is integrated independently; an unsupported
security record or algorithm is an explicit failure, never a fabricated secure
answer. Ordinary DNS and nameserver discovery stay on the DNS path, with the
same exchange bounds through UDP/TCP, referral and alias processing. System
address queries use the same process broker; their default 60-second record
lifetime is explicit Rust policy because that broker returns no DNS TTL.

The default symbolic service/protocol provider reads bounded `/etc/protocols`
and `/etc/services`; this is the files profile, not all NSS or GANA registries. Numeric DNS bootstrap endpoints come from bounded `/etc/resolv.conf`. These
synchronous configuration reads happen before live dependency effects and may
block in the OS; no forced cancellation of a blocking read is claimed. `INTERCEPT_DNS=YES` attaches the configured ordinary `[dns]` CLIENT with the
standard PRE_RESOLUTION subscription. Its original callbacks select typed zTLDs
or configured `[gns] .suffix` public zones and use the same retained GNS Manager;
non-GNS, malformed and other-profile questions are forwarded unchanged by their
original callbacks. No self-RPC, extra UDP listener, Manager, Resolver or worker
is created. A malformed selected namespace is an error, not DNS fallback.

Interception resource controls in `[gns-rust]` are MAX_INTERCEPT_REQUESTS(default
MAX_QUERIES,max4096), INTERCEPT_PACKET_BYTES(default65507,max65519 IPC payload),
INTERCEPT_SOURCE_BYTES(default4MiB,max64MiB), INTERCEPT_ARENA_BYTES(default2MiB,
max16MiB), and INTERCEPT_WORK(default8MiB,max64MiB). Records/bytes and original
callback lifetime reuse MAX_RECORDS/MAX_RECORD_BYTES and QUERY_TIMEOUT. Packet
workspace follows input/results up to its cap. Actual privileged DNS
service/helper deployment remains a separate platform dependency; READY reports
configured owners and does not assert packet interception or IP delivery.

Each DNS callback retains its physical token/epoch and original logical/native
targets across Manager backpressure. Only a GNS result is projected into a
reply; local decision admission and whole IPC write are distinct observations. Source loss cancels original lookups and never replays old callbacks or bytes on
a new epoch. Soft shutdown drains its original decisions/query retirement on the
same Manager/clock before closing the provider. Immediate shutdown physically
closes the original source while retaining any earlier loss observation.

`[gns-rust]` controls explicit resource policy: MAX_QUERIES (default32, max64),
MAX_CLIENTS (32), MAX_CLIENT_CALLS (2*MAX_QUERIES), MAX_CALLS_PER_CLIENT (8),
MAX_CLIENT_OUTPUT_FRAMES (8), MAX_CLIENT_OUTPUT_BYTES (8*65535), IO_SLICE_BYTES,
MAX_STEPS, MAX_RECORDS, MAX_RECORD_BYTES, MAX_RECURSION_FRAMES and MAX_SERVERS. QUERY_TIMEOUT defaults180s for the complete original call, INPUT_TIMEOUT15s
from the first input byte, DNS_EXCHANGE_TIMEOUT2s, and SHUTDOWN_GRACE10s for an
explicit Soft stop. These are Rust bounds, not copied C queue/timer internals. A second stop or the first Soft grace expiry escalates to Immediate without
renewal. RESOLV_CONF, RESOLV_CONF_BYTES, PROTOCOLS_FILE, SERVICES_FILE,
DNS_EXCHANGES, SYSTEM_ADDRESS_LIFETIME and RESOLVER_* bounds are also explicit.

Every post-Server exit enters old-owner cleanup: peer FDs close, only
their original queries cancel, original operations retire under their existing
native bounds, then the original shared Resolver Driver disconnects and drops. Subscription revocation is not described as shared wire retirement. Queued
responses are not called Written; positive write prefixes and discarded suffix
bytes remain diagnostic facts. No timeout or Drop is renamed an operation END. One fixed slot per native error/report category plus explicit total counts
bounds process diagnostics; later causes are omitted as recorded counts, not
silently accumulated forever. Selected Logger, original body, IPC, cancellation,
Resolver, output and close failures remain independent typed causes.

Normal cache hits with less than five minutes left can start an independent
bounded refresh while returning the original authenticated answer promptly. `[gns-rust] MAX_REFRESHES` defaults8 (0 disables, max64), `REFRESH_BYTES` defaults
512KiB (aggregate selected-candidate capacity), and `REFRESH_TIMEOUT` defaults30s
for the entire new original GET-through-cache operation. Disabled refresh skips
unused refresh budget/timeout preparation. `[namecache] DISABLE=YES` disables both
ordinary cache use and refresh. Native NAMECACHE/DHT row capacities include the
foreground-plus-refresh total through checked addition. Local-only lookup policy
still prevents remote refresh at that authority.

The same existing DHT/NAMECACHE clients, shared clock and broker drive actual
background work; there is no detached task or extra Resolver. Original GET
retirement precedes at most one fresher validated cache insertion. Caller query
identity, deadlines and answers remain independent. Optional-refresh failures
have bounded nonfatal diagnostics; late cache statuses and original
retirement reports remain observations. STOPPED includes bounded refresh
counts, without claiming remote publication, durability or measured performance.
