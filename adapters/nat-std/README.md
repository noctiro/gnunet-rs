# GNUnet NAT native host and services

The service path combines pure NAT protocols/state with native network ports.

## Features

The explicit `providers` feature includes the complete service, interface discovery,
IGD HTTP/HTTPS, SOAP/XML and raw-helper supervision. `program` adds the normal
PROGRAM entries and always enables these providers. The SDK's `official-nat`
feature also selects the full provider composition.

`service` enables the caller-driven foreground and shared Resolver broker.

Default features are empty. `deadline`, `interfaces`, `resolve` and `stun`
are available to client/test adapters. This primitive profile avoids coupling
NAT clients to an HTTP/TLS provider and does not supply a reduced service backend.

## Service and provider interfaces

`server::Server` accepts shared SERVICE streams, checks Unix/TCP ACLs, decodes the exact explicit host ABI, registers original `state::Source`, and dispatches REGISTER/STUN/ADD_GLOBAL/REVERSAL. It queues only official address/reversal notifications. Each immutable TX tag stays on its original MQ, with retained partial cursors, FIFO, original per-frame output bound, first-byte input bound and finite transient sessions. Unknown malformed sources close only that physical MQ. No RID, general ACK, wire CANCEL/UNREGISTER or fabricated operation completion exists. Local whole writes are reported distinctly from provider/remote observations.

[`helpers::Supervisor`](../nat-helper-std/README.md#caller-driven-supervision) owns native child launch, framing and original wait/retirement without an HTTP dependency. Its shared Bounds keep process-clock and native targets unchanged.

`manager::Manager` owns source configuration, original provider/job generations, complete interface snapshots, shared-Resolver DNS, explicit HOLE_EXTERNAL literal/DNS/AUTO behavior, bound-UDP STUN observations, IGD discovery/Add/Query/Delete/ExternalIP, mapping leases and original child helpers. New periodic work/retry creates a fresh local job/provider generation; an old result is never reattached. Every request has original absolute and native bounds, and cleanup gets its own explicitly new finite deadline once, including queue residence. Logical clock rollback never refreshes a native hard target. Provider expiry/invalidation precedes native address writes; obsolete zero-written adds are discarded, while a partial obsolete original closes its MQ. Shared metadata exhaustion during critical freshness maintenance fails closed instead of emitting a known-expired address.

IGD selection preserves supported WANIP/WANPPP services from multiple descriptors, instead of statically keeping a highest-ranked service or the first SSDP device. Before any Add, bounded `GetStatusInfo`/`GetExternalIPAddress` reads prefer the first connected service with a nonreserved IPv4 claim; otherwise the first connected service remains the fallback, including a locally rejected external-address read. `Connected` is the standard state and `Up` is the miniupnpc compatibility alias. This permits private/CGNAT gateways without claiming public reachability. A disconnected service or a rejected status read never authorizes Add. Once a candidate is selected, Add failure/exposure/uncertainty never triggers another candidate or mutation replay.

Selection uses the same original Gate, Source, Resolver and both expiry targets throughout. Only explicit endpoint OS refusal/disconnection or local HTTP/SOAP/XML rejection permits another read-only candidate. Clock, original deadline, cancellation, resource and opaque IO refusals stop the scope. Every candidate read error retains its stage, original bounded target and typed cause. One shared `ReadObservations` allocation survives a pending future's cancellation; terminal success, failure, source retirement and abort first drop original IO and then move its observations once. A failed read remains separate from eventual selection or mutation. Mapping announcements preserve GNUnet IPv4 scope: private/CGNAT is LAN and other externally learned addresses are EXTERN. The miniupnpc reserved-address preference and the GNUnet announcement class are separate policies.

Jobs retain native futures and completed outcomes across dropped caller drive futures and output backpressure. Mapping mutation `Written` retains the original generic HTTP Job and reports owner queueing, dispatch invocation, stream-write attempts, TLS/plaintext acceptance, native socket bytes and complete response separately. Queueing/TLS acceptance/native writes are never whole-request ACKs. `AddAttempt` distinguishes unexposed, SOAP rejection, SOAP success and exposed unknown outcomes. A SOAP718 rejection never authorizes deletion. Cancellation/loss after possible exposure permits only separately bounded recovery, preserving the original cause and independent cleanup facts.

Each Add uses fresh operating-system entropy for a 128-bit identity in the standard `NewPortMappingDescription` field. Cleanup first uses `GetSpecificPortMappingEntry` to check the original internal address/port, enabled state and exact attempt marker; the same tuple alone grants no deletion authority. Foreign, missing-description and otherwise unproven entries are not deleted. The original known mapping receipt or uncertain attempt retains its marker without inventing a GNUnet wire field. The standard IGD query and delete are not atomic, so this check does not eliminate router-side replacement races.

Pure bounded SOAP classification occurs once at the shared HTTP framing boundary, before a post-response clock/expiry wait or failure. Actual Add success/rejection and Delete success/absence remain facts when that independent guard fails; the original guard cause still fails the job. Queued cleanup never refreshes its original deadline. Query SOAP714 is only an absence snapshot: it settles a previously confirmed mapping, but cannot exclude an earlier exposed unknown Add applying later. That case reports absence and unresolved uncertainty independently. Observing the original marker proves that original Add has applied; subsequent DELETE success or its SOAP714 absence can settle that cleanup. `OwnedThenAbsent` keeps the latter fact distinct from absence before ownership was established. TLS-buffered plaintext cannot be treated as known-unsent, and timeout/error/capacity/clock refusal cannot become a removal receipt.

The standalone service selects installed helpers through `SUID_BINARY_PATH`
and `libexec`. An embedded service receives the installed pair from its host.
The supervisor launches each executable directly and owns its generation,
stdout framing, source or interface lifetime, deadline and retirement. A
successful sender exit records two complete local raw datagram sends. A
server line carries an unauthenticated ICMP observation. Port zero is
diagnostic. Native child retirement continues while the canonical clock
stabilizes. Source reappearance creates a fresh helper generation.
[Executable interfaces](../nat-helper-std/README.md#executable-interfaces)

`auto::propose` parses the serialized configuration and returns its serialized diff. The active pinned C NAT-auto daemon only probes whether external upnpc exists; this implementation has a built-in Rust IGD backend and proposes ENABLE_UPNP=YES. It returns UNKNOWN classification, never a fictitious connectivity test. It does not apply/write configuration. The original codec retains raw0/unknown status/type values from official peers.

The public `gnunet-nat-server` listener decodes the16-byte official NAT_TEST. It writes the two exact opaque challenge bytes over TCP/UDP, or launches the two-packet raw reversal sender. As in the official production handler, the test request MQ can close immediately after admission while that original finite action finishes; its original Source tag/targets are retained and no output moves to another source. Ordinary NAT registration reversal work remains canceled with its source. There is no test-server ACK.

Three foreground apps are included: gnunet-service-nat, gnunet-service-nat-auto and gnunet-nat-server. They perform once-only inherited-descriptor capture, shared PROGRAM preparation/clock, official service-user privilege policy, one shared Resolver broker, SERVICE bind/credentials/activation, signal/parent stop, finite source drain, child/router cleanup and independent final error reporting. PROGRAM's GNUNET_OK=1 is distinguished from process exit0. READY means local listener/owner setup, never NAT connectivity. STOPPED includes pending/unresolved cleanup; unresolved ownership does not become a clean shutdown.

## STUN configuration

Periodic outward probes require both `[nat] USE_STUN = YES` and a nonempty
`STUN_SERVERS` list. Each entry is a host or host:port; the default port is
3478. Set `STUN_FREQUENCY` to change the five-minute interval. Passive NAT
client STUN messages still use the official wire format and `STUN_STALE` policy.

## Embedded service

`startup::serve_embedded` binds ordinary NAT IPC and runs the same server and
Resolver driver as the standalone service. `startup::EmbeddedSettings` supplies
the configuration, clock, network hints and socket policy. The caller drives
the service under its current identity and keeps the configured listener namespace
stable. Interface scans, STUN and UPnP use the configured policy.

A deployment can supply `startup::HelperPrograms` with separate trusted
absolute paths for the installed NAT observer and sender. The deployment owns
the paths and native permissions for the service lifetime. A protected socket
policy rejects this process-helper profile before listener binding. The
existing NAT supervisor owns each helper through bounded retirement. Stop
reports provider and listener cleanup failures.

## Native process composition

`startup::EmbeddedSettings` takes a host-owned `NetworkChanges` consumer. Notifications
coalesce into the existing bounded interface scan and honor `ENABLE_IPSCAN`.
Native deadlines and provider work keep their turns during repeated notifications.
Stopping disables notification-driven scans. A default consumer uses the periodic
scan schedule.

With feature `program`, `foreground::main(Mode)` is the unsafe fresh-executable
entry shared by NAT, NAT-AUTO and the NAT test server. It captures original
activation and parent control before other native owners. Unix applies the
configured process identity; Windows verifies its token and imports activation.
Settings, selected Reporter, one clock and one caller-driven Resolver remain
shared with the original business loop. This PROGRAM entry has no SERVICE
fork/detach option.

Readiness proves local listener and owner construction. Parent notification has
a fixed native deadline and observes the same stop source and logging failure
latch. Cancellation keeps an admitted status; it never creates a replacement
READY. Foreground diagnostics use the selected Logger. PROGRAM cancellation retains actual
Resolver disconnect errors and pending cleanup reports independently of its
scheduler/task error.

All explicit exits abort original sources before final reporting.
`Server::poll_retirement` then polls original child waits without a canonical
clock, new network operation or renewed deadline. A helper's unknown retirement
increments unresolved cleanup even after its bounded slot is released. Neither
an empty helper table nor a requested kill proves successful reaping.

## Ports and bounds

Discovery uses bounded native interface snapshots on Unix and Windows, original Gate, shared Resolver, application-bound UDP STUN sender (application retains RX ownership), dedicated monitor socket, bounded SSDP and shared mature HTTP/HTTPS1 (length/chunked/EOF) transport, mature quick-xml exact0.42 borrowed UTF8 NsReader with namespace/depth/event/attribute/body limits, no DTD/custom entities/external entities, end-name checks. IGD WANIPConnection/WANPPPConnection1/2 support includes external-IP/add/delete/query; HTTP and HTTPS IGD descriptor/URLBase/control targets use the independent gnunet-http-host owner with verified TLS, shared Resolver and unchanged original logical/native Bounds. SOAP POST does not follow redirects or automatically replay after any exposure; genuine HTTP500 bodies still enter the bounded SOAP fault parser. Default public roots verify hostname/SystemTime validity; callers can supply explicit trust roots through http::exchange_with_tls without disabling checks. No miniupnpc/upnpc/external-ip C utility is called. Native helpers remain platform capability gates, not implicit permission/route/system changes.

The default original selection admits at most eight descriptor locations and 32 supported service entries per description/32 distinct canonical service-control pairs in total. Description and SOAP bodies remain individually capped at 65536 bytes, URLs at 2048 bytes and service URNs at 256 bytes, with the existing XML event/depth/attribute/namespace limits. There are at most eight description reads, 32 status reads and 32 external-address reads. The error allocation is reserved before IO for at most devices+services entries: each description fails at most once, and a service can fail status or, only after successful status, external-address reading once. Invalid control URLs reject the whole description; malformed service entries are not silently repaired. Explicit-location selection is available without SSDP and still uses the same HTTP/SOAP and original bounds.

Official NAT keys control IP scan, UPNP, local/v6 filtering, STUN servers/freshness/refresh, DYNDNS and HOLE_EXTERNAL. IFC_SCAN_FREQUENCY is honored instead of the C internal hardcoded15-second scan that ignores its conf entry. Periodic mapping checks use the active C5-minute interval. Rust-only nat-rust keys bound sources/frames/queues/providers/events/jobs/mappings/interfaces/helpers/timeouts/shutdown; they are resource budgets, not an alternative protocol or address policy.

## Limitations

The native Registration/AutoQuery client is supplied by gnunet-nat-client-host
and the optional `clients::nat` SDK edge. The gnunet-nat and gnunet-nat-auto
commands use gnunet-nat-test-host for challenge listening, registration and
test-server calls. The util NAT burst/socket API is supplied by
gnunet-nat-burst-host.

The cleanup queue is fallibly reserved at Manager construction. Original source
retirement revokes core authority first and queues cleanup without a temporary
collection; shutdown likewise needs no source-list allocation. Original query
futures retain their own Mapping rather than duplicating it in job tags. Dedicated STUN probes use one fallible65536-byte UDP buffer, outside the future's
inline storage, and configurable nat-rust MAX_STUN_DATAGRAMS (default1024). Capacity exhaustion is an explicit local error and never a NAT classification. Clock failure while retiring a failed provider aborts the original owner and
preserves the original job error separately. Unknown mapping deletion remains
unknown, including after expiry or failed cleanup admission.
