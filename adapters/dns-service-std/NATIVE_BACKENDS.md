# Native DNS backends

The shared DNS host implements raw helper/TUN sources, Windows WinDivert capture
and Apple DNS proxy providers using original application flows.
Native receiving-path qualification remains separate from implemented SDK
ownership and service orchestration. Open implementation work belongs in
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Shared engine and reply authority

The official DNS service sends DNS bytes and opaque request IDs to monitors and
PRE/POST providers. Its [client messages](../../crates/gnunet-wire/src/official/dns.rs)
carry no IP header, interface index or native flow handle. All sources use one
[payload engine](../../crates/gnunet-dns-interception/src/engine.rs), with the same
phase ordering, subscriber snapshots, rewrite/drop rules, resolver correlation
and output effects. PRE answers still enter POST processing.

Each source supplies a DNS view and its private reply owner together. Raw
adapters validate IP/UDP once, retain the original storage and reply tuple, and
encode their own reply framing. The Apple adapter retains its SDK endpoint
beside exact DNS bytes and writes DNS bytes directly. Gateway admission binds
that owner to the original core request and source; it does not select packet
framing. Native metadata cannot manufacture a reply permit.

| Owner | Retained state |
| --- | --- |
| Source | Original process, device, capture session or bounded flow table. |
| Native flow | Original SDK object, non-reused identity and original endpoints. |
| Request | Core request/source identity, noncloneable reply permit and fixed deadline. |
| Output | Original effect, immutable bytes, native submission and callback loans. |

Preparation performs fallible host frame allocation and encoding before
reserving an effect. Queue rejection returns the original bytes and permit.
Successful native submission consumes its endpoint; a completion cannot recreate
that authority. Source shutdown closes admission before requesting native close,
then preserves pending callback loans through retirement. Failure of one
application flow aborts only its requests. Address tuples, PIDs and interface
indices cannot replace these owners.

Resource contracts and APIs are documented in the [DNS host](README.md) and
[native flow boundary](../native-std/DNS_PROXY.md). Callback publication uses
reserved one-shot slots and remains independent of read capacity. Native
operation completion, callback disposal and application consumption remain
separate observations.

Native packet and flow outputs record whether the owner requested cancellation
or the local send deadline expired. A late native completion still reports its
actual acceptance or failure against the original operation.

## Apple provider path

The `dns-proxy` native feature supplies the bounded controller, UDP/TCP flow
owners and Network.framework connections. The
[macOS executable](../../apps/gnunet-service-dns/macos/README.md) enters
system-extension mode. The [iOS SDK](../../platform/ios/README.md) attaches to a
containing application's DNS proxy extension. Both drive the Rust foreground on
one worker thread. Stop closes admission and waits for resource leases held by
native owners and their callback contexts.

UDP flows enter the existing gateway and GNUnet monitor/PRE/POST pipeline.
TCP flows enter a bounded byte relay preserving order and half-close. A submitted
receive or FIN waits for its original callback across connection readiness
changes. The active relay delivers a receive's final data prefix before its
accompanying error. Both paths use the same service's configuration,
diagnostics and shutdown orchestration.
[DNS proxy flow contract](https://developer.apple.com/documentation/networkextension/nednsproxyprovider),
[TCP flow API](https://developer.apple.com/documentation/networkextension/neappproxytcpflow)

Modern flow selectors retain original `nw_endpoint_t` objects, including opaque
hostname, Bonjour and URL endpoints. No address lookup or numeric conversion is
needed to return an original UDP endpoint or create its TCP upstream. Opening
supplies the provided local endpoint, and an application-bound endpoint takes
precedence under the SDK contract. After opening, UDP also observes the
original socket's local endpoint for scoped datagram admission.
Numeric link-local and legacy site-local
IPv6 require an explicit original zone and local endpoint. Numeric endpoints
with the same scoped address class must agree on the zone. Link-local and site
zones retain their distinct meanings. TCP multicast peers and UDP multicast
reply sources are refused by their respective role checks. Interface and
socket-replacement behavior require native qualification.
[Flow opening](https://developer.apple.com/documentation/networkextension/neappproxyflow/open%28withlocalflowendpoint%3Acompletionhandler%3A%29)

The configured GNUnet DNS resolver and PRE replies supply DNS bytes. Its
ordinary gateway completes one answer per request. The separate
[native multicast exchange](../native-std/DNS_PROXY.md#native-multicast-exchange)
keeps the original group and bound interface and observes each unicast sender
from its message. The provider's explicit port 53 relay checks the original
DNS ID, opcode and questions and checks section framing. It cancels the group
after the first valid match and retains that sender through the original flow
write. Its fixed deadline starts at the native read. Ordinary unicast work
in the same batch stays eligible while group operations wait for callbacks.
This relay is disabled by default. iOS deployments enabling it require Apple's
[multicast entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.multicast).

Apple's DNS proxy delivers application flows for UDP and TCP port 53. Full mDNS
uses port 5353, interface-specific memberships and asynchronous responses.
The proxy exposes neither those flows nor the application's membership state.
Full interception also needs delivery to the original socket according to its
memberships. The packet filter API can pass, drop or delay the original packet.
Apple lists the legacy socket-filter registration and injection interfaces as
unsupported since macOS 11.
[Apple DNS proxy](https://developer.apple.com/documentation/networkextension/nednsproxyprovider?language=objc)
[Apple packet filter](https://developer.apple.com/documentation/networkextension/nefilterpacketprovider)
[Apple kernel extension policy](https://developer.apple.com/support/kernel-extensions/)
[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)

Provider upstreams use Network.framework. TCP binds the connection to the exact
original flow and retains its remote endpoint. macOS copies the flow's native
metadata to the connection parameters. An application interface binding requires the
original native interface object; an unbound flow is not frozen to a sampled
interface. UDP retains explicit configured resolver peers and the shared pure
DNSSTUB scheduler. A failed peer or flow does not replace another owner. The BSD
socket variant requires a matching numeric endpoint and zone. Real-provider
recursion behavior remains part of acceptance.

Provider UDP readiness and submitted sends have fixed monotonic bounds, including
while canonical time is unavailable. Expiry stops only the original peer; native
callback loans remain retained until disposal. The pre-canonical guard neither
starts new I/O nor consumes a live receive result. A pending original native send
cannot retain a later DNSSTUB attempt indefinitely: that new attempt receives a
local refusal so the unchanged retry order can advance.
Failed cache generations retain their loans in a bounded retirement arena while
new generations can open. If that arena is full, the original endpoint and
opening token remain queued until capacity returns; native readiness timing
starts when the connection is actually created.

The [bundle helper](../../apps/gnunet-service-dns/macos/README.md#assemble-the-bundle)
produces unsigned system-extension files and signing entitlements. A containing
application source supplies the AppKit lifecycle, explicit activation and
serialized `NEDNSProxyManager` operations. The application bundle helper embeds
the exact provider and emits separate signing inputs. Node staging checks and
preserves the signed containing app for deployment to `/Applications`.
Provider activation, official IPC readiness and original-zone delivery are
distinct observations.
[Signed application staging](../../apps/gnunet-service-dns/macos/README.md#stage-and-activate-a-signed-application),
[Deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
[provider entry](https://developer.apple.com/documentation/networkextension/neprovider/startsystemextensionmode%28%29),
[manager configuration](https://developer.apple.com/documentation/networkextension/nednsproxymanager)

## FreeBSD receiving path

PF startup state retirement holds one original `/dev/pf` descriptor. It sends
one `DIOCKILLSTATESNV` operation per selected nonzero state and creator ID, then
reads back those IDs under the original sweep deadline. FreeBSD selects the
VNET from the calling thread, so this operation runs in the helper's existing
jail context. UDP delivery authority comes from the original receiving path.
[FreeBSD 14.5 PF ioctl](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/netpfil/pf/pf_ioctl.c),
[FreeBSD 15.0 PF ioctl](https://github.com/freebsd/freebsd-src/blob/releng/15.0/sys/netpfil/pf/pf_ioctl.c)

The [PF fallback](PF.md#runtime-policy-observation) retires the capture when
its original route socket reports a receive-queue overrun. FreeBSD reports
this through `SO_RERROR`.
[FreeBSD routing socket delivery](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/net/rtsock.c#L316)

PF diversion is a capture candidate. FreeBSD 14.5 `PF_DIVERT` supports IPv4/IPv6,
but its outgoing metadata uses INADDR_ANY, its incoming interface-name slot is
eight bytes including the terminator, and its source notes an IPv6 reinjection
defect. Copying this sockaddr does not establish original-zone delivery for all
interfaces.
[Native implementation](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/netinet/ip_divert.c)

Per-interface diversion ports distinguish configured capture bindings without
pinning the packet's original interface or receiving UDP socket. Name/index
checks before injection leave a replacement interval. A complete receiving path
needs a kernel operation/context that validates the original flow and zone at
delivery, or a separately deployed capability supplying that contract.

Raw `sendmsg` with IPV6_PKTINFO selects an output interface. BPF feedback performs
interface output before local input and can emit an extra network frame. Socket
redirection and NAT lookup require proof of original-zone recovery, local OUTPUT
coverage and reverse delivery. None is a complete TUN replacement based only on
copied address fields.
[BPF feedback](https://github.com/freebsd/freebsd-src/blob/releng/14.5/share/man/man4/bpf.4),
[diversion contract](https://github.com/freebsd/freebsd-src/blob/releng/14.5/share/man/man4/divert.4)

A kernel backend can capture the original `inpcb` and `ifnet` at outbound
pfil. In FreeBSD main, UDP selects a PCB and can run per-socket tunnel or IPsec
processing before the MAC `inpcb_check_deliver` hook. The receive path needs
recipient selection that verifies the held original PCB, interface and VNET
before per-socket processing. It also needs original-zone reinjection and
bounded callback retirement.
[pfil callback](https://github.com/freebsd/freebsd-src/blob/e5b2c0a1e163ff0d9fb1a3b958ab9db865d03a4e/sys/net/pfil.h),
[IPv4 delivery](https://github.com/freebsd/freebsd-src/blob/main/sys/netinet/udp_usrreq.c)

## Windows and Linux receiving paths

| Target | Required mechanism |
| --- | --- |
| Windows | A Rust WFP DATAGRAM_DATA callout under original ALE flow ownership and an independent inbound flow-context gate. Receive injection alone selects interface numbers rather than a socket; the gate's final socket-delivery behavior requires qualification. |
| Linux | Transparent UDP ingress retains the actual original destination and incoming interface from PREROUTING. Local OUTPUT interception still needs original socket and zone authority before routing through loopback. |

Linux transparent UDP uses the original receiving interface for link-local
scope. In a VRF it retains the distinct slave and master scopes. Legacy
site-local destinations require a site-zone source beyond pktinfo.

The Windows gate validates original flow-context generation, compartment,
reversed endpoints, native interface LUID and interface indices for a
self-injected response. The inbound route uses its own classification fields.
A link-local remote uses that interface's zone and must agree with the captured
outbound zone. Site-local remotes need a separate site-zone source. The guard
covers inbound UDP without a flow-context filter condition so it can deny
delivery to a replacement socket. Microsoft documents flow-context association at the selected WFP
layer, but that observation alone does not establish the final socket enqueue
behavior. Injection completion, a matching flow context and application delivery
remain separate observations.

The driver creates and owns the outbound discovery and capture filters,
inbound guards and UDP endpoint-closure filters. The closure callback revokes
every flow of the native endpoint and retains deletion and completion debt.
Callbacks accept the original filter IDs returned by the
driver's original BFE transaction. IDs are staged before commit so delete
notifications can revoke admission even during startup. Only native IDs
returned by the owning transaction can authorize a callback. File cleanup revokes capture
and outstanding reply authority while the guard still inspects previously
submitted replies.

Native injection context must identify an original request without borrowing a
request allocation that its completion can release. WFP also reports packets
previously self-injected and later cloned/reinjected by another callout. An
expired, unknown or foreign identifier must fail the receive gate; a tuple lookup
cannot recreate authority. Driver shutdown must account for those packets as
well as its own asynchronous injection completions.

The [kernel callout leaf](../../platform/windows/wfp-driver/README.md) owns
native registrations, transport handles, and a guard policy session. It reserves
original flow contexts before association and retains them until native flow
deletion. It checks incoming indications against the original flow and one-shot
request authority in fixed storage. Stale contexts, previously self-injected
packets, and missing native path facts are refused. Ordinary unrelated UDP
continues WFP classification through the `FWP_ACTION_CALLOUT_UNKNOWN` guard.

The device boundary publishes an exclusive file, holds bounded captures, and
uses original native completions for submitted replies. It revokes capture and
reply authority at file cleanup while retaining already submitted native work.
The shared event schedules another gateway poll. Query, client and upstream
work can continue in the current turn. A failed wait registration is retired
once, with outstanding completion observation still bounded by its deadline.
The explicit installer API owns static callout metadata independently of the
service and driver policy sessions.

The Windows DNS service selects this path with `WINDOWS_BACKEND=WFP`. It
queries the exact IFS upstream sockets for their ALE endpoint handles and
retains their original user owners. A startup worker keeps the opened file
and socket reservations until the gateway takes ownership. If that handoff
is cancelled or exceeds the original startup deadline, the worker closes the
file before releasing its reservations.
The driver holds native handles through capture revocation and independently
drains original reply operations.
A single retirement worker owns the original file and socket reservations
through STOP, completion observation and FILE close. A canceled submitted reply
keeps its original token and receives at most one discard command. The host
probes the original completion before enforcing its observation deadline. If
that deadline expires, the gateway retires the file and reports pending native
exposure. Shutdown and recovery bound observation of the worker from the time
capture admission closes. The original worker keeps ownership of unconfirmed
native work. A BFE policy loss suspends packet admission and cancels old
resolver work. A reply or discard write that reports the device unavailable
also starts recovery. An expired queued reply reports its original
unsubmitted outcome before suspension. A revoked file retains the loss until
STOP releases its sockets. Recovery waits for the original file's
actual close, retains the upstream reservations, and attaches a source after
replacement START. One finite open deadline covers every replacement attempt,
including native calls that are still pending. A late attempt retains its own
file and socket custody in the original worker and cannot attach a source.
The [protected driver maintenance channel](../wfp-dns-std/README.md#driver-maintenance)
orders native retirement and WDM unload independently of the data file.
Run signed Windows qualification with repeated BFE restart, active UDP flows,
socket custody on abrupt process exit, original-zone delivery and shutdown.
Receive guards depend on their native WFP policy during a BFE outage.
[Winsock ALE endpoint query](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls)

[WFP flow context](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0),
[receive injection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjecttransportreceiveasync0),
[injection history](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsquerypacketinjectionstate0),
[callout actions](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0),
[WFP object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
[Linux TPROXY](https://docs.kernel.org/networking/tproxy.html)

### Linux transparent ingress

The transparent source binds all requested listener families before applying
resolver bypass marks. The ingress families and the configured upstream
resolver's address family are independent. The UDP listeners retain the native
peer, original destination and ingress interface from `recvmsg`. A packet needs
matching original destination and packet-info records and a configured
non-loopback ingress.
Ordinary IPv6 link-local endpoints must agree with their original ingress.
Legacy IPv6 site-local endpoints are refused because Linux supplies no site
zone in the receive metadata.
VRF input retains the slave for the original destination and pktinfo, and the
master for the scoped peer. Rechecking the exact parent relationship qualifies
both observations. Each reply permit keeps the original route. A bounded socket
cache binds the original local address and port to its interface or VRF master
and sends with the received physical interface in pktinfo. After preparing
the reply socket, the send attempt checks that original ingress again. Linux
UDP send acceptance is a local output fact. The DNS wire payload remains unchanged.
Readiness and data I/O borrow the same owned native socket for each listener
and cached reply socket.

The link watcher, ingress query, both listeners, resolver sockets and reply
sockets must share the kernel namespace recorded with `SO_NETNS_COOKIE`.
Each listener is enrolled in the original capture source. The source retains
one received body while its original ingress is checked. A cached reply socket
also checks the capture owner, including for unscoped endpoints in a shared
namespace. The source validates the complete original resolver socket set
before applying any bypass mark. Missing kernel cookie support or a namespace
mismatch refuses setup or a reply before submission.

Startup awaits `PacketSource::transparent` while the native worker resolves
the configured links. One worker holds the original namespace-bound
`NETLINK_ROUTE` query socket. Each `RTM_GETLINK` observation checks the original
name, index, interface role, master membership and VRF classification together.
VRF probes also check the original master.
At most one probe is outstanding. The reactor applies each result only to its
original input or reply attempt after draining the original link watch. Every
native send attempt uses fresh evidence. An overdue probe retires the capture
generation. The service waits for that worker to exit before reattaching or
reporting shutdown. Before reusing a netlink sequence, the query owner binds a
new socket in the same namespace while the old port is still owned.

A route-netlink link subscription starts before interface resolution. The
service processes link notifications before packet I/O. The reported name and
interface role belong to the same kernel record. A deletion, reported rename,
loopback role or changed VRF membership retires that ingress even if a later
lookup sees the original name and index. An incomplete notification for a
tracked link requires a fresh capture generation.
Direct lookup also retires an ingress on confirmed loss. A transient lookup
error during admission or send refuses that operation and leaves the ingress
observation active.
Retirement discards held input, cancels active work, invalidates pending replies
and releases cached sockets bound to that source interface or retired VRF master.
An interrupted watch keeps packet I/O paused until a nonblocking read of the
original descriptor observes an empty queue. A queue that stays backlogged for
three seconds, a notification overrun or retirement of every ingress closes the
capture generation. The gateway aborts its requests and releases unsent replies.
The original marked resolver sockets stay owned. An interrupted UDP receive or
send keeps its original socket, reply permit and deadlines for the next poll.
A worker resolves configured names at startup and during recovery within a
fixed ten-second window. Cancellation wakes the original worker. Recovery
joins it before accepting the result or starting another observation. Startup
requires every name to resolve. Recovery can resume
with the available names when a sibling interface is absent. A notification that a
configured interface or its retired VRF master has returned prompts a fresh
lookup and watch drain while surviving ingress remains active. If the new
observation adds an eligible ingress, the service briefly pauses capture and
closes the entire old generation before binding fresh listeners. This discards
queued datagrams and reply ownership from the old generation, including for
a reused interface index. Capture resumes after the new watch drains again.
Refresh and outage recovery retry temporary worker, descriptor and reactor
registration failures within the original ten-second deadline. A timed-out
refresh retires its original worker before another refresh can begin.
Failed initial startup or invalid notification framing closes the source.
Kernel-atomic interface custody through reply submission still requires a
native submission mechanism.

The host applies the configured bypass mark to the exact retained resolver
sockets and to reply sockets. Closing listeners and reply sockets precedes
restoration of resolver marks. The deployment owns interception and routing
configuration. Qualification must check actual scoped routing and interface
replacement as well as resolver exclusion. See the
[service configuration](../../apps/gnunet-service-dns/README.md#linux-transparent-ingress).

## Qualification

Keep raw unicast link-local exclusions until a native receiving path establishes
its required contract. SDK builds and ownership tests establish neither provider
activation nor original-zone packet delivery.

Native acceptance must cover equal link-local addresses on different interfaces;
source, destination and both scoped endpoints; connected/sendto clients;
wildcard and explicit binds; socket/interface replacement; upstream exclusion;
provider restart; late completion; and shutdown with pending writes. Verify
application-observed local/remote endpoints, DNS bytes and TCP relay behavior
separately from raw packet equivalence. Official C client IPC and PRE/POST
interoperability remain a separate qualification from native flow routing.
